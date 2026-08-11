import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const EMAIL_FROM = process.env.EMAIL_FROM;
const EMAIL_FROM_NAME =
    process.env.EMAIL_FROM_NAME || "Legacy Lens AI";

const FRONTEND_URL =
    process.env.FRONTEND_URL || "*";

const FACE_ENCRYPTION_KEY =
    process.env.FACE_ENCRYPTION_KEY ||
    crypto.randomBytes(32).toString("hex");

if (FACE_ENCRYPTION_KEY.length !== 64) {
    console.warn(
        "WARNING: FACE_ENCRYPTION_KEY should contain 64 hexadecimal characters."
    );
}

app.use(
    helmet({
        crossOriginResourcePolicy: {
            policy: "cross-origin"
        }
    })
);

app.use(
    cors({
        origin:
            FRONTEND_URL === "*"
                ? true
                : FRONTEND_URL,
        methods: ["GET", "POST"],
        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ]
    })
);

app.use(
    express.json({
        limit: "2mb"
    })
);

/*
|--------------------------------------------------------------------------
| STORAGE
|--------------------------------------------------------------------------
|
| IMPORTANT:
| These Maps are temporary.
|
| Render/server restarts will erase them.
|
| For production, move faceTemplates and OTP data
| into a real database.
|
|--------------------------------------------------------------------------
*/

const otpRequests = new Map();

const faceTemplates = new Map();

/*
|--------------------------------------------------------------------------
| FACE ENCRYPTION
|--------------------------------------------------------------------------
*/

function getEncryptionKey() {
    return Buffer.from(
        FACE_ENCRYPTION_KEY,
        "hex"
    );
}

function encryptFaceTemplate(template) {

    const iv =
        crypto.randomBytes(12);

    const key =
        getEncryptionKey();

    const cipher =
        crypto.createCipheriv(
            "aes-256-gcm",
            key,
            iv
        );

    const encrypted =
        Buffer.concat([
            cipher.update(
                JSON.stringify(template),
                "utf8"
            ),
            cipher.final()
        ]);

    const authTag =
        cipher.getAuthTag();

    return {
        iv: iv.toString("base64"),
        data: encrypted.toString("base64"),
        authTag: authTag.toString("base64")
    };
}

function decryptFaceTemplate(stored) {

    const key =
        getEncryptionKey();

    const iv =
        Buffer.from(
            stored.iv,
            "base64"
        );

    const encrypted =
        Buffer.from(
            stored.data,
            "base64"
        );

    const authTag =
        Buffer.from(
            stored.authTag,
            "base64"
        );

    const decipher =
        crypto.createDecipheriv(
            "aes-256-gcm",
            key,
            iv
        );

    decipher.setAuthTag(
        authTag
    );

    const decrypted =
        Buffer.concat([
            decipher.update(
                encrypted
            ),
            decipher.final()
        ]);

    return JSON.parse(
        decrypted.toString("utf8")
    );
}

/*
|--------------------------------------------------------------------------
| FACE TEMPLATE VALIDATION
|--------------------------------------------------------------------------
*/

function validateFaceTemplate(template) {

    if (!Array.isArray(template)) {
        return false;
    }

    if (template.length < 32) {
        return false;
    }

    if (template.length > 4096) {
        return false;
    }

    return template.every(
        value =>
            typeof value === "number" &&
            Number.isFinite(value)
    );
}

/*
|--------------------------------------------------------------------------
| FACE DISTANCE
|--------------------------------------------------------------------------
*/

function euclideanDistance(
    first,
    second
) {

    if (
        !Array.isArray(first) ||
        !Array.isArray(second)
    ) {
        return Infinity;
    }

    if (
        first.length !==
        second.length
    ) {
        return Infinity;
    }

    let sum = 0;

    for (
        let i = 0;
        i < first.length;
        i++
    ) {

        const difference =
            first[i] - second[i];

        sum +=
            difference *
            difference;
    }

    return Math.sqrt(sum);
}

/*
|--------------------------------------------------------------------------
| FACE MATCH THRESHOLD
|--------------------------------------------------------------------------
|
| Lower = stricter.
|
| This value should be calibrated with
| the face-recognition library used by
| the frontend.
|
|--------------------------------------------------------------------------
*/

const FACE_MATCH_THRESHOLD =
    Number(
        process.env.FACE_MATCH_THRESHOLD ||
        0.55
    );

/*
|--------------------------------------------------------------------------
| RATE LIMITING
|--------------------------------------------------------------------------
*/

const sendCodeLimiter =
    rateLimit({
        windowMs:
            15 * 60 * 1000,

        max: 5,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,
            message:
                "Too many verification requests. Please try again later."
        }
    });

const verifyCodeLimiter =
    rateLimit({
        windowMs:
            15 * 60 * 1000,

        max: 10,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,
            message:
                "Too many verification attempts. Please try again later."
        }
    });

const faceRegisterLimiter =
    rateLimit({
        windowMs:
            15 * 60 * 1000,

        max: 5,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,
            message:
                "Too many face registration attempts. Please try again later."
        }
    });

const faceLoginLimiter =
    rateLimit({
        windowMs:
            15 * 60 * 1000,

        max: 20,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,
            message:
                "Too many face login attempts. Please try again later."
        }
    });

/*
|--------------------------------------------------------------------------
| OTP FUNCTIONS
|--------------------------------------------------------------------------
*/

function generateOTP() {

    return crypto
        .randomInt(
            100000,
            1000000
        )
        .toString();
}

function hashOTP(code) {

    return crypto
        .createHash("sha256")
        .update(code)
        .digest("hex");
}

/*
|--------------------------------------------------------------------------
| CLEAN EXPIRED OTPs
|--------------------------------------------------------------------------
*/

function cleanupExpiredCodes() {

    const now =
        Date.now();

    for (
        const [
            email,
            data
        ] of otpRequests.entries()
    ) {

        if (
            data.expiresAt <=
            now
        ) {

            otpRequests.delete(
                email
            );
        }
    }
}

setInterval(
    cleanupExpiredCodes,
    60 * 1000
);

/*
|--------------------------------------------------------------------------
| CLEANUP FACE LOGIN CHALLENGES
|--------------------------------------------------------------------------
*/

const faceLoginChallenges =
    new Map();

function cleanupFaceChallenges() {

    const now =
        Date.now();

    for (
        const [
            challengeId,
            data
        ] of faceLoginChallenges.entries()
    ) {

        if (
            data.expiresAt <=
            now
        ) {

            faceLoginChallenges.delete(
                challengeId
            );
        }
    }
}

setInterval(
    cleanupFaceChallenges,
    60 * 1000
);

/*
|--------------------------------------------------------------------------
| HEALTH CHECK
|--------------------------------------------------------------------------
*/

app.get(
    "/api/health",
    (req, res) => {

        res.json({
            success: true,
            service:
                "Legacy Lens AI",
            status: "online"
        });
    }
);

/*
|--------------------------------------------------------------------------
| SEND BREVO EMAIL
|--------------------------------------------------------------------------
*/

async function sendBrevoEmail({
    recipient,
    subject,
    htmlContent,
    textContent
}) {

    if (!BREVO_API_KEY) {

        throw new Error(
            "BREVO_API_KEY is not configured."
        );
    }

    if (!EMAIL_FROM) {

        throw new Error(
            "EMAIL_FROM is not configured."
        );
    }

    const response =
        await fetch(
            "https://api.brevo.com/v3/smtp/email",
            {
                method: "POST",

                headers: {
                    accept:
                        "application/json",

                    "api-key":
                        BREVO_API_KEY,

                    "content-type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        sender: {
                            name:
                                EMAIL_FROM_NAME,

                            email:
                                EMAIL_FROM
                        },

                        to: [
                            {
                                email:
                                    recipient
                            }
                        ],

                        subject,

                        htmlContent,

                        textContent
                    })
            }
        );

    const data =
        await response.json();

    if (!response.ok) {

        console.error(
            "Brevo API error:",
            data
        );

        throw new Error(
            data.message ||
            "Brevo could not send the email."
        );
    }

    return data;
}

/*
|--------------------------------------------------------------------------
| SEND VERIFICATION CODE
|--------------------------------------------------------------------------
*/

app.post(
    "/api/send-code",
    sendCodeLimiter,
    async (req, res) => {

        let email = "";

        try {

            email =
                String(
                    req.body.email ||
                    ""
                )
                    .trim()
                    .toLowerCase();

            if (!email) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Email address is required."
                });
            }

            const emailPattern =
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

            if (
                !emailPattern.test(
                    email
                )
            ) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            const existing =
                otpRequests.get(
                    email
                );

            if (
                existing &&
                existing.lastSentAt &&
                Date.now() -
                    existing.lastSentAt <
                    60 * 1000
            ) {

                return res.status(
                    429
                ).json({
                    success: false,
                    message:
                        "Please wait before requesting another code."
                });
            }

            const code =
                generateOTP();

            const codeHash =
                hashOTP(code);

            const expiresAt =
                Date.now() +
                10 * 60 * 1000;

            otpRequests.set(
                email,
                {
                    codeHash,
                    expiresAt,
                    attempts: 0,
                    lastSentAt:
                        Date.now()
                }
            );

            const htmlContent = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Legacy Lens AI Verification</title>
</head>

<body style="
margin:0;
padding:0;
background:#f4f7fb;
font-family:Arial,Helvetica,sans-serif;
">

<div style="
max-width:600px;
margin:40px auto;
padding:20px;
">

<div style="
background:#ffffff;
border-radius:18px;
padding:40px 30px;
box-shadow:0 8px 30px rgba(0,0,0,0.08);
">

<div style="
text-align:center;
">

<h1 style="
margin:0;
color:#111827;
font-size:28px;
">
Legacy Lens AI
</h1>

<p style="
margin-top:10px;
color:#64748b;
font-size:16px;
">
Verify your email address
</p>

</div>

<div style="
margin-top:30px;
padding:30px 20px;
background:#f8fafc;
border-radius:16px;
text-align:center;
">

<p style="
margin:0 0 18px;
color:#475569;
font-size:15px;
">
Your verification code is:
</p>

<div style="
font-size:36px;
font-weight:700;
letter-spacing:10px;
color:#111827;
">
${code}
</div>

<p style="
margin-top:20px;
color:#64748b;
font-size:14px;
">
This code expires in 10 minutes.
</p>

</div>

<p style="
margin-top:30px;
color:#64748b;
font-size:14px;
line-height:1.6;
text-align:center;
">
If you did not request this verification code,
you can safely ignore this email.
</p>

<p style="
margin-top:30px;
color:#94a3b8;
font-size:13px;
text-align:center;
">
© ${new Date().getFullYear()}
Legacy Lens AI
</p>

</div>
</div>

</body>
</html>
`;

            const textContent = `
Legacy Lens AI

Verify your email address.

Your verification code is:

${code}

This code expires in 10 minutes.

If you did not request this verification code,
you can safely ignore this email.

© ${new Date().getFullYear()} Legacy Lens AI
`;

            await sendBrevoEmail({
                recipient: email,

                subject:
                    "Your Legacy Lens AI verification code",

                htmlContent,

                textContent
            });

            console.log(
                `Verification code sent to ${email}`
            );

            return res.json({
                success: true,
                message:
                    "Verification code sent."
            });

        } catch (error) {

            console.error(
                "Send verification error:",
                error
            );

            if (email) {

                otpRequests.delete(
                    email
                );
            }

            return res.status(
                500
            ).json({
                success: false,
                message:
                    error.message ||
                    "Unable to send verification email."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| VERIFY EMAIL CODE
|--------------------------------------------------------------------------
*/

app.post(
    "/api/verify-code",
    verifyCodeLimiter,
    async (req, res) => {

        try {

            const email =
                String(
                    req.body.email ||
                    ""
                )
                    .trim()
                    .toLowerCase();

            const code =
                String(
                    req.body.code ||
                    ""
                )
                    .trim();

            if (
                !email ||
                !code
            ) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Email and verification code are required."
                });
            }

            if (
                !/^\d{6}$/.test(
                    code
                )
            ) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Verification code must contain 6 digits."
                });
            }

            const stored =
                otpRequests.get(
                    email
                );

            if (!stored) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "This verification code is invalid or has expired."
                });
            }

            if (
                Date.now() >
                stored.expiresAt
            ) {

                otpRequests.delete(
                    email
                );

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "This verification code has expired."
                });
            }

            if (
                stored.attempts >= 5
            ) {

                otpRequests.delete(
                    email
                );

                return res.status(
                    429
                ).json({
                    success: false,
                    message:
                        "Too many incorrect attempts. Request a new code."
                });
            }

            const submittedHash =
                hashOTP(code);

            const submittedBuffer =
                Buffer.from(
                    submittedHash,
                    "hex"
                );

            const storedBuffer =
                Buffer.from(
                    stored.codeHash,
                    "hex"
                );

            const isValid =
                submittedBuffer.length ===
                    storedBuffer.length &&
                crypto.timingSafeEqual(
                    submittedBuffer,
                    storedBuffer
                );

            if (!isValid) {

                stored.attempts +=
                    1;

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Incorrect verification code."
                });
            }

            otpRequests.delete(
                email
            );

            console.log(
                `Email verified: ${email}`
            );

            return res.json({
                success: true,
                verified: true,
                message:
                    "Email verified successfully."
            });

        } catch (error) {

            console.error(
                "Verification error:",
                error
            );

            return res.status(
                500
            ).json({
                success: false,
                message:
                    "Something went wrong."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| FACE REGISTRATION
|--------------------------------------------------------------------------
|
| Frontend sends:
|
| {
|   email: "user@example.com",
|   template: [0.123, -0.456, ...]
| }
|
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/register",
    faceRegisterLimiter,
    async (req, res) => {

        try {

            const email =
                String(
                    req.body.email ||
                    ""
                )
                    .trim()
                    .toLowerCase();

            const template =
                req.body.template;

            if (!email) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }

            const emailPattern =
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

            if (
                !emailPattern.test(
                    email
                )
            ) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Invalid email address."
                });
            }

            if (
                !validateFaceTemplate(
                    template
                )
            ) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Invalid facial template."
                });
            }

            const encrypted =
                encryptFaceTemplate(
                    template
                );

            faceTemplates.set(
                email,
                {
                    encrypted,

                    createdAt:
                        new Date().toISOString(),

                    updatedAt:
                        new Date().toISOString()
                }
            );

            console.log(
                `Face registration completed for ${email}`
            );

            return res.json({
                success: true,

                registered: true,

                message:
                    "Face authentication enabled successfully."
            });

        } catch (error) {

            console.error(
                "Face registration error:",
                error
            );

            return res.status(
                500
            ).json({
                success: false,
                message:
                    "Unable to register your face."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| CHECK FACE REGISTRATION
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/status",
    async (req, res) => {

        try {

            const email =
                String(
                    req.body.email ||
                    ""
                )
                    .trim()
                    .toLowerCase();

            if (!email) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }

            return res.json({
                success: true,

                registered:
                    faceTemplates.has(
                        email
                    )
            });

        } catch (error) {

            console.error(
                "Face status error:",
                error
            );

            return res.status(
                500
            ).json({
                success: false,
                message:
                    "Unable to check face authentication status."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| DELETE FACE REGISTRATION
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/delete",
    async (req, res) => {

        try {

            const email =
                String(
                    req.body.email ||
                    ""
                )
                    .trim()
                    .toLowerCase();

            if (!email) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }

            const deleted =
                faceTemplates.delete(
                    email
                );

            return res.json({
                success: true,

                deleted,

                message:
                    deleted
                        ? "Face authentication data deleted."
                        : "No face authentication data found."
            });

        } catch (error) {

            console.error(
                "Face deletion error:",
                error
            );

            return res.status(
                500
            ).json({
                success: false,
                message:
                    "Unable to delete face authentication data."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| START FACE LOGIN
|--------------------------------------------------------------------------
|
| The frontend first asks for a challenge.
|
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/login/start",
    faceLoginLimiter,
    async (req, res) => {

        try {

            const email =
                String(
                    req.body.email ||
                    ""
                )
                    .trim()
                    .toLowerCase();

            if (!email) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }

            const stored =
                faceTemplates.get(
                    email
                );

            if (!stored) {

                return res.status(
                    404
                ).json({
                    success: false,
                    registered: false,
                    message:
                        "Face authentication has not been enabled for this account."
                });
            }

            const challengeId =
                crypto
                    .randomBytes(32)
                    .toString("hex");

            faceLoginChallenges.set(
                challengeId,
                {
                    email,

                    expiresAt:
                        Date.now() +
                        2 * 60 * 1000
                }
            );

            return res.json({
                success: true,

                challengeId,

                expiresIn:
                    120
            });

        } catch (error) {

            console.error(
                "Face login start error:",
                error
            );

            return res.status(
                500
            ).json({
                success: false,
                message:
                    "Unable to start face authentication."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| VERIFY FACE LOGIN
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/login/verify",
    faceLoginLimiter,
    async (req, res) => {

        try {

            const challengeId =
                String(
                    req.body.challengeId ||
                    ""
                ).trim();

            const template =
                req.body.template;

            if (!challengeId) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Login challenge is required."
                });
            }

            if (
                !validateFaceTemplate(
                    template
                )
            ) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Invalid facial template."
                });
            }

            const challenge =
                faceLoginChallenges.get(
                    challengeId
                );

            if (!challenge) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Face login session expired. Please try again."
                });
            }

            if (
                Date.now() >
                challenge.expiresAt
            ) {

                faceLoginChallenges.delete(
                    challengeId
                );

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Face login session expired. Please try again."
                });
            }

            const stored =
                faceTemplates.get(
                    challenge.email
                );

            if (!stored) {

                faceLoginChallenges.delete(
                    challengeId
                );

                return res.status(
                    404
                ).json({
                    success: false,
                    message:
                        "No registered face was found."
                });
            }

            const registeredTemplate =
                decryptFaceTemplate(
                    stored.encrypted
                );

            const distance =
                euclideanDistance(
                    registeredTemplate,
                    template
                );

            const matched =
                distance <=
                FACE_MATCH_THRESHOLD;

            faceLoginChallenges.delete(
                challengeId
            );

            if (!matched) {

                console.warn(
                    `Face authentication failed for ${challenge.email}. Distance: ${distance}`
                );

                return res.status(
                    401
                ).json({
                    success: false,
                    authenticated: false,
                    message:
                        "Face not recognized."
                });
            }

            console.log(
                `Face authentication successful for ${challenge.email}`
            );

            return res.json({
                success: true,

                authenticated: true,

                email:
                    challenge.email,

                message:
                    "Face authentication successful."
            });

        } catch (error) {

            console.error(
                "Face login verification error:",
                error
            );

            return res.status(
                500
            ).json({
                success: false,
                authenticated: false,
                message:
                    "Unable to verify your face."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| 404 HANDLER
|--------------------------------------------------------------------------
*/

app.use(
    (req, res) => {

        res.status(404).json({
            success: false,
            message:
                "Endpoint not found."
        });
    }
);

/*
|--------------------------------------------------------------------------
| ERROR HANDLER
|--------------------------------------------------------------------------
*/

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "Unhandled server error:",
            error
        );

        if (
            res.headersSent
        ) {
            return next(
                error
            );
        }

        res.status(
            500
        ).json({
            success: false,
            message:
                "Internal server error."
        });
    }
);

/*
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
*/

app.listen(
    PORT,
    () => {

        console.log(
            `Legacy Lens AI backend running on port ${PORT}`
        );

        console.log(
            `Health check: http://localhost:${PORT}/api/health`
        );

    }
);
