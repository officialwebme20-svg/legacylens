import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
    process.env.FRONTEND_URL || "*";

const BREVO_API_KEY =
    process.env.BREVO_API_KEY;

const EMAIL_FROM =
    process.env.EMAIL_FROM;

const EMAIL_FROM_NAME =
    process.env.EMAIL_FROM_NAME ||
    "Legacy Lens AI";

/*
|--------------------------------------------------------------------------
| SECURITY / MIDDLEWARE
|--------------------------------------------------------------------------
*/

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(
    cors({
        origin:
            FRONTEND_URL === "*"
                ? true
                : FRONTEND_URL,
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ]
    })
);

app.use(
    express.json({
        limit: "200kb"
    })
);

/*
|--------------------------------------------------------------------------
| OTP STORAGE
|--------------------------------------------------------------------------
*/

const otpRequests = new Map();

/*
|--------------------------------------------------------------------------
| FACE STORAGE
|--------------------------------------------------------------------------
|
| IMPORTANT:
| This Map is temporary memory storage.
| Render can clear it when the service restarts.
| For permanent face storage, use a database.
|
*/

const faceUsers = new Map();

/*
|--------------------------------------------------------------------------
| RATE LIMITERS
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

        max: 10,

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
| HELPERS
|--------------------------------------------------------------------------
*/

function normalizeEmail(email) {
    return String(email || "")
        .trim()
        .toLowerCase();
}

function validEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        email
    );
}

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
| FACE HELPERS
|--------------------------------------------------------------------------
*/

function validateDescriptor(
    descriptor
) {
    if (!Array.isArray(descriptor)) {
        return false;
    }

    if (descriptor.length !== 128) {
        return false;
    }

    return descriptor.every(
        value =>
            typeof value === "number" &&
            Number.isFinite(value)
    );
}

function faceDistance(a, b) {
    if (
        !Array.isArray(a) ||
        !Array.isArray(b) ||
        a.length !== b.length
    ) {
        return Infinity;
    }

    let sum = 0;

    for (
        let i = 0;
        i < a.length;
        i++
    ) {
        const difference =
            a[i] - b[i];

        sum +=
            difference *
            difference;
    }

    return Math.sqrt(sum);
}

function averageDescriptors(
    descriptors
) {
    if (
        !Array.isArray(descriptors) ||
        descriptors.length === 0
    ) {
        return null;
    }

    const length =
        descriptors[0].length;

    const average =
        new Array(length).fill(0);

    for (
        const descriptor
        of descriptors
    ) {
        for (
            let i = 0;
            i < length;
            i++
        ) {
            average[i] +=
                descriptor[i];
        }
    }

    for (
        let i = 0;
        i < length;
        i++
    ) {
        average[i] /=
            descriptors.length;
    }

    return average;
}

/*
|--------------------------------------------------------------------------
| CLEAN EXPIRED OTPs
|--------------------------------------------------------------------------
*/

function cleanupExpiredCodes() {
    const now = Date.now();

    for (
        const [
            email,
            data
        ] of otpRequests.entries()
    ) {
        if (
            data.expiresAt <= now
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
| HEALTH CHECK
|--------------------------------------------------------------------------
*/

app.get(
    "/api/health",
    (req, res) => {
        return res.json({
            success: true,
            service:
                "Legacy Lens AI",
            status: "online"
        });
    }
);

/*
|--------------------------------------------------------------------------
| BREVO EMAIL
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
            "BREVO_API_KEY is not configured on the server."
        );
    }

    if (!EMAIL_FROM) {
        throw new Error(
            "EMAIL_FROM is not configured on the server."
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

    let data = {};

    try {
        data =
            await response.json();
    } catch {
        data = {};
    }

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
                normalizeEmail(
                    req.body.email
                );

            /*
            |--------------------------------------------------------------
            | EMAIL VALIDATION
            |--------------------------------------------------------------
            */

            if (!email) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email address is required."
                });
            }

            if (!validEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            /*
            |--------------------------------------------------------------
            | RESEND COOLDOWN
            |--------------------------------------------------------------
            */

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
                return res.status(429).json({
                    success: false,
                    message:
                        "Please wait before requesting another code."
                });
            }

            /*
            |--------------------------------------------------------------
            | GENERATE OTP
            |--------------------------------------------------------------
            */

            const code =
                generateOTP();

            const codeHash =
                hashOTP(code);

            const expiresAt =
                Date.now() +
                10 * 60 * 1000;

            /*
            |--------------------------------------------------------------
            | STORE OTP
            |--------------------------------------------------------------
            */

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

            /*
            |--------------------------------------------------------------
            | EMAIL HTML
            |--------------------------------------------------------------
            */

            const htmlContent = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width, initial-scale=1.0">
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

<div style="text-align:center;">

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
If you did not request this verification
code, you can safely ignore this email.
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

            /*
            |--------------------------------------------------------------
            | TEXT EMAIL
            |--------------------------------------------------------------
            */

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

            /*
            |--------------------------------------------------------------
            | SEND
            |--------------------------------------------------------------
            */

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

            return res.status(500).json({
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
                normalizeEmail(
                    req.body.email
                );

            const code =
                String(
                    req.body.code || ""
                ).trim();

            /*
            |--------------------------------------------------------------
            | VALIDATION
            |--------------------------------------------------------------
            */

            if (!email || !code) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email and verification code are required."
                });
            }

            if (!validEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            if (
                !/^\d{6}$/.test(
                    code
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Verification code must contain 6 digits."
                });
            }

            /*
            |--------------------------------------------------------------
            | GET STORED OTP
            |--------------------------------------------------------------
            */

            const stored =
                otpRequests.get(
                    email
                );

            if (!stored) {
                return res.status(400).json({
                    success: false,
                    message:
                        "This verification code is invalid or has expired."
                });
            }

            /*
            |--------------------------------------------------------------
            | EXPIRATION
            |--------------------------------------------------------------
            */

            if (
                Date.now() >
                stored.expiresAt
            ) {

                otpRequests.delete(
                    email
                );

                return res.status(400).json({
                    success: false,
                    message:
                        "This verification code has expired."
                });
            }

            /*
            |--------------------------------------------------------------
            | ATTEMPT LIMIT
            |--------------------------------------------------------------
            */

            if (
                stored.attempts >= 5
            ) {

                otpRequests.delete(
                    email
                );

                return res.status(429).json({
                    success: false,
                    message:
                        "Too many incorrect attempts. Request a new code."
                });
            }

            /*
            |--------------------------------------------------------------
            | HASH CODE
            |--------------------------------------------------------------
            */

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

            /*
            |--------------------------------------------------------------
            | SAFE COMPARISON
            |--------------------------------------------------------------
            */

            const isValid =
                submittedBuffer.length ===
                    storedBuffer.length &&
                crypto.timingSafeEqual(
                    submittedBuffer,
                    storedBuffer
                );

            /*
            |--------------------------------------------------------------
            | INVALID CODE
            |--------------------------------------------------------------
            */

            if (!isValid) {

                stored.attempts += 1;

                return res.status(400).json({
                    success: false,
                    message:
                        "Incorrect verification code."
                });
            }

            /*
            |--------------------------------------------------------------
            | VERIFIED
            |--------------------------------------------------------------
            */

            otpRequests.delete(
                email
            );

            console.log(
                `Email verified: ${email}`
            );

            return res.json({
                success: true,

                verified: true,

                email,

                message:
                    "Email verified successfully."
            });

        } catch (error) {

            console.error(
                "Verification error:",
                error
            );

            return res.status(500).json({
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
*/

app.post(
    "/api/face/register",
    faceRegisterLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            const descriptors =
                req.body.descriptors;

            if (!email) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email address is required."
                });
            }

            if (!validEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            if (
                !Array.isArray(
                    descriptors
                ) ||
                descriptors.length < 3 ||
                descriptors.length > 10
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please provide between 3 and 10 face captures."
                });
            }

            for (
                const descriptor
                of descriptors
            ) {

                if (
                    !validateDescriptor(
                        descriptor
                    )
                ) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "Invalid face data received."
                    });
                }
            }

            const faceTemplate =
                averageDescriptors(
                    descriptors
                );

            if (
                !validateDescriptor(
                    faceTemplate
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Unable to create face template."
                });
            }

            const existing =
                faceUsers.get(
                    email
                );

            faceUsers.set(
                email,
                {
                    email,

                    faceTemplate,

                    registeredAt:
                        existing?.registeredAt ||
                        new Date().toISOString(),

                    updatedAt:
                        new Date().toISOString()
                }
            );

            console.log(
                `Face registered for ${email}`
            );

            return res.json({
                success: true,

                registered: true,

                message:
                    "Face registered successfully."
            });

        } catch (error) {

            console.error(
                "Face registration error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to register your face."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| FACE STATUS
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/status",
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            if (!email) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email address is required."
                });
            }

            const user =
                faceUsers.get(
                    email
                );

            return res.json({
                success: true,

                registered:
                    Boolean(user)
            });

        } catch (error) {

            console.error(
                "Face status error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to check face status."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| FACE LOGIN
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/login",
    faceLoginLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            const descriptor =
                req.body.descriptor;

            if (!email) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email address is required."
                });
            }

            if (!validEmail(email)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            if (
                !validateDescriptor(
                    descriptor
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid face data."
                });
            }

            const user =
                faceUsers.get(
                    email
                );

            if (!user) {
                return res.status(404).json({
                    success: false,

                    authenticated: false,

                    registered: false,

                    message:
                        "No face is registered for this account."
                });
            }

            const distance =
                faceDistance(
                    descriptor,
                    user.faceTemplate
                );

            /*
            |--------------------------------------------------------------
            | MATCH THRESHOLD
            |--------------------------------------------------------------
            */

            const MATCH_THRESHOLD =
                0.45;

            const matched =
                distance <=
                MATCH_THRESHOLD;

            if (!matched) {

                console.warn(
                    `Face mismatch for ${email}. Distance: ${distance}`
                );

                return res.status(401).json({
                    success: false,

                    authenticated: false,

                    message:
                        "Face not recognized. Please try again."
                });
            }

            /*
            |--------------------------------------------------------------
            | SUCCESS
            |--------------------------------------------------------------
            */

            const sessionToken =
                crypto
                    .randomBytes(32)
                    .toString("hex");

            console.log(
                `Face login successful for ${email}`
            );

            return res.json({
                success: true,

                authenticated: true,

                email,

                token:
                    sessionToken,

                message:
                    "Face recognized successfully."
            });

        } catch (error) {

            console.error(
                "Face login error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to complete face login."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| REMOVE FACE
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/remove",
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            if (!email) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email address is required."
                });
            }

            const existed =
                faceUsers.delete(
                    email
                );

            return res.json({
                success: true,

                removed:
                    existed,

                message:
                    existed
                        ? "Face data removed successfully."
                        : "No registered face was found."
            });

        } catch (error) {

            console.error(
                "Face removal error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Unable to remove face data."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| 404
|--------------------------------------------------------------------------
*/

app.use(
    (req, res) => {

        return res.status(404).json({
            success: false,

            message:
                "Endpoint not found."
        });
    }
);

/*
|--------------------------------------------------------------------------
| GLOBAL ERROR HANDLER
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
            "Server error:",
            error
        );

        return res.status(500).json({
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
    "0.0.0.0",
    () => {

        console.log(
            `Legacy Lens AI backend running on port ${PORT}`
        );

        console.log(
            `Health endpoint: /api/health`
        );

        console.log(
            `Send code endpoint: /api/send-code`
        );

        console.log(
            `Verify code endpoint: /api/verify-code`
        );

        console.log(
            `Face registration endpoint: /api/face/register`
        );

        console.log(
            `Face login endpoint: /api/face/login`
        );
    }
);
