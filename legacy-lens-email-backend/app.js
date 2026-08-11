import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;

app.use(helmet());

app.use(
    cors({
        origin: process.env.FRONTEND_URL || true
    })
);

app.use(express.json());

app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        service: "Legacy Lens AI",
        status: "online"
    });
});

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Endpoint not found."
    });
});

app.listen(PORT, () => {
    console.log(
        `Legacy Lens AI backend running on port ${PORT}`
    );
});

const FRONTEND_URL =
    process.env.FRONTEND_URL || true;

const BREVO_API_KEY =
    process.env.BREVO_API_KEY;

const EMAIL_FROM =
    process.env.EMAIL_FROM;

const EMAIL_FROM_NAME =
    process.env.EMAIL_FROM_NAME ||
    "Legacy Lens AI";

/*
|--------------------------------------------------------------------------
| APP SECURITY
|--------------------------------------------------------------------------
*/

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(
    cors({
        origin: FRONTEND_URL,
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ]
    })
);

app.use(
    express.json({
        limit: "10mb"
    })
);

/*
|--------------------------------------------------------------------------
| STORAGE
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| These Maps are temporary in-memory storage.
|
| If Render restarts your server, this data disappears.
|
| For production face login, replace these Maps with
| MongoDB, PostgreSQL, Firebase, Supabase, etc.
|
|--------------------------------------------------------------------------
*/

const otpRequests = new Map();

const faceUsers = new Map();

/*
|--------------------------------------------------------------------------
| FACE USER STRUCTURE
|--------------------------------------------------------------------------
|
| faceUsers.set(email, {
|
|     email,
|
|     faceDescriptor: [...],
|
|     registeredAt,
|
|     lastLoginAt
|
| });
|
|--------------------------------------------------------------------------
*/

/*
|--------------------------------------------------------------------------
| RATE LIMITING
|--------------------------------------------------------------------------
*/

const sendCodeLimiter =
    rateLimit({
        windowMs: 15 * 60 * 1000,
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
        windowMs: 15 * 60 * 1000,
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
        windowMs: 15 * 60 * 1000,
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
        windowMs: 15 * 60 * 1000,
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

            status:
                "online",

            faceRecognition:
                "enabled"
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

                return res.status(400)
                    .json({

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

                return res.status(400)
                    .json({

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

                return res.status(429)
                    .json({

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

<meta
name="viewport"
content="width=device-width, initial-scale=1.0"
>

<title>
Legacy Lens AI Verification
</title>

</head>

<body
style="
margin:0;
padding:0;
background:#f4f7fb;
font-family:Arial,Helvetica,sans-serif;
"
>

<div
style="
max-width:600px;
margin:40px auto;
padding:20px;
"
>

<div
style="
background:#ffffff;
border-radius:18px;
padding:40px 30px;
box-shadow:0 8px 30px rgba(0,0,0,0.08);
"
>

<div style="text-align:center;">

<h1
style="
margin:0;
color:#111827;
font-size:28px;
"
>
Legacy Lens AI
</h1>

<p
style="
margin-top:10px;
color:#64748b;
font-size:16px;
"
>
Verify your email address
</p>

</div>

<div
style="
margin-top:30px;
padding:30px 20px;
background:#f8fafc;
border-radius:16px;
text-align:center;
"
>

<p
style="
margin:0 0 18px;
color:#475569;
font-size:15px;
"
>
Your verification code is:
</p>

<div
style="
font-size:36px;
font-weight:700;
letter-spacing:10px;
color:#111827;
"
>
${code}
</div>

<p
style="
margin-top:20px;
color:#64748b;
font-size:14px;
"
>
This code expires in 10 minutes.
</p>

</div>

<p
style="
margin-top:30px;
color:#64748b;
font-size:14px;
line-height:1.6;
text-align:center;
"
>
If you did not request this verification code,
you can safely ignore this email.
</p>

<p
style="
margin-top:30px;
color:#94a3b8;
font-size:13px;
text-align:center;
"
>
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

                recipient:
                    email,

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

            return res.status(500)
                .json({

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

                return res.status(400)
                    .json({

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

                return res.status(400)
                    .json({

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

                return res.status(400)
                    .json({

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

                return res.status(400)
                    .json({

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

                return res.status(429)
                    .json({

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

                stored.attempts += 1;

                return res.status(400)
                    .json({

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

            return res.status(500)
                .json({

                    success: false,

                    message:
                        "Something went wrong."
                });
        }
    }
);

/*
|--------------------------------------------------------------------------
| FACE DESCRIPTOR VALIDATION
|--------------------------------------------------------------------------
*/

function validateFaceDescriptor(
    descriptor
) {

    if (
        !Array.isArray(
            descriptor
        )
    ) {

        return false;
    }

    if (
        descriptor.length < 64
    ) {

        return false;
    }

    for (
        const value of descriptor
    ) {

        if (
            typeof value !==
            "number"
        ) {

            return false;
        }

        if (
            !Number.isFinite(
                value
            )
        ) {

            return false;
        }
    }

    return true;
}

/*
|--------------------------------------------------------------------------
| FACE DISTANCE
|--------------------------------------------------------------------------
|
| Euclidean distance between two face embeddings.
|
|--------------------------------------------------------------------------
*/

function faceDistance(
    descriptorA,
    descriptorB
) {

    if (
        descriptorA.length !==
        descriptorB.length
    ) {

        return Infinity;
    }

    let sum = 0;

    for (
        let i = 0;
        i < descriptorA.length;
        i++
    ) {

        const difference =
            descriptorA[i] -
            descriptorB[i];

        sum +=
            difference *
            difference;
    }

    return Math.sqrt(
        sum
    );
}

/*
|--------------------------------------------------------------------------
| FACE MATCH THRESHOLD
|--------------------------------------------------------------------------
|
| Lower = stricter.
|
| 0.45 is intentionally conservative.
|
|--------------------------------------------------------------------------
*/

const FACE_MATCH_THRESHOLD =
    Number(
        process.env.FACE_MATCH_THRESHOLD ||
        0.45
    );

/*
|--------------------------------------------------------------------------
| REGISTER FACE
|--------------------------------------------------------------------------
|
| POST:
|
| /api/face/register
|
| BODY:
|
| {
|     "email": "...",
|     "faceDescriptor": [...]
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

            const faceDescriptor =
                req.body.faceDescriptor;

            if (!email) {

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Email is required."
                    });
            }

            if (
                !validateFaceDescriptor(
                    faceDescriptor
                )
            ) {

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Invalid face data."
                    });
            }

            const existing =
                faceUsers.get(
                    email
                );

            if (existing) {

                return res.status(409)
                    .json({

                        success: false,

                        message:
                            "Face login is already registered for this account."
                    });
            }

            /*
            |--------------------------------------------------------------
            | Store normalized copy
            |--------------------------------------------------------------
            */

            const normalizedDescriptor =
                faceDescriptor.map(
                    Number
                );

            faceUsers.set(
                email,
                {

                    email,

                    faceDescriptor:
                        normalizedDescriptor,

                    registeredAt:
                        new Date().toISOString(),

                    lastLoginAt:
                        null
                }
            );

            console.log(
                `Face registered for ${email}`
            );

            return res.json({

                success: true,

                registered: true,

                message:
                    "Face login enabled successfully."
            });

        } catch (error) {

            console.error(
                "Face registration error:",
                error
            );

            return res.status(500)
                .json({

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
|
| POST:
|
| /api/face/status
|
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

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Email is required."
                    });
            }

            const user =
                faceUsers.get(
                    email
                );

            return res.json({

                success: true,

                registered:
                    Boolean(user),

                email
            });

        } catch (error) {

            console.error(
                "Face status error:",
                error
            );

            return res.status(500)
                .json({

                    success: false,

                    message:
                        "Unable to check face registration."
                });
        }
    }
);

/*
|--------------------------------------------------------------------------
| FACE LOGIN
|--------------------------------------------------------------------------
|
| POST:
|
| /api/face/login
|
| BODY:
|
| {
|     "faceDescriptor": [...]
| }
|
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/login",
    faceLoginLimiter,
    async (req, res) => {

        try {

            const faceDescriptor =
                req.body.faceDescriptor;

            if (
                !validateFaceDescriptor(
                    faceDescriptor
                )
            ) {

                return res.status(400)
                    .json({

                        success: false,

                        authenticated: false,

                        message:
                            "Invalid face data."
                    });
            }

            let bestMatch = null;

            let smallestDistance =
                Infinity;

            /*
            |--------------------------------------------------------------
            | Compare submitted face with stored faces
            |--------------------------------------------------------------
            */

            for (
                const [
                    email,
                    user
                ] of faceUsers.entries()
            ) {

                const distance =
                    faceDistance(
                        faceDescriptor,
                        user.faceDescriptor
                    );

                if (
                    distance <
                    smallestDistance
                ) {

                    smallestDistance =
                        distance;

                    bestMatch = {
                        email,
                        user
                    };
                }
            }

            /*
            |--------------------------------------------------------------
            | No registered faces
            |--------------------------------------------------------------
            */

            if (
                !bestMatch
            ) {

                return res.status(401)
                    .json({

                        success: false,

                        authenticated: false,

                        message:
                            "No registered face was found."
                    });
            }

            /*
            |--------------------------------------------------------------
            | Face does not match
            |--------------------------------------------------------------
            */

            if (
                smallestDistance >
                FACE_MATCH_THRESHOLD
            ) {

                console.warn(
                    "Face login rejected. Distance:",
                    smallestDistance
                );

                return res.status(401)
                    .json({

                        success: false,

                        authenticated: false,

                        message:
                            "Face not recognized."
                    });
            }

            /*
            |--------------------------------------------------------------
            | SUCCESS
            |--------------------------------------------------------------
            */

            bestMatch.user.lastLoginAt =
                new Date().toISOString();

            faceUsers.set(
                bestMatch.email,
                bestMatch.user
            );

            console.log(
                `Face login successful: ${bestMatch.email}`
            );

            /*
            |--------------------------------------------------------------
            | IMPORTANT
            |--------------------------------------------------------------
            |
            | This returns the matched email.
            |
            | Your frontend should then use Firebase Auth
            | or another proper authentication mechanism
            | to create the actual logged-in session.
            |
            */

            return res.json({

                success: true,

                authenticated: true,

                email:
                    bestMatch.email,

                message:
                    "Face recognized successfully."
            });

        } catch (error) {

            console.error(
                "Face login error:",
                error
            );

            return res.status(500)
                .json({

                    success: false,

                    authenticated: false,

                    message:
                        "Unable to process face login."
                });
        }
    }
);

/*
|--------------------------------------------------------------------------
| DELETE FACE REGISTRATION
|--------------------------------------------------------------------------
|
| POST:
|
| /api/face/remove
|
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/remove",
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

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Email is required."
                    });
            }

            const existed =
                faceUsers.delete(
                    email
                );

            if (!existed) {

                return res.status(404)
                    .json({

                        success: false,

                        message:
                            "No face registration was found."
                    });
            }

            console.log(
                `Face registration removed: ${email}`
            );

            return res.json({

                success: true,

                message:
                    "Face login removed successfully."
            });

        } catch (error) {

            console.error(
                "Face removal error:",
                error
            );

            return res.status(500)
                .json({

                    success: false,

                    message:
                        "Unable to remove face login."
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

        res.status(404)
            .json({

                success: false,

                message:
                    "Endpoint not found.",

                path:
                    req.originalUrl
            });
    }
);

/*
|--------------------------------------------------------------------------
| GLOBAL ERROR HANDLER
|--------------------------------------------------------------------------
*/

app.use(
    (error, req, res, next) => {

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

        return res.status(500)
            .json({

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
            `Face matching threshold: ${FACE_MATCH_THRESHOLD}`
        );
    }
);
