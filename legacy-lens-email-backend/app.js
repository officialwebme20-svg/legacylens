import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "crypto";
import { Resend } from "resend";
import * as faceapi from "@vladmandic/face-api";
import canvas from "canvas";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const {
    Canvas,
    Image,
    ImageData
} = canvas;

faceapi.env.monkeyPatch({
    Canvas,
    Image,
    ImageData
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
    process.env.FRONTEND_URL || "*";

const EMAIL_FROM =
    process.env.EMAIL_FROM;

const EMAIL_FROM_NAME =
    process.env.EMAIL_FROM_NAME ||
    "Legacy Lens AI";

const RESEND_API_KEY =
    process.env.RESEND_API_KEY;

const resend =
    RESEND_API_KEY
        ? new Resend(RESEND_API_KEY)
        : null;


/*
|--------------------------------------------------------------------------
| APP CONFIGURATION
|--------------------------------------------------------------------------
*/

app.set(
    "trust proxy",
    1
);

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(
    cors({
        origin: FRONTEND_URL,
        methods: [
            "GET",
            "POST",
            "OPTIONS"
        ],
        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ]
    })
);

app.use(
    express.json({
        limit: "15mb"
    })
);


/*
|--------------------------------------------------------------------------
| FACE STORAGE
|--------------------------------------------------------------------------
|
| email -> {
|     descriptor: [...]
| }
|
| IMPORTANT:
| This is temporary memory storage.
| Data disappears when Render restarts.
|
*/

const faceUsers =
    new Map();


/*
|--------------------------------------------------------------------------
| OTP STORAGE
|--------------------------------------------------------------------------
*/

const otpRequests =
    new Map();


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


const faceLimiter =
    rateLimit({
        windowMs:
            15 * 60 * 1000,

        max: 30,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,
            message:
                "Too many face authentication attempts. Please try again later."
        }
    });


/*
|--------------------------------------------------------------------------
| LOAD FACE MODELS
|--------------------------------------------------------------------------
*/

let faceModelsLoaded =
    false;


async function loadFaceModels() {

    if (faceModelsLoaded) {
        return;
    }

    const modelPath =
        path.join(
            __dirname,
            "models"
        );

    console.log(
        "Loading face recognition models..."
    );

    await faceapi.nets.ssdMobilenetv1.loadFromDisk(
        modelPath
    );

    await faceapi.nets.faceLandmark68Net.loadFromDisk(
        modelPath
    );

    await faceapi.nets.faceRecognitionNet.loadFromDisk(
        modelPath
    );

    faceModelsLoaded =
        true;

    console.log(
        "Face recognition models loaded."
    );
}


/*
|--------------------------------------------------------------------------
| NORMALIZE EMAIL
|--------------------------------------------------------------------------
*/

function normalizeEmail(
    email
) {

    return String(
        email || ""
    )
        .trim()
        .toLowerCase();
}


/*
|--------------------------------------------------------------------------
| GENERATE OTP
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


/*
|--------------------------------------------------------------------------
| HASH OTP
|--------------------------------------------------------------------------
*/

function hashOTP(
    code
) {

    return crypto
        .createHash("sha256")
        .update(code)
        .digest("hex");
}


/*
|--------------------------------------------------------------------------
| FACE IMAGE DATA
|--------------------------------------------------------------------------
*/

function base64ToBuffer(
    image
) {

    if (
        typeof image !==
        "string"
    ) {

        throw new Error(
            "Invalid image."
        );
    }

    const match =
        image.match(
            /^data:image\/[a-zA-Z0-9.+-]+;base64,(.+)$/
        );

    if (!match) {

        throw new Error(
            "Invalid image format."
        );
    }

    return Buffer.from(
        match[1],
        "base64"
    );
}


/*
|--------------------------------------------------------------------------
| CREATE FACE DESCRIPTOR
|--------------------------------------------------------------------------
*/

async function createFaceDescriptor(
    image
) {

    await loadFaceModels();

    const buffer =
        base64ToBuffer(
            image
        );

    const img =
        await canvas.loadImage(
            buffer
        );

    const detection =
        await faceapi
            .detectSingleFace(
                img
            )
            .withFaceLandmarks()
            .withFaceDescriptor();

    if (!detection) {

        throw new Error(
            "No face detected. Please position your face clearly inside the camera."
        );
    }

    if (
        detection.detection.score <
        0.65
    ) {

        throw new Error(
            "Face detection was not clear enough. Please move closer and try again."
        );
    }

    return Array.from(
        detection.descriptor
    );
}


/*
|--------------------------------------------------------------------------
| COMPARE FACES
|--------------------------------------------------------------------------
*/

function compareFaces(
    storedDescriptor,
    liveDescriptor
) {

    if (
        !Array.isArray(
            storedDescriptor
        ) ||
        !Array.isArray(
            liveDescriptor
        )
    ) {

        return Infinity;
    }

    if (
        storedDescriptor.length !==
        liveDescriptor.length
    ) {

        return Infinity;
    }

    let sum = 0;

    for (
        let i = 0;
        i < storedDescriptor.length;
        i++
    ) {

        const difference =
            storedDescriptor[i] -
            liveDescriptor[i];

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
| HEALTH CHECK
|--------------------------------------------------------------------------
*/

app.get(
    "/api/health",
    async (req, res) => {

        res.json({
            success: true,
            service:
                "Legacy Lens AI",
            status:
                "online",
            faceRecognition:
                faceModelsLoaded
                    ? "ready"
                    : "loading"
        });
    }
);


/*
|--------------------------------------------------------------------------
| FACE STATUS
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/status",
    faceLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            if (!email) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }

            const registered =
                faceUsers.has(
                    email
                );

            return res.json({
                success: true,
                registered
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
                    "Unable to check Face ID status."
            });
        }
    }
);


/*
|--------------------------------------------------------------------------
| REGISTER FACE
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/register",
    faceLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            const image =
                req.body.image;

            if (!email) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }

            if (!image) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Face image is required."
                });
            }


            console.log(
                `Face registration started for ${email}`
            );


            const descriptor =
                await createFaceDescriptor(
                    image
                );


            faceUsers.set(
                email,
                {
                    descriptor,

                    createdAt:
                        new Date().toISOString()
                }
            );


            console.log(
                `Face registered for ${email}`
            );


            return res.json({
                success: true,

                registered:
                    true,

                message:
                    "Face ID registered successfully."
            });

        } catch (error) {

            console.error(
                "Face registration error:",
                error
            );

            return res.status(
                400
            ).json({
                success: false,
                message:
                    error.message ||
                    "Unable to register your face."
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
    faceLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            const image =
                req.body.image;


            if (!email) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }


            if (!image) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Face image is required."
                });
            }


            const storedUser =
                faceUsers.get(
                    email
                );


            if (!storedUser) {

                return res.status(
                    404
                ).json({
                    success: false,
                    registered:
                        false,
                    message:
                        "Face ID has not been registered for this account."
                });
            }


            const liveDescriptor =
                await createFaceDescriptor(
                    image
                );


            const distance =
                compareFaces(
                    storedUser.descriptor,
                    liveDescriptor
                );


            /*
            |--------------------------------------------------------------------------
            | FACE MATCH THRESHOLD
            |--------------------------------------------------------------------------
            |
            | Lower = stricter.
            |
            | 0.45 = strict
            | 0.50 = balanced
            | 0.60 = more tolerant
            |
            */

            const MATCH_THRESHOLD =
                0.50;


            console.log(
                `Face match for ${email}:`,
                distance
            );


            if (
                distance >
                MATCH_THRESHOLD
            ) {

                return res.status(
                    401
                ).json({
                    success: false,
                    authenticated:
                        false,
                    message:
                        "Face not recognized. Please try again."
                });
            }


            /*
            |--------------------------------------------------------------------------
            | SUCCESS
            |--------------------------------------------------------------------------
            */

            const loginToken =
                crypto.randomBytes(
                    32
                ).toString(
                    "hex"
                );


            console.log(
                `Face login successful for ${email}`
            );


            return res.json({
                success: true,

                authenticated:
                    true,

                email,

                token:
                    loginToken,

                message:
                    "Face recognized successfully."
            });

        } catch (error) {

            console.error(
                "Face login error:",
                error
            );

            return res.status(
                400
            ).json({
                success: false,
                authenticated:
                    false,
                message:
                    error.message ||
                    "Unable to verify your face."
            });
        }
    }
);


/*
|--------------------------------------------------------------------------
| DELETE FACE
|--------------------------------------------------------------------------
*/

app.post(
    "/api/face/remove",
    faceLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            if (!email) {

                return res.status(
                    400
                ).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }


            const removed =
                faceUsers.delete(
                    email
                );


            return res.json({
                success: true,

                removed,

                message:
                    removed
                        ? "Face ID removed successfully."
                        : "No Face ID was registered."
            });

        } catch (error) {

            console.error(
                "Face removal error:",
                error
            );

            return res.status(
                500
            ).json({
                success: false,
                message:
                    "Unable to remove Face ID."
            });
        }
    }
);


/*
|--------------------------------------------------------------------------
| SEND VERIFICATION CODE
|--------------------------------------------------------------------------
*/

app.post(
    "/api/send-code",
    sendCodeLimiter,
    async (req, res) => {

        const email =
            normalizeEmail(
                req.body.email
            );


        try {

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
                hashOTP(
                    code
                );


            otpRequests.set(
                email,
                {
                    codeHash,

                    expiresAt:
                        Date.now() +
                        10 * 60 * 1000,

                    attempts: 0,

                    lastSentAt:
                        Date.now()
                }
            );


            if (!resend) {

                throw new Error(
                    "RESEND_API_KEY is not configured."
                );
            }


            if (!EMAIL_FROM) {

                throw new Error(
                    "EMAIL_FROM is not configured."
                );
            }


            await resend.emails.send({
                from:
                    `${EMAIL_FROM_NAME} <${EMAIL_FROM}>`,

                to: [
                    email
                ],

                subject:
                    "Your Legacy Lens AI verification code",

                html: `
<!DOCTYPE html>
<html>
<body style="
    margin:0;
    padding:40px 20px;
    background:#f4f7fb;
    font-family:Arial,sans-serif;
">

<div style="
    max-width:600px;
    margin:auto;
    background:white;
    padding:40px;
    border-radius:20px;
">

<h1 style="
    text-align:center;
    color:#111827;
">
Legacy Lens AI
</h1>

<p style="
    text-align:center;
    color:#64748b;
">
Verify your email address
</p>

<div style="
    margin:30px 0;
    padding:30px;
    background:#f8fafc;
    border-radius:15px;
    text-align:center;
">

<p>
Your verification code is:
</p>

<div style="
    font-size:36px;
    font-weight:bold;
    letter-spacing:8px;
">
${code}
</div>

<p style="
    color:#64748b;
">
This code expires in 10 minutes.
</p>

</div>

<p style="
    color:#94a3b8;
    text-align:center;
    font-size:13px;
">
If you did not request this code,
you can safely ignore this email.
</p>

</div>

</body>
</html>
                `,

                text:
                    `Legacy Lens AI

Your verification code is:

${code}

This code expires in 10 minutes.

If you did not request this code,
you can safely ignore this email.`
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
| VERIFY CODE
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
                stored.attempts >=
                5
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
                hashOTP(
                    code
                );


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

                verified:
                    true,

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
| CLEAN EXPIRED OTP
|--------------------------------------------------------------------------
*/

setInterval(
    () => {

        const now =
            Date.now();

        for (
            const [
                email,
                data
            ] of otpRequests
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

    },
    60 * 1000
);


/*
|--------------------------------------------------------------------------
| 404
|--------------------------------------------------------------------------
*/

app.use(
    (req, res) => {

        res.status(
            404
        ).json({
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
            "Server error:",
            error
        );

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

async function startServer() {

    try {

        await loadFaceModels();

        app.listen(
            PORT,
            () => {

                console.log(
                    "===================================="
                );

                console.log(
                    "Legacy Lens AI backend"
                );

                console.log(
                    `Running on port ${PORT}`
                );

                console.log(
                    "Face recognition: READY"
                );

                console.log(
                    "===================================="
                );
            }
        );

    } catch (error) {

        console.error(
            "Failed to start server:",
            error
        );

        process.exit(
            1
        );
    }
}


startServer();
