```js
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

/*
|--------------------------------------------------------------------------
| APP CONFIGURATION
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
        methods: ["GET", "POST"],
        allowedHeaders: ["Content-Type"]
    })
);

app.use(
    express.json({
        limit: "100kb"
    })
);

/*
|--------------------------------------------------------------------------
| HEALTH
|--------------------------------------------------------------------------
*/

app.get("/api/health", (req, res) => {
    return res.json({
        success: true,
        service: "Legacy Lens AI",
        status: "online"
    });
});

/*
|--------------------------------------------------------------------------
| TEMPORARY FACE STORAGE
|--------------------------------------------------------------------------
|
| IMPORTANT:
| This Map is temporary.
|
| Render can restart your application, which will clear this data.
|
| For production, replace this with MongoDB, PostgreSQL,
| Firebase Firestore, Supabase, etc.
|
*/

const faceUsers = new Map();

/*
|--------------------------------------------------------------------------
| FACE RATE LIMITERS
|--------------------------------------------------------------------------
*/

const faceRegisterLimiter = rateLimit({
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

const faceLoginLimiter = rateLimit({
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
| VALIDATE EMAIL
|--------------------------------------------------------------------------
*/

function normalizeEmail(email) {
    return String(email || "")
        .trim()
        .toLowerCase();
}

function validEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/*
|--------------------------------------------------------------------------
| VALIDATE FACE DESCRIPTOR
|--------------------------------------------------------------------------
*/

function validateDescriptor(descriptor) {
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

/*
|--------------------------------------------------------------------------
| FACE DISTANCE
|--------------------------------------------------------------------------
|
| Euclidean distance between two 128-value face descriptors.
|
*/

function faceDistance(a, b) {
    if (
        !Array.isArray(a) ||
        !Array.isArray(b) ||
        a.length !== b.length
    ) {
        return Infinity;
    }

    let sum = 0;

    for (let i = 0; i < a.length; i++) {
        const difference = a[i] - b[i];

        sum += difference * difference;
    }

    return Math.sqrt(sum);
}

/*
|--------------------------------------------------------------------------
| DESCRIPTOR AVERAGE
|--------------------------------------------------------------------------
|
| We average several captures during registration.
| This makes the stored template more stable.
|
*/

function averageDescriptors(descriptors) {
    if (!descriptors.length) {
        return null;
    }

    const length = descriptors[0].length;

    const average = new Array(length).fill(0);

    for (const descriptor of descriptors) {
        for (let i = 0; i < length; i++) {
            average[i] += descriptor[i];
        }
    }

    for (let i = 0; i < length; i++) {
        average[i] /= descriptors.length;
    }

    return average;
}

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

            /*
            |--------------------------------------------------------------------------
            | VALIDATE EMAIL
            |--------------------------------------------------------------------------
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
            |--------------------------------------------------------------------------
            | VALIDATE DESCRIPTORS
            |--------------------------------------------------------------------------
            */

            if (
                !Array.isArray(descriptors) ||
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
                const descriptor of descriptors
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

            /*
            |--------------------------------------------------------------------------
            | CREATE STABLE TEMPLATE
            |--------------------------------------------------------------------------
            */

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

            /*
            |--------------------------------------------------------------------------
            | STORE TEMPLATE
            |--------------------------------------------------------------------------
            */

            const existing =
                faceUsers.get(email);

            faceUsers.set(email, {
                email,

                faceTemplate,

                registeredAt:
                    existing?.registeredAt ||
                    new Date().toISOString(),

                updatedAt:
                    new Date().toISOString()
            });

            console.log(
                `Face registered for ${email}`
            );

            return res.json({
                success: true,

                message:
                    "Face registered successfully.",

                registered: true
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
| CHECK WHETHER FACE IS REGISTERED
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
                faceUsers.get(email);

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

            /*
            |--------------------------------------------------------------------------
            | VALIDATE EMAIL
            |--------------------------------------------------------------------------
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
            |--------------------------------------------------------------------------
            | VALIDATE DESCRIPTOR
            |--------------------------------------------------------------------------
            */

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

            /*
            |--------------------------------------------------------------------------
            | FIND REGISTERED USER
            |--------------------------------------------------------------------------
            */

            const user =
                faceUsers.get(email);

            if (!user) {

                return res.status(404).json({
                    success: false,
                    registered: false,
                    message:
                        "No face is registered for this account."
                });
            }

            /*
            |--------------------------------------------------------------------------
            | COMPARE FACE
            |--------------------------------------------------------------------------
            */

            const distance =
                faceDistance(
                    descriptor,
                    user.faceTemplate
                );

            /*
            |--------------------------------------------------------------------------
            | MATCH THRESHOLD
            |--------------------------------------------------------------------------
            |
            | Lower = stricter.
            |
            | 0.45 is deliberately conservative.
            |
            */

            const MATCH_THRESHOLD =
                0.45;

            const matched =
                distance <=
                MATCH_THRESHOLD;

            /*
            |--------------------------------------------------------------------------
            | FAILED MATCH
            |--------------------------------------------------------------------------
            */

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
            |--------------------------------------------------------------------------
            | SUCCESS
            |--------------------------------------------------------------------------
            */

            console.log(
                `Face login successful for ${email}`
            );

            /*
            |--------------------------------------------------------------------------
            | DEMO AUTH TOKEN
            |--------------------------------------------------------------------------
            |
            | For a production system, replace this with a real
            | signed session/JWT connected to your authentication
            | system.
            |
            */

            const sessionToken =
                crypto
                    .randomBytes(32)
                    .toString("hex");

            return res.json({
                success: true,

                authenticated: true,

                message:
                    "Face recognized successfully.",

                email,

                token:
                    sessionToken
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
| REMOVE REGISTERED FACE
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
                faceUsers.delete(email);

            return res.json({
                success: true,

                removed: existed,

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
    (error, req, res, next) => {

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
    () => {

        console.log(
            `Legacy Lens AI backend running on port ${PORT}`
        );

        console.log(
            `Health: http://localhost:${PORT}/api/health`
        );

    }
);
```
