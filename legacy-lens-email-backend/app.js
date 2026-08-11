import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
    process.env.FRONTEND_URL || "*";

/*
|--------------------------------------------------------------------------
| FILE PATHS
|--------------------------------------------------------------------------
*/

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR =
    path.join(__dirname, "data");

const FACE_FILE =
    path.join(DATA_DIR, "face-users.json");

/*
|--------------------------------------------------------------------------
| CREATE DATA DIRECTORY
|--------------------------------------------------------------------------
*/

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, {
        recursive: true
    });
}

/*
|--------------------------------------------------------------------------
| LOAD STORED FACE USERS
|--------------------------------------------------------------------------
*/

let faceUsers = new Map();

function loadFaceUsers() {
    try {
        if (!fs.existsSync(FACE_FILE)) {
            fs.writeFileSync(
                FACE_FILE,
                JSON.stringify({}, null, 2)
            );

            return;
        }

        const raw =
            fs.readFileSync(
                FACE_FILE,
                "utf8"
            );

        const data =
            JSON.parse(raw);

        faceUsers =
            new Map(
                Object.entries(data)
            );

        console.log(
            `Loaded ${faceUsers.size} registered face user(s).`
        );

    } catch (error) {

        console.error(
            "Unable to load face database:",
            error
        );

        faceUsers = new Map();
    }
}

loadFaceUsers();

/*
|--------------------------------------------------------------------------
| SAVE FACE USERS
|--------------------------------------------------------------------------
*/

function saveFaceUsers() {

    try {

        const data =
            Object.fromEntries(
                faceUsers
            );

        fs.writeFileSync(
            FACE_FILE,
            JSON.stringify(
                data,
                null,
                2
            )
        );

    } catch (error) {

        console.error(
            "Unable to save face database:",
            error
        );

        throw error;
    }
}

/*
|--------------------------------------------------------------------------
| SECURITY
|--------------------------------------------------------------------------
*/

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

/*
|--------------------------------------------------------------------------
| CORS
|--------------------------------------------------------------------------
*/

app.use(
    cors({
        origin:
            FRONTEND_URL === "*"
                ? true
                : FRONTEND_URL,

        methods: [
            "GET",
            "POST",
            "OPTIONS"
        ],

        allowedHeaders: [
            "Content-Type"
        ]
    })
);

/*
|--------------------------------------------------------------------------
| JSON
|--------------------------------------------------------------------------
*/

app.use(
    express.json({
        limit: "250kb"
    })
);

/*
|--------------------------------------------------------------------------
| HEALTH
|--------------------------------------------------------------------------
*/

app.get(
    "/api/health",
    (req, res) => {

        return res.json({
            success: true,
            service: "Legacy Lens AI",
            status: "online"
        });

    }
);

/*
|--------------------------------------------------------------------------
| NORMALIZE EMAIL
|--------------------------------------------------------------------------
*/

function normalizeEmail(email) {

    return String(email || "")
        .trim()
        .toLowerCase();
}

/*
|--------------------------------------------------------------------------
| VALIDATE EMAIL
|--------------------------------------------------------------------------
*/

function validEmail(email) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email);
}

/*
|--------------------------------------------------------------------------
| VALIDATE DESCRIPTOR
|--------------------------------------------------------------------------
*/

function validateDescriptor(
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
        descriptor.length !== 128
    ) {
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
*/

function faceDistance(
    a,
    b
) {

    if (
        !validateDescriptor(a) ||
        !validateDescriptor(b)
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

/*
|--------------------------------------------------------------------------
| AVERAGE DESCRIPTORS
|--------------------------------------------------------------------------
*/

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
        new Array(length)
            .fill(0);

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
| RATE LIMITERS
|--------------------------------------------------------------------------
*/

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

        max: 30,

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
            | EMAIL
            |--------------------------------------------------------------------------
            */

            if (!email) {

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Email address is required."

                    });
            }

            if (!validEmail(email)) {

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Please provide a valid email address."

                    });
            }

            /*
            |--------------------------------------------------------------------------
            | DESCRIPTORS
            |--------------------------------------------------------------------------
            */

            if (
                !Array.isArray(
                    descriptors
                )
            ) {

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Face data is required."

                    });
            }

            if (
                descriptors.length < 3 ||
                descriptors.length > 10
            ) {

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Please provide between 3 and 10 face captures."

                    });
            }

            /*
            |--------------------------------------------------------------------------
            | VALIDATE EACH CAPTURE
            |--------------------------------------------------------------------------
            */

            for (
                const descriptor
                of descriptors
            ) {

                if (
                    !validateDescriptor(
                        descriptor
                    )
                ) {

                    return res.status(400)
                        .json({

                            success: false,

                            message:
                                "Invalid face data received."

                        });
                }
            }

            /*
            |--------------------------------------------------------------------------
            | CREATE TEMPLATE
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

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Unable to create face template."

                    });
            }

            /*
            |--------------------------------------------------------------------------
            | STORE USER
            |--------------------------------------------------------------------------
            */

            const existing =
                faceUsers.get(
                    email
                );

            const user = {

                email,

                faceTemplate,

                registeredAt:
                    existing?.registeredAt ||
                    new Date()
                        .toISOString(),

                updatedAt:
                    new Date()
                        .toISOString()

            };

            faceUsers.set(
                email,
                user
            );

            /*
            |--------------------------------------------------------------------------
            | SAVE
            |--------------------------------------------------------------------------
            */

            saveFaceUsers();

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

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Email address is required."

                    });
            }

            if (!validEmail(email)) {

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Please provide a valid email address."

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

            return res.status(500)
                .json({

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
            | EMAIL
            |--------------------------------------------------------------------------
            */

            if (!email) {

                return res.status(400)
                    .json({

                        success: false,

                        authenticated: false,

                        message:
                            "Email address is required."

                    });
            }

            if (!validEmail(email)) {

                return res.status(400)
                    .json({

                        success: false,

                        authenticated: false,

                        message:
                            "Please provide a valid email address."

                    });
            }

            /*
            |--------------------------------------------------------------------------
            | DESCRIPTOR
            |--------------------------------------------------------------------------
            */

            if (
                !validateDescriptor(
                    descriptor
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

            /*
            |--------------------------------------------------------------------------
            | FIND USER
            |--------------------------------------------------------------------------
            */

            const user =
                faceUsers.get(
                    email
                );

            if (!user) {

                return res.status(404)
                    .json({

                        success: false,

                        authenticated: false,

                        registered: false,

                        message:
                            "No face is registered for this account."

                    });
            }

            /*
            |--------------------------------------------------------------------------
            | COMPARE
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
            | 0.45 = relatively strict.
            |
            */

            const MATCH_THRESHOLD =
                0.45;

            const matched =
                distance <=
                MATCH_THRESHOLD;

            console.log(
                `Face comparison for ${email}: ${distance.toFixed(4)}`
            );

            /*
            |--------------------------------------------------------------------------
            | NOT MATCHED
            |--------------------------------------------------------------------------
            */

            if (!matched) {

                return res.status(401)
                    .json({

                        success: false,

                        authenticated: false,

                        message:
                            "Face not recognized. Please try again."

                    });
            }

            /*
            |--------------------------------------------------------------------------
            | CREATE SESSION TOKEN
            |--------------------------------------------------------------------------
            */

            const sessionToken =
                crypto
                    .randomBytes(32)
                    .toString("hex");

            /*
            |--------------------------------------------------------------------------
            | SUCCESS
            |--------------------------------------------------------------------------
            */

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

            return res.status(500)
                .json({

                    success: false,

                    authenticated: false,

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

                return res.status(400)
                    .json({

                        success: false,

                        message:
                            "Email address is required."

                    });
            }

            const existed =
                faceUsers.delete(
                    email
                );

            if (existed) {
                saveFaceUsers();
            }

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

            return res.status(500)
                .json({

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

        return res.status(404)
            .json({

                success: false,

                message:
                    "Endpoint not found."

            });
    }
);

/*
|--------------------------------------------------------------------------
| GLOBAL ERROR
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
            "Global server error:",
            error
        );

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
| START
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
