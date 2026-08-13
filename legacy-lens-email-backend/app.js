import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { BrevoClient } from "@getbrevo/brevo";

dotenv.config();

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
    process.env.FRONTEND_URL || "*";

const BREVO_API_KEY =
    process.env.BREVO_API_KEY || "";

const EMAIL_FROM =
    process.env.EMAIL_FROM ||
    process.env.BREVO_SENDER_EMAIL ||
    "";

const EMAIL_FROM_NAME =
    process.env.EMAIL_FROM_NAME ||
    "Legacy Lens AI";


/* =========================================================
   BREVO
========================================================= */

const brevo =
    BREVO_API_KEY
        ? new BrevoClient({
            apiKey: BREVO_API_KEY,
            timeoutInSeconds: 30,
            maxRetries: 2
        })
        : null;


/* =========================================================
   APP CONFIG
========================================================= */

app.disable("x-powered-by");

app.set("trust proxy", 1);

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

app.use(
    express.urlencoded({
        extended: true,
        limit: "15mb"
    })
);

app.use(
    (req, res, next) => {

        console.log(
            `${new Date().toISOString()} ${req.method} ${req.path}`
        );

        next();
    }
);


/* =========================================================
   DATABASE
========================================================= */

const dataDirectory =
    path.join(
        __dirname,
        "data"
    );

const databaseFile =
    path.join(
        dataDirectory,
        "database.json"
    );


if (
    !fs.existsSync(
        dataDirectory
    )
) {

    fs.mkdirSync(
        dataDirectory,
        {
            recursive: true
        }
    );
}


if (
    !fs.existsSync(
        databaseFile
    )
) {

    fs.writeFileSync(
        databaseFile,
        JSON.stringify(
            {
                users: {},
                sessions: {}
            },
            null,
            2
        )
    );
}


function readDatabase() {

    try {

        return JSON.parse(
            fs.readFileSync(
                databaseFile,
                "utf8"
            )
        );

    } catch (error) {

        console.error(
            "Database read error:",
            error
        );

        return {
            users: {},
            sessions: {}
        };
    }
}


function writeDatabase(database) {

    const temporaryFile =
        `${databaseFile}.tmp`;

    fs.writeFileSync(
        temporaryFile,
        JSON.stringify(
            database,
            null,
            2
        )
    );

    fs.renameSync(
        temporaryFile,
        databaseFile
    );
}


/* =========================================================
   MEMORY
========================================================= */

const otpRequests =
    new Map();

const vaultResetRequests =
    new Map();


/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(email) {

    return String(
        email || ""
    )
        .trim()
        .toLowerCase();
}


function validEmail(email) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email);
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
        .update(
            String(code)
        )
        .digest("hex");
}


function generateToken() {

    return crypto
        .randomBytes(48)
        .toString("hex");
}


function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(
            String(token)
        )
        .digest("hex");
}


function validateImage(image) {

    if (
        typeof image !==
        "string"
    ) {

        return false;
    }

    if (
        !image.startsWith(
            "data:image/"
        )
    ) {

        return false;
    }

    if (
        image.length >
        12 * 1024 * 1024
    ) {

        return false;
    }

    return true;
}


/* =========================================================
   PIN HELPERS
========================================================= */

function validPIN(pin) {

    return /^\d{4,8}$/
        .test(
            String(pin || "")
        );
}


function hashPIN(pin) {

    const salt =
        crypto.randomBytes(16);

    const derivedKey =
        crypto.scryptSync(
            String(pin),
            salt,
            64
        );

    return {
        algorithm: "scrypt",

        salt:
            salt.toString("hex"),

        hash:
            derivedKey.toString("hex")
    };
}


function verifyPIN(pin, storedPIN) {

    try {

        if (
            !storedPIN ||
            storedPIN.algorithm !==
            "scrypt" ||
            !storedPIN.salt ||
            !storedPIN.hash
        ) {

            return false;
        }

        const salt =
            Buffer.from(
                storedPIN.salt,
                "hex"
            );

        const expected =
            Buffer.from(
                storedPIN.hash,
                "hex"
            );

        const actual =
            crypto.scryptSync(
                String(pin),
                salt,
                expected.length
            );

        if (
            actual.length !==
            expected.length
        ) {

            return false;
        }

        return crypto.timingSafeEqual(
            actual,
            expected
        );

    } catch (error) {

        console.error(
            "PIN verification error:",
            error
        );

        return false;
    }
}


/* =========================================================
   SESSION CREATION
========================================================= */

function createAuthenticatedSession(
    database,
    email
) {

    const token =
        generateToken();

    const tokenHash =
        hashToken(token);

    const sessionId =
        crypto
            .randomBytes(16)
            .toString("hex");

    const now =
        Date.now();

    database.sessions[
        sessionId
    ] = {

        email,

        tokenHash,

        createdAt:
            new Date(
                now
            ).toISOString(),

        expiresAt:
            new Date(
                now +
                7 * 24 * 60 * 60 * 1000
            ).toISOString()
    };

    return {
        sessionId,
        token
    };
}


/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.json({

            success: true,

            service:
                "Legacy Lens AI",

            status:
                "online"
        });
    }
);


app.get(
    "/api/health",
    (req, res) => {

        return res.json({

            success:
                true,

            service:
                "Legacy Lens AI",

            status:
                "online",

            emailService:
                brevo
                    ? "configured"
                    : "not_configured",

            emailSender:
                EMAIL_FROM
                    ? "configured"
                    : "not_configured",

            cameraSecurity:
                "enabled",

            authentication:
                "enabled",

            vault:
                "enabled",

            persistentDatabase:
                "enabled"
        });
    }
);


/* =========================================================
   RATE LIMITERS
========================================================= */

const sendCodeLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            5,

        standardHeaders:
            true,

        legacyHeaders:
            false
    });


const verifyCodeLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            10,

        standardHeaders:
            true,

        legacyHeaders:
            false
    });


const faceRegisterLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            10,

        standardHeaders:
            true,

        legacyHeaders:
            false
    });


const faceLoginLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            20,

        standardHeaders:
            true,

        legacyHeaders:
            false
    });


const vaultCreateLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            10,

        standardHeaders:
            true,

        legacyHeaders:
            false
    });


const vaultVerifyLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            20,

        standardHeaders:
            true,

        legacyHeaders:
            false
    });


const vaultChangeLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            10,

        standardHeaders:
            true,

        legacyHeaders:
            false
    });


const vaultForgotLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            5,

        standardHeaders:
            true,

        legacyHeaders:
            false
    });


const vaultResetLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max:
            10,

        standardHeaders:
            true,

        legacyHeaders:
            false
    });


/* =========================================================
   OTP CLEANUP
========================================================= */

function cleanupExpiredRequests() {

    const now =
        Date.now();


    for (
        const [
            email,
            data
        ]
        of otpRequests.entries()
    ) {

        if (
            !data ||
            data.expiresAt <=
            now
        ) {

            otpRequests.delete(
                email
            );
        }
    }


    for (
        const [
            email,
            data
        ]
        of vaultResetRequests.entries()
    ) {

        if (
            !data ||
            data.expiresAt <=
            now
        ) {

            vaultResetRequests.delete(
                email
            );
        }
    }
}


setInterval(
    cleanupExpiredRequests,
    60 * 1000
);


/* =========================================================
   SEND VERIFICATION EMAIL
========================================================= */

async function sendVerificationEmail({
    email,
    code,
    purpose = "account"
}) {

    if (!brevo) {

        throw new Error(
            "Brevo email service is not configured."
        );
    }


    if (!EMAIL_FROM) {

        throw new Error(
            "Email sender is not configured."
        );
    }


    const subject =
        purpose === "vault"
            ? "Your Legacy Lens AI Vault Reset Code"
            : "Your Legacy Lens AI Verification Code";


    const title =
        purpose === "vault"
            ? "Vault Security Verification"
            : "Security Verification";


    const emailData = {

        sender: {

            email:
                EMAIL_FROM,

            name:
                EMAIL_FROM_NAME
        },


        to: [

            {
                email
            }

        ],


        subject,


        htmlContent: `

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

</head>

<body
style="
margin:0;
padding:0;
background:#f3f6fa;
font-family:Arial,Helvetica,sans-serif;
">

<div
style="
max-width:600px;
margin:40px auto;
padding:20px;
">

<div
style="
background:#ffffff;
border-radius:20px;
padding:40px 30px;
">

<h1
style="
text-align:center;
color:#111827;
margin-bottom:10px;
">

Legacy Lens AI

</h1>

<p
style="
text-align:center;
color:#64748b;
margin-top:0;
">

${title}

</p>

<div
style="
margin-top:30px;
background:#f8fafc;
border-radius:16px;
padding:30px;
text-align:center;
">

<p
style="
color:#334155;
font-size:16px;
">

Your verification code is:

</p>

<div
style="
font-size:40px;
font-weight:700;
letter-spacing:10px;
color:#111827;
margin:20px 0;
">

${code}

</div>

<p
style="
color:#64748b;
font-size:14px;
">

This code expires in 10 minutes.

</p>

<p
style="
color:#64748b;
font-size:13px;
">

If you did not request this code,
you can safely ignore this email.

</p>

</div>

</div>

</div>

</body>

</html>

`,

        textContent:
`
Legacy Lens AI

${title}

Your verification code is:

${code}

This code expires in 10 minutes.

If you did not request this code,
you can safely ignore this email.
`
    };


    return await brevo
        .transactionalEmails
        .sendTransacEmail(
            emailData
        );
}


/* =========================================================
   SEND ACCOUNT VERIFICATION CODE
========================================================= */

app.post(
    "/api/send-code",
    sendCodeLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );


            if (
                !validEmail(email)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        sent:
                            false,

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
                Date.now() -
                existing.lastSentAt <
                60000
            ) {

                return res
                    .status(429)
                    .json({

                        success:
                            false,

                        sent:
                            false,

                        message:
                            "Please wait before requesting another code."
                    });
            }


            const code =
                generateOTP();


            otpRequests.set(
                email,
                {

                    codeHash:
                        hashOTP(code),

                    expiresAt:
                        Date.now() +
                        10 * 60 * 1000,

                    attempts:
                        0,

                    lastSentAt:
                        Date.now()
                }
            );


            try {

                await sendVerificationEmail({
                    email,
                    code,
                    purpose:
                        "account"
                });

            } catch (error) {

                otpRequests.delete(
                    email
                );

                throw error;
            }


            return res.json({

                success:
                    true,

                sent:
                    true,

                message:
                    "Verification code sent successfully."
            });


        } catch (error) {

            console.error(
                "Send code error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    sent:
                        false,

                    message:
                        "Unable to send verification code."
                });
        }
    }
);


/* =========================================================
   VERIFY ACCOUNT CODE
========================================================= */

app.post(
    "/api/verify-code",
    verifyCodeLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );


            const code =
                String(
                    req.body?.code ||
                    ""
                ).trim();


            if (
                !validEmail(email)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Invalid email address."
                    });
            }


            const stored =
                otpRequests.get(
                    email
                );


            if (!stored) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Invalid or expired verification code."
                    });
            }


            if (
                Date.now() >
                stored.expiresAt
            ) {

                otpRequests.delete(
                    email
                );

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Verification code expired."
                    });
            }


            if (
                stored.attempts >=
                5
            ) {

                otpRequests.delete(
                    email
                );

                return res
                    .status(429)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Too many incorrect attempts."
                    });
            }


            const submittedHash =
                hashOTP(code);


            if (
                submittedHash !==
                stored.codeHash
            ) {

                stored.attempts++;

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Incorrect verification code."
                    });
            }


            const database =
                readDatabase();


            if (
                !database.users[email]
            ) {

                database.users[email] = {

                    email,

                    createdAt:
                        new Date()
                            .toISOString(),

                    faceRegistered:
                        false,

                    vaultPIN:
                        null
                };

            } else {

                if (
                    typeof database.users[email]
                        .vaultPIN ===
                    "undefined"
                ) {

                    database.users[email]
                        .vaultPIN = null;
                }

                if (
                    typeof database.users[email]
                        .faceRegistered ===
                    "undefined"
                ) {

                    database.users[email]
                        .faceRegistered = false;
                }
            }


            database.users[email]
                .emailVerified = true;


            database.users[email]
                .emailVerifiedAt =
                    new Date()
                        .toISOString();


            /*
             * IMPORTANT:
             *
             * Create an authenticated session immediately
             * after successful email verification.
             *
             * This allows vault.html to use:
             *
             * Authorization: Bearer TOKEN
             */

            const session =
                createAuthenticatedSession(
                    database,
                    email
                );


            writeDatabase(
                database
            );


            otpRequests.delete(
                email
            );


            return res.json({

                success:
                    true,

                verified:
                    true,

                authenticated:
                    true,

                email,

                token:
                    session.token,

                message:
                    "Email verified successfully."
            });


        } catch (error) {

            console.error(
                "Verify code error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    verified:
                        false,

                    authenticated:
                        false,

                    message:
                        "Verification failed."
                });
        }
    }
);


/* =========================================================
   FACE REGISTER
========================================================= */

app.post(
    "/api/face/register",
    faceRegisterLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );


            const image =
                req.body?.image;


            if (
                !validEmail(email)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Please provide a valid email address."
                    });
            }


            if (
                !validateImage(image)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "A valid camera image is required."
                    });
            }


            const database =
                readDatabase();


            if (
                !database.users[email]
            ) {

                database.users[email] = {

                    email,

                    createdAt:
                        new Date()
                            .toISOString(),

                    emailVerified:
                        false,

                    faceRegistered:
                        false,

                    vaultPIN:
                        null
                };
            }


            database.users[email]
                .faceRegistered = true;


            database.users[email]
                .faceRegisteredAt =
                    new Date()
                        .toISOString();


            database.users[email]
                .faceSecurityHash =
                    crypto
                        .createHash("sha256")
                        .update(image)
                        .digest("hex");


            writeDatabase(
                database
            );


            return res.json({

                success:
                    true,

                registered:
                    true,

                message:
                    "Face security registered successfully."
            });


        } catch (error) {

            console.error(
                "Face registration error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to register face security."
                });
        }
    }
);


/* =========================================================
   FACE STATUS
========================================================= */

app.post(
    "/api/face/status",
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );


            if (
                !validEmail(email)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Invalid email address."
                    });
            }


            const database =
                readDatabase();


            const user =
                database.users[email];


            return res.json({

                success:
                    true,

                registered:
                    Boolean(
                        user &&
                        user.faceRegistered
                    )
            });


        } catch (error) {

            console.error(
                "Face status error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to check face security status."
                });
        }
    }
);


/* =========================================================
   FACE LOGIN
========================================================= */

app.post(
    "/api/face/login",
    faceLoginLimiter,
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );


            const image =
                req.body?.image;


            if (
                !validEmail(email)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        authenticated:
                            false,

                        message:
                            "Invalid email address."
                    });
            }


            if (
                !validateImage(image)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        authenticated:
                            false,

                        message:
                            "Camera image is required."
                    });
            }


            const database =
                readDatabase();


            const user =
                database.users[email];


            if (
                !user ||
                !user.faceRegistered
            ) {

                return res
                    .status(404)
                    .json({

                        success:
                            false,

                        authenticated:
                            false,

                        registered:
                            false,

                        message:
                            "No face security profile exists for this account."
                    });
            }


            /*
             * IMPORTANT:
             *
             * This remains your existing DEMO face-login
             * behavior.
             *
             * It does NOT perform actual biometric
             * face recognition.
             */

            const session =
                createAuthenticatedSession(
                    database,
                    email
                );


            writeDatabase(
                database
            );


            return res.json({

                success:
                    true,

                authenticated:
                    true,

                email,

                token:
                    session.token,

                message:
                    "Face security verification successful."
            });


        } catch (error) {

            console.error(
                "Face login error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    authenticated:
                        false,

                    message:
                        "Unable to complete face login."
                });
        }
    }
);


/* =========================================================
   AUTH SESSION
========================================================= */

function getAuthorizationToken(req) {

    const header =
        req.headers.authorization ||
        "";


    if (
        !header.startsWith(
            "Bearer "
        )
    ) {

        return null;
    }


    return header
        .substring(7)
        .trim();
}


function authenticateSession(
    req,
    res,
    next
) {

    const token =
        getAuthorizationToken(
            req
        );


    if (!token) {

        return res
            .status(401)
            .json({

                success:
                    false,

                authenticated:
                    false,

                message:
                    "Authentication required."
            });
    }


    const tokenHash =
        hashToken(token);


    const database =
        readDatabase();


    let session =
        null;


    for (
        const [
            id,
            current
        ]
        of Object.entries(
            database.sessions
        )
    ) {

        if (
            current.tokenHash ===
            tokenHash
        ) {

            session = {

                id,

                ...current
            };

            break;
        }
    }


    if (!session) {

        return res
            .status(401)
            .json({

                success:
                    false,

                authenticated:
                    false,

                message:
                    "Invalid authentication session."
            });
    }


    if (
        Date.now() >
        new Date(
            session.expiresAt
        ).getTime()
    ) {

        delete database.sessions[
            session.id
        ];

        writeDatabase(
            database
        );


        return res
            .status(401)
            .json({

                success:
                    false,

                authenticated:
                    false,

                message:
                    "Your session has expired."
            });
    }


    req.auth =
        session;


    next();
}


/* =========================================================
   CURRENT USER
========================================================= */

app.get(
    "/api/auth/me",
    authenticateSession,
    (req, res) => {

        const database =
            readDatabase();


        const user =
            database.users[
                req.auth.email
            ];


        return res.json({

            success:
                true,

            authenticated:
                true,

            email:
                req.auth.email,

            emailVerified:
                Boolean(
                    user &&
                    user.emailVerified
                ),

            vaultPINCreated:
                Boolean(
                    user &&
                    user.vaultPIN
                ),

            faceRegistered:
                Boolean(
                    user &&
                    user.faceRegistered
                )
        });
    }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/auth/logout",
    authenticateSession,
    (req, res) => {

        const database =
            readDatabase();


        delete database.sessions[
            req.auth.id
        ];


        writeDatabase(
            database
        );


        return res.json({

            success:
                true,

            message:
                "Logged out successfully."
        });
    }
);


/* =========================================================
   VAULT STATUS
========================================================= */

app.get(
    "/api/vault/status",
    authenticateSession,
    (req, res) => {

        try {

            const database =
                readDatabase();


            const user =
                database.users[
                    req.auth.email
                ];


            return res.json({

                success:
                    true,

                hasPIN:
                    Boolean(
                        user &&
                        user.vaultPIN
                    ),

                email:
                    req.auth.email
            });

        } catch (error) {

            console.error(
                "Vault status error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to check Vault status."
                });
        }
    }
);


/* =========================================================
   CREATE VAULT PIN
========================================================= */

app.post(
    "/api/vault/create-pin",
    authenticateSession,
    vaultCreateLimiter,
    (req, res) => {

        try {

            const pin =
                String(
                    req.body?.pin ||
                    ""
                ).trim();


            const confirmPIN =
                String(
                    req.body?.confirmPIN ||
                    ""
                ).trim();


            if (
                !validPIN(pin)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "PIN must contain 4 to 8 digits."
                    });
            }


            if (
                pin !==
                confirmPIN
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "PINs do not match."
                    });
            }


            const database =
                readDatabase();


            const email =
                req.auth.email;


            const user =
                database.users[email];


            if (!user) {

                return res
                    .status(404)
                    .json({

                        success:
                            false,

                        message:
                            "Account not found."
                    });
            }


            if (
                user.vaultPIN
            ) {

                return res
                    .status(409)
                    .json({

                        success:
                            false,

                        message:
                            "A Vault PIN already exists."
                    });
            }


            user.vaultPIN =
                hashPIN(pin);


            user.vaultPINCreatedAt =
                new Date()
                    .toISOString();


            writeDatabase(
                database
            );


            return res.json({

                success:
                    true,

                created:
                    true,

                message:
                    "Vault PIN created successfully."
            });

        } catch (error) {

            console.error(
                "Vault create PIN error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to create Vault PIN."
                });
        }
    }
);


/* =========================================================
   VERIFY VAULT PIN
========================================================= */

app.post(
    "/api/vault/verify-pin",
    authenticateSession,
    vaultVerifyLimiter,
    (req, res) => {

        try {

            const pin =
                String(
                    req.body?.pin ||
                    ""
                ).trim();


            if (
                !validPIN(pin)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Invalid PIN format."
                    });
            }


            const database =
                readDatabase();


            const user =
                database.users[
                    req.auth.email
                ];


            if (
                !user ||
                !user.vaultPIN
            ) {

                return res
                    .status(404)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        hasPIN:
                            false,

                        message:
                            "No Vault PIN has been created."
                    });
            }


            const correct =
                verifyPIN(
                    pin,
                    user.vaultPIN
                );


            if (!correct) {

                return res
                    .status(401)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Incorrect Vault PIN."
                    });
            }


            return res.json({

                success:
                    true,

                verified:
                    true,

                message:
                    "Vault unlocked successfully."
            });

        } catch (error) {

            console.error(
                "Vault verify PIN error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    verified:
                        false,

                    message:
                        "Unable to verify Vault PIN."
                });
        }
    }
);


/* =========================================================
   CHANGE VAULT PIN
========================================================= */

app.post(
    "/api/vault/change-pin",
    authenticateSession,
    vaultChangeLimiter,
    (req, res) => {

        try {

            const currentPIN =
                String(
                    req.body?.currentPIN ||
                    ""
                ).trim();


            const newPIN =
                String(
                    req.body?.newPIN ||
                    ""
                ).trim();


            const confirmPIN =
                String(
                    req.body?.confirmPIN ||
                    ""
                ).trim();


            if (
                !validPIN(currentPIN) ||
                !validPIN(newPIN)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "PIN must contain 4 to 8 digits."
                    });
            }


            if (
                newPIN !==
                confirmPIN
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "New PINs do not match."
                    });
            }


            if (
                currentPIN ===
                newPIN
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "New PIN must be different from the current PIN."
                    });
            }


            const database =
                readDatabase();


            const user =
                database.users[
                    req.auth.email
                ];


            if (
                !user ||
                !user.vaultPIN
            ) {

                return res
                    .status(404)
                    .json({

                        success:
                            false,

                        message:
                            "No Vault PIN exists."
                    });
            }


            const currentCorrect =
                verifyPIN(
                    currentPIN,
                    user.vaultPIN
                );


            if (!currentCorrect) {

                return res
                    .status(401)
                    .json({

                        success:
                            false,

                        message:
                            "Current PIN is incorrect."
                    });
            }


            user.vaultPIN =
                hashPIN(newPIN);


            user.vaultPINChangedAt =
                new Date()
                    .toISOString();


            writeDatabase(
                database
            );


            return res.json({

                success:
                    true,

                changed:
                    true,

                message:
                    "Vault PIN changed successfully."
            });

        } catch (error) {

            console.error(
                "Vault change PIN error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to change Vault PIN."
                });
        }
    }
);


/* =========================================================
   FORGOT VAULT PIN
========================================================= */

app.post(
    "/api/vault/forgot-pin",
    authenticateSession,
    vaultForgotLimiter,
    async (req, res) => {

        try {

            const database =
                readDatabase();


            const email =
                req.auth.email;


            const user =
                database.users[email];


            if (!user) {

                return res
                    .status(404)
                    .json({

                        success:
                            false,

                        message:
                            "Account not found."
                    });
            }


            if (
                !user.vaultPIN
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "No Vault PIN exists for this account."
                    });
            }


            const existing =
                vaultResetRequests.get(
                    email
                );


            if (
                existing &&
                Date.now() -
                existing.lastSentAt <
                60000
            ) {

                return res
                    .status(429)
                    .json({

                        success:
                            false,

                        message:
                            "Please wait before requesting another reset code."
                    });
            }


            const code =
                generateOTP();


            const resetToken =
                generateToken();


            vaultResetRequests.set(
                email,
                {

                    codeHash:
                        hashOTP(code),

                    resetTokenHash:
                        hashToken(
                            resetToken
                        ),

                    resetToken,

                    expiresAt:
                        Date.now() +
                        10 * 60 * 1000,

                    attempts:
                        0,

                    lastSentAt:
                        Date.now()
                }
            );


            try {

                await sendVerificationEmail({

                    email,

                    code,

                    purpose:
                        "vault"

                });

            } catch (error) {

                vaultResetRequests.delete(
                    email
                );

                throw error;
            }


            return res.json({

                success:
                    true,

                sent:
                    true,

                message:
                    "A Vault verification code was sent to your account email."
            });

        } catch (error) {

            console.error(
                "Vault forgot PIN error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to send Vault reset code."
                });
        }
    }
);


/* =========================================================
   VERIFY VAULT RESET CODE
========================================================= */

app.post(
    "/api/vault/verify-reset-code",
    authenticateSession,
    vaultResetLimiter,
    (req, res) => {

        try {

            const code =
                String(
                    req.body?.code ||
                    ""
                ).trim();


            const email =
                req.auth.email;


            const stored =
                vaultResetRequests.get(
                    email
                );


            if (!stored) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Invalid or expired Vault verification code."
                    });
            }


            if (
                Date.now() >
                stored.expiresAt
            ) {

                vaultResetRequests.delete(
                    email
                );

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Vault verification code expired."
                    });
            }


            if (
                stored.attempts >=
                5
            ) {

                vaultResetRequests.delete(
                    email
                );

                return res
                    .status(429)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Too many incorrect attempts."
                    });
            }


            const submittedHash =
                hashOTP(code);


            if (
                submittedHash !==
                stored.codeHash
            ) {

                stored.attempts++;

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        verified:
                            false,

                        message:
                            "Incorrect Vault verification code."
                    });
            }


            /*
             * The reset token is now returned only after
             * successful verification.
             *
             * The token itself exists only in server memory.
             * The stored hash is used during reset.
             */

            return res.json({

                success:
                    true,

                verified:
                    true,

                resetToken:
                    stored.resetToken,

                message:
                    "Vault verification successful."
            });

        } catch (error) {

            console.error(
                "Vault reset verification error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    verified:
                        false,

                    message:
                        "Unable to verify Vault reset code."
                });
        }
    }
);


/* =========================================================
   RESET VAULT PIN
========================================================= */

app.post(
    "/api/vault/reset-pin",
    authenticateSession,
    vaultResetLimiter,
    (req, res) => {

        try {

            const resetToken =
                String(
                    req.body?.resetToken ||
                    ""
                ).trim();


            const newPIN =
                String(
                    req.body?.newPIN ||
                    ""
                ).trim();


            const confirmPIN =
                String(
                    req.body?.confirmPIN ||
                    ""
                ).trim();


            if (
                !resetToken
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Vault reset authorization is required."
                    });
            }


            if (
                !validPIN(newPIN)
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "PIN must contain 4 to 8 digits."
                    });
            }


            if (
                newPIN !==
                confirmPIN
            ) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "New PINs do not match."
                    });
            }


            const email =
                req.auth.email;


            const stored =
                vaultResetRequests.get(
                    email
                );


            if (!stored) {

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Vault reset authorization has expired."
                    });
            }


            if (
                Date.now() >
                stored.expiresAt
            ) {

                vaultResetRequests.delete(
                    email
                );

                return res
                    .status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Vault reset authorization has expired."
                    });
            }


            const suppliedTokenHash =
                hashToken(
                    resetToken
                );


            if (
                !stored.resetTokenHash ||
                suppliedTokenHash !==
                stored.resetTokenHash
            ) {

                return res
                    .status(401)
                    .json({

                        success:
                            false,

                        message:
                            "Invalid Vault reset authorization."
                    });
            }


            const database =
                readDatabase();


            const user =
                database.users[email];


            if (!user) {

                vaultResetRequests.delete(
                    email
                );

                return res
                    .status(404)
                    .json({

                        success:
                            false,

                        message:
                            "Account not found."
                    });
            }


            user.vaultPIN =
                hashPIN(newPIN);


            user.vaultPINChangedAt =
                new Date()
                    .toISOString();


            user.vaultPINResetAt =
                new Date()
                    .toISOString();


            writeDatabase(
                database
            );


            /*
             * One-time reset token.
             */

            vaultResetRequests.delete(
                email
            );


            return res.json({

                success:
                    true,

                reset:
                    true,

                message:
                    "Vault PIN reset successfully."
            });

        } catch (error) {

            console.error(
                "Vault reset PIN error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to reset Vault PIN."
                });
        }
    }
);


/* =========================================================
   REMOVE FACE SECURITY
========================================================= */

app.post(
    "/api/face/remove",
    authenticateSession,
    (req, res) => {

        try {

            const email =
                req.auth.email;


            const database =
                readDatabase();


            const user =
                database.users[email];


            if (!user) {

                return res.json({

                    success:
                        true,

                    removed:
                        false,

                    message:
                        "Account not found."
                });
            }


            user.faceRegistered =
                false;


            delete user.faceRegisteredAt;

            delete user.faceSecurityHash;


            writeDatabase(
                database
            );


            return res.json({

                success:
                    true,

                removed:
                    true,

                message:
                    "Face security removed successfully."
            });


        } catch (error) {

            console.error(
                "Face removal error:",
                error
            );


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to remove face security."
                });
        }
    }
);


/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        return res
            .status(404)
            .json({

                success:
                    false,

                message:
                    "Endpoint not found."
            });
    }
);


/* =========================================================
   GLOBAL ERROR
========================================================= */

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


        return res
            .status(500)
            .json({

                success:
                    false,

                message:
                    "Internal server error."
            });
    }
);


/* =========================================================
   SERVER
========================================================= */

const server =
    app.listen(
        PORT,
        () => {

            console.log(
                "======================================"
            );

            console.log(
                "Legacy Lens AI server started"
            );

            console.log(
                `Port: ${PORT}`
            );

            console.log(
                `Health: http://localhost:${PORT}/api/health`
            );

            console.log(
                ""
            );

            console.log(
                "ACCOUNT"
            );

            console.log(
                "Send code: /api/send-code"
            );

            console.log(
                "Verify code: /api/verify-code"
            );

            console.log(
                ""
            );

            console.log(
                "FACE SECURITY"
            );

            console.log(
                "Face register: /api/face/register"
            );

            console.log(
                "Face status: /api/face/status"
            );

            console.log(
                "Face login: /api/face/login"
            );

            console.log(
                ""
            );

            console.log(
                "AUTH"
            );

            console.log(
                "Auth me: /api/auth/me"
            );

            console.log(
                "Auth logout: /api/auth/logout"
            );

            console.log(
                ""
            );

            console.log(
                "VAULT"
            );

            console.log(
                "Vault status: /api/vault/status"
            );

            console.log(
                "Create PIN: /api/vault/create-pin"
            );

            console.log(
                "Verify PIN: /api/vault/verify-pin"
            );

            console.log(
                "Change PIN: /api/vault/change-pin"
            );

            console.log(
                "Forgot PIN: /api/vault/forgot-pin"
            );

            console.log(
                "Verify reset code: /api/vault/verify-reset-code"
            );

            console.log(
                "Reset PIN: /api/vault/reset-pin"
            );

            console.log(
                ""
            );

            console.log(
                `Email service: ${
                    brevo
                        ? "READY"
                        : "NOT CONFIGURED"
                }`
            );

            console.log(
                "Vault PIN hashing: scrypt"
            );

            console.log(
                "Persistent database: ENABLED"
            );

            console.log(
                "======================================"
            );
        }
    );


server.on(
    "error",
    error => {

        console.error(
            "HTTP server error:",
            error
        );
    }
);
