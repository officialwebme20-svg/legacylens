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
    process.env.BREVO_SENDER_NAME ||
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
   DATABASE FILES
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


function writeDatabase(
    database
) {

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


/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(
    email
) {

    return String(
        email || ""
    )
        .trim()
        .toLowerCase();
}


function validEmail(
    email
) {

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


function hashOTP(
    code
) {

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


function hashToken(
    token
) {

    return crypto
        .createHash("sha256")
        .update(
            token
        )
        .digest("hex");
}


function validateImage(
    image
) {

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

        res.json({

            success: true,

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


/* =========================================================
   OTP CLEANUP
========================================================= */

function cleanupExpiredOTPs() {

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
}


setInterval(
    cleanupExpiredOTPs,
    60 * 1000
);


/* =========================================================
   SEND EMAIL
========================================================= */

async function sendVerificationEmail({
    email,
    code
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


        subject:
            "Your Legacy Lens AI Verification Code",


        htmlContent: `

<!DOCTYPE html>

<html>

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
"
>

<h1
style="
text-align:center;
color:#111827;
"
>
Legacy Lens AI
</h1>

<p
style="
text-align:center;
color:#64748b;
"
>
Security Verification
</p>

<div
style="
margin-top:30px;
background:#f8fafc;
border-radius:16px;
padding:30px;
text-align:center;
"
>

<p>
Your verification code is:
</p>

<div
style="
font-size:40px;
font-weight:700;
letter-spacing:10px;
color:#111827;
"
>
${code}
</div>

<p
style="
color:#64748b;
"
>
This code expires in 10 minutes.
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

Your verification code is:

${code}

This code expires in 10 minutes.
`
    };


    return await brevo
        .transactionalEmails
        .sendTransacEmail(
            emailData
        );
}


/* =========================================================
   SEND OTP
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
                !validEmail(
                    email
                )
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
                    code
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
                        error.message ||
                        "Unable to send verification code."
                });
        }
    }
);


/* =========================================================
   VERIFY OTP
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
                        false
                };
            }


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

                email,

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

                    faceRegistered:
                        false
                };
            }


            database.users[email]
                .faceRegistered = true;


            database.users[email]
                .faceRegisteredAt =
                    new Date()
                        .toISOString();


            /*
             * For the demo we store a fingerprint
             * of the registration image rather
             * than pretending it is a biometric
             * face descriptor.
             */

            database.users[email]
                .faceSecurityHash =
                    crypto
                        .createHash("sha256")
                        .update(image)
                        .digest("hex");


            writeDatabase(
                database
            );


            console.log(
                `Face security registered for ${email}`
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
             * DEMO AUTHENTICATION
             *
             * The camera capture proves that the
             * security camera workflow is active.
             *
             * This does NOT claim to perform actual
             * biometric face matching.
             */


            const token =
                generateToken();


            const tokenHash =
                hashToken(token);


            const sessionId =
                crypto
                    .randomBytes(16)
                    .toString("hex");


            database.sessions[
                sessionId
            ] = {

                email,

                tokenHash,

                createdAt:
                    new Date()
                        .toISOString(),

                expiresAt:
                    new Date(
                        Date.now() +
                        7 * 24 * 60 * 60 * 1000
                    ).toISOString()
            };


            writeDatabase(
                database
            );


            console.log(
                `Face security login successful for ${email}`
            );


            return res.json({

                success:
                    true,

                authenticated:
                    true,

                email,

                token,

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

function getAuthorizationToken(
    req
) {

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

        return res.json({

            success:
                true,

            authenticated:
                true,

            email:
                req.auth.email
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
                "Face register: /api/face/register"
            );

            console.log(
                "Face status: /api/face/status"
            );

            console.log(
                "Face login: /api/face/login"
            );

            console.log(
                "Auth me: /api/auth/me"
            );

            console.log(
                "Auth logout: /api/auth/logout"
            );

            console.log(
                "Persistent database: ENABLED"
            );

            console.log(
                "Face models: NOT REQUIRED"
            );

            console.log(
                `Email service: ${
                    brevo
                        ? "READY"
                        : "NOT CONFIGURED"
                }`
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
