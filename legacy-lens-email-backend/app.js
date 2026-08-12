import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "crypto";
import pg from "pg";
import { BrevoClient } from "@getbrevo/brevo";

dotenv.config();

const { Pool } = pg;

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
    process.env.FRONTEND_URL || "*";

const DATABASE_URL =
    process.env.DATABASE_URL || "";

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

const SESSION_DAYS =
    Number(process.env.SESSION_DAYS || 30);

const FACE_MATCH_THRESHOLD =
    Number(
        process.env.FACE_MATCH_THRESHOLD || 0.45
    );

const FACE_ENCRYPTION_KEY =
    process.env.FACE_ENCRYPTION_KEY || "";

if (!DATABASE_URL) {
    console.error(
        "DATABASE_URL is not configured."
    );
}

if (!FACE_ENCRYPTION_KEY) {
    console.error(
        "FACE_ENCRYPTION_KEY is not configured."
    );
}

if (
    FACE_ENCRYPTION_KEY &&
    !/^[0-9a-fA-F]{64}$/.test(
        FACE_ENCRYPTION_KEY
    )
) {
    console.error(
        "FACE_ENCRYPTION_KEY must be exactly 64 hexadecimal characters."
    );
}

const pool = DATABASE_URL
    ? new Pool({
        connectionString:
            DATABASE_URL,
        ssl:
            process.env.NODE_ENV ===
            "production"
                ? {
                    rejectUnauthorized:
                        false
                }
                : false
    })
    : null;

pool?.on(
    "error",
    error => {
        console.error(
            "PostgreSQL pool error:",
            error
        );
    }
);

const brevo = BREVO_API_KEY
    ? new BrevoClient({
        apiKey:
            BREVO_API_KEY,
        timeoutInSeconds: 30,
        maxRetries: 2
    })
    : null;

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

function hashValue(value) {
    return crypto
        .createHash("sha256")
        .update(String(value))
        .digest("hex");
}

function generateToken() {
    return crypto
        .randomBytes(32)
        .toString("hex");
}

function timingSafeEqualStrings(
    a,
    b
) {
    const bufferA =
        Buffer.from(
            String(a),
            "utf8"
        );

    const bufferB =
        Buffer.from(
            String(b),
            "utf8"
        );

    if (
        bufferA.length !==
        bufferB.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        bufferA,
        bufferB
    );
}

function encryptFaceData(data) {
    if (
        !FACE_ENCRYPTION_KEY ||
        !/^[0-9a-fA-F]{64}$/.test(
            FACE_ENCRYPTION_KEY
        )
    ) {
        throw new Error(
            "FACE_ENCRYPTION_KEY is not configured correctly."
        );
    }

    const key =
        Buffer.from(
            FACE_ENCRYPTION_KEY,
            "hex"
        );

    const iv =
        crypto.randomBytes(12);

    const cipher =
        crypto.createCipheriv(
            "aes-256-gcm",
            key,
            iv
        );

    const plaintext =
        Buffer.from(
            JSON.stringify(data),
            "utf8"
        );

    const encrypted =
        Buffer.concat([
            cipher.update(
                plaintext
            ),
            cipher.final()
        ]);

    const authTag =
        cipher.getAuthTag();

    return {
        encrypted:
            encrypted.toString(
                "base64"
            ),
        iv:
            iv.toString(
                "base64"
            ),
        authTag:
            authTag.toString(
                "base64"
            )
    };
}

function decryptFaceData({
    encrypted,
    iv,
    authTag
}) {
    if (
        !FACE_ENCRYPTION_KEY ||
        !/^[0-9a-fA-F]{64}$/.test(
            FACE_ENCRYPTION_KEY
        )
    ) {
        throw new Error(
            "FACE_ENCRYPTION_KEY is not configured correctly."
        );
    }

    const key =
        Buffer.from(
            FACE_ENCRYPTION_KEY,
            "hex"
        );

    const decipher =
        crypto.createDecipheriv(
            "aes-256-gcm",
            key,
            Buffer.from(
                iv,
                "base64"
            )
        );

    decipher.setAuthTag(
        Buffer.from(
            authTag,
            "base64"
        )
    );

    const decrypted =
        Buffer.concat([
            decipher.update(
                Buffer.from(
                    encrypted,
                    "base64"
                )
            ),
            decipher.final()
        ]);

    return JSON.parse(
        decrypted.toString(
            "utf8"
        )
    );
}

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
        descriptor.length !==
        128
    ) {
        return false;
    }

    return descriptor.every(
        value =>
            typeof value ===
                "number" &&
            Number.isFinite(
                value
            )
    );
}

function faceDistance(
    a,
    b
) {
    if (
        !Array.isArray(a) ||
        !Array.isArray(b) ||
        a.length !==
            b.length
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

    return Math.sqrt(
        sum
    );
}

function averageDescriptors(
    descriptors
) {
    if (
        !Array.isArray(
            descriptors
        ) ||
        descriptors.length === 0
    ) {
        return null;
    }

    const length =
        descriptors[0].length;

    const average =
        new Array(
            length
        ).fill(0);

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

function getBearerToken(req) {
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
        .slice(7)
        .trim();
}

async function createDatabase() {
    if (!pool) {
        throw new Error(
            "DATABASE_URL is not configured."
        );
    }

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email TEXT UNIQUE NOT NULL,
            email_verified BOOLEAN NOT NULL DEFAULT FALSE,
            email_verified_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS otp_codes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            verified BOOLEAN NOT NULL DEFAULT FALSE,
            verified_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_otp_user_id
        ON otp_codes(user_id);
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS face_profiles (
            user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            encrypted_template TEXT NOT NULL,
            iv TEXT NOT NULL,
            auth_tag TEXT NOT NULL,
            registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS auth_sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            revoked_at TIMESTAMPTZ
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_token
        ON auth_sessions(token_hash);
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
        ON auth_sessions(user_id);
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_users_email
        ON users(email);
    `);

    console.log(
        "PostgreSQL database initialized."
    );
}

async function cleanupDatabase() {
    if (!pool) {
        return;
    }

    try {
        await pool.query(`
            DELETE FROM otp_codes
            WHERE expires_at < NOW()
        `);

        await pool.query(`
            DELETE FROM auth_sessions
            WHERE expires_at < NOW()
               OR revoked_at IS NOT NULL
        `);
    } catch (error) {
        console.error(
            "Database cleanup error:",
            error
        );
    }
}

const sendCodeLimiter =
    rateLimit({
        windowMs:
            15 * 60 * 1000,
        max: 5,
        standardHeaders: true,
        legacyHeaders: false,
        message: {
            success: false,
            sent: false,
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
            verified: false,
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
            authenticated: false,
            message:
                "Too many face login attempts. Please try again later."
        }
    });

const sessionLimiter =
    rateLimit({
        windowMs:
            15 * 60 * 1000,
        max: 100,
        standardHeaders: true,
        legacyHeaders: false,
        message: {
            success: false,
            message:
                "Too many authentication requests."
        }
    });

app.use(
    helmet({
        crossOriginResourcePolicy:
            false
    })
);

const allowedOrigins =
    FRONTEND_URL === "*"
        ? true
        : FRONTEND_URL
            .split(",")
            .map(
                value =>
                    value.trim()
            )
            .filter(Boolean);

app.use(
    cors({
        origin:
            allowedOrigins,
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
        limit: "10mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "10mb"
    })
);

app.use(
    (
        req,
        res,
        next
    ) => {
        console.log(
            `${new Date().toISOString()} ${req.method} ${req.path}`
        );

        next();
    }
);

app.get(
    "/",
    (
        req,
        res
    ) => {
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
    async (
        req,
        res
    ) => {
        let database =
            "not_configured";

        if (pool) {
            try {
                await pool.query(
                    "SELECT 1"
                );

                database =
                    "connected";
            } catch {
                database =
                    "error";
            }
        }

        res.json({
            success: true,
            service:
                "Legacy Lens AI",
            status:
                "online",
            database,
            emailService:
                brevo
                    ? "configured"
                    : "not_configured",
            emailSender:
                EMAIL_FROM
                    ? "configured"
                    : "not_configured",
            faceService:
                "online",
            authentication:
                "database_sessions"
        });
    }
);

async function getOrCreateUser(
    email
) {
    const result =
        await pool.query(
            `
            INSERT INTO users (
                email
            )
            VALUES ($1)
            ON CONFLICT (email)
            DO UPDATE SET
                updated_at = NOW()
            RETURNING *
            `,
            [email]
        );

    return result.rows[0];
}

async function sendVerificationEmail({
    email,
    code
}) {
    if (!BREVO_API_KEY) {
        throw new Error(
            "BREVO_API_KEY is not configured on the server."
        );
    }

    if (!brevo) {
        throw new Error(
            "Brevo email service is not initialized."
        );
    }

    if (!EMAIL_FROM) {
        throw new Error(
            "EMAIL_FROM or BREVO_SENDER_EMAIL is not configured."
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
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Legacy Lens AI</title>
</head>

<body style="margin:0;padding:0;background:#f3f6fa;font-family:Arial,Helvetica,sans-serif;">

<div style="max-width:600px;margin:40px auto;padding:20px;">

<div style="background:#ffffff;border-radius:20px;padding:40px 30px;box-shadow:0 10px 35px rgba(0,0,0,0.08);">

<div style="text-align:center;">

<h1 style="margin:0;font-size:28px;color:#111827;">
Legacy Lens AI
</h1>

<p style="margin-top:10px;color:#64748b;font-size:15px;">
Security Verification
</p>

</div>

<div style="margin-top:30px;background:#f8fafc;border-radius:16px;padding:30px 20px;text-align:center;">

<p style="margin:0 0 18px;font-size:15px;color:#475569;">
Your verification code is
</p>

<div style="font-size:40px;font-weight:700;letter-spacing:10px;color:#111827;">
${code}
</div>

<p style="margin:20px 0 0;font-size:14px;color:#64748b;">
This code expires in 10 minutes.
</p>

</div>

<p style="margin-top:30px;font-size:14px;line-height:1.7;color:#64748b;text-align:center;">
If you did not request this code, you can safely ignore this email.
</p>

<p style="margin-top:30px;font-size:12px;color:#94a3b8;text-align:center;">
© ${new Date().getFullYear()} Legacy Lens AI
</p>

</div>

</div>

</body>
</html>
`,

        textContent:
`Legacy Lens AI

Security Verification

Your verification code is:

${code}

This code expires in 10 minutes.

If you did not request this code,
you can safely ignore this email.

© ${new Date().getFullYear()} Legacy Lens AI`
    };

    return await brevo
        .transactionalEmails
        .sendTransacEmail(
            emailData
        );
}

app.post(
    "/api/send-code",
    sendCodeLimiter,
    async (
        req,
        res
    ) => {
        try {
            if (!pool) {
                return res.status(
                    500
                ).json({
                    success:
                        false,
                    sent:
                        false,
                    message:
                        "Database is not configured."
                });
            }

            const email =
                normalizeEmail(
                    req.body?.email
                );

            if (!email) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    sent:
                        false,
                    message:
                        "Email address is required."
                });
            }

            if (
                !validEmail(
                    email
                )
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    sent:
                        false,
                    message:
                        "Please provide a valid email address."
                });
            }

            const user =
                await getOrCreateUser(
                    email
                );

            const previous =
                await pool.query(
                    `
                    SELECT *
                    FROM otp_codes
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    LIMIT 1
                    `,
                    [user.id]
                );

            if (
                previous.rows.length
            ) {
                const last =
                    previous.rows[0];

                const seconds =
                    (
                        Date.now() -
                        new Date(
                            last.last_sent_at
                        ).getTime()
                    ) / 1000;

                if (
                    seconds <
                    60
                ) {
                    const remaining =
                        Math.ceil(
                            60 -
                            seconds
                        );

                    return res.status(
                        429
                    ).json({
                        success:
                            false,
                        sent:
                            false,
                        message:
                            `Please wait ${remaining} seconds before requesting another code.`
                    });
                }
            }

            const code =
                generateOTP();

            const codeHash =
                hashValue(code);

            await pool.query(
                `
                UPDATE otp_codes
                SET expires_at = NOW()
                WHERE user_id = $1
                  AND verified = FALSE
                `,
                [user.id]
            );

            await pool.query(
                `
                INSERT INTO otp_codes (
                    user_id,
                    code_hash,
                    expires_at,
                    attempts,
                    last_sent_at
                )
                VALUES (
                    $1,
                    $2,
                    NOW() + INTERVAL '10 minutes',
                    0,
                    NOW()
                )
                `,
                [
                    user.id,
                    codeHash
                ]
            );

            try {
                await sendVerificationEmail({
                    email,
                    code
                });
            } catch (
                emailError
            ) {
                console.error(
                    "Brevo error:",
                    emailError
                );

                await pool.query(
                    `
                    UPDATE otp_codes
                    SET expires_at = NOW()
                    WHERE user_id = $1
                      AND verified = FALSE
                    `,
                    [user.id]
                );

                return res.status(
                    500
                ).json({
                    success:
                        false,
                    sent:
                        false,
                    message:
                        emailError?.message ||
                        "Unable to send verification email."
                });
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

            return res.status(
                500
            ).json({
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

app.post(
    "/api/verify-code",
    verifyCodeLimiter,
    async (
        req,
        res
    ) => {
        try {
            if (!pool) {
                return res.status(
                    500
                ).json({
                    success:
                        false,
                    verified:
                        false,
                    message:
                        "Database is not configured."
                });
            }

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
                !email ||
                !code
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    verified:
                        false,
                    message:
                        "Email and verification code are required."
                });
            }

            if (
                !validEmail(
                    email
                )
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    verified:
                        false,
                    message:
                        "Please provide a valid email address."
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
                    success:
                        false,
                    verified:
                        false,
                    message:
                        "Verification code must contain 6 digits."
                });
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        otp_codes.*,
                        users.email
                    FROM otp_codes
                    INNER JOIN users
                        ON users.id = otp_codes.user_id
                    WHERE users.email = $1
                    ORDER BY otp_codes.created_at DESC
                    LIMIT 1
                    `,
                    [email]
                );

            if (
                !result.rows.length
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    verified:
                        false,
                    message:
                        "This verification code is invalid or has expired."
                });
            }

            const stored =
                result.rows[0];

            if (
                new Date(
                    stored.expires_at
                ).getTime() <
                Date.now()
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    verified:
                        false,
                    message:
                        "This verification code has expired. Request a new code."
                });
            }

            if (
                stored.verified
            ) {
                return res.json({
                    success:
                        true,
                    verified:
                        true,
                    email,
                    message:
                        "Email is already verified."
                });
            }

            if (
                stored.attempts >=
                5
            ) {
                return res.status(
                    429
                ).json({
                    success:
                        false,
                    verified:
                        false,
                    message:
                        "Too many incorrect attempts. Request a new code."
                });
            }

            const submittedHash =
                hashValue(code);

            if (
                !timingSafeEqualStrings(
                    submittedHash,
                    stored.code_hash
                )
            ) {
                await pool.query(
                    `
                    UPDATE otp_codes
                    SET attempts = attempts + 1
                    WHERE id = $1
                    `,
                    [stored.id]
                );

                return res.status(
                    400
                ).json({
                    success:
                        false,
                    verified:
                        false,
                    message:
                        "Incorrect verification code."
                });
            }

            await pool.query(
                `
                UPDATE otp_codes
                SET
                    verified = TRUE,
                    verified_at = NOW()
                WHERE id = $1
                `,
                [stored.id]
            );

            await pool.query(
                `
                UPDATE users
                SET
                    email_verified = TRUE,
                    email_verified_at = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                `,
                [stored.user_id]
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

            return res.status(
                500
            ).json({
                success:
                    false,
                verified:
                    false,
                message:
                    "Something went wrong while verifying the code."
            });
        }
    }
);

app.post(
    "/api/face/register",
    faceRegisterLimiter,
    async (
        req,
        res
    ) => {
        try {
            if (!pool) {
                return res.status(
                    500
                ).json({
                    success:
                        false,
                    message:
                        "Database is not configured."
                });
            }

            const email =
                normalizeEmail(
                    req.body?.email
                );

            const descriptors =
                req.body?.descriptors;

            if (
                !validEmail(
                    email
                )
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    message:
                        "Please provide a valid email address."
                });
            }

            if (
                !Array.isArray(
                    descriptors
                ) ||
                descriptors.length <
                    3 ||
                descriptors.length >
                    10
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
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
                    return res.status(
                        400
                    ).json({
                        success:
                            false,
                        message:
                            "Invalid face data received."
                    });
                }
            }

            const userResult =
                await pool.query(
                    `
                    SELECT *
                    FROM users
                    WHERE email = $1
                    LIMIT 1
                    `,
                    [email]
                );

            if (
                !userResult.rows.length
            ) {
                return res.status(
                    404
                ).json({
                    success:
                        false,
                    message:
                        "Account not found. Verify your email first."
                });
            }

            const user =
                userResult.rows[0];

            if (
                !user.email_verified
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,
                    message:
                        "Verify your email before registering your face."
                });
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
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    message:
                        "Unable to create face template."
                });
            }

            const encrypted =
                encryptFaceData(
                    faceTemplate
                );

            await pool.query(
                `
                INSERT INTO face_profiles (
                    user_id,
                    encrypted_template,
                    iv,
                    auth_tag
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4
                )
                ON CONFLICT (user_id)
                DO UPDATE SET
                    encrypted_template = EXCLUDED.encrypted_template,
                    iv = EXCLUDED.iv,
                    auth_tag = EXCLUDED.auth_tag,
                    updated_at = NOW()
                `,
                [
                    user.id,
                    encrypted.encrypted,
                    encrypted.iv,
                    encrypted.authTag
                ]
            );

            return res.json({
                success:
                    true,
                registered:
                    true,
                message:
                    "Face registered successfully."
            });

        } catch (error) {
            console.error(
                "Face registration error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,
                message:
                    "Unable to register your face."
            });
        }
    }
);

app.post(
    "/api/face/status",
    async (
        req,
        res
    ) => {
        try {
            if (!pool) {
                return res.status(
                    500
                ).json({
                    success:
                        false,
                    message:
                        "Database is not configured."
                });
            }

            const email =
                normalizeEmail(
                    req.body?.email
                );

            if (
                !validEmail(
                    email
                )
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    message:
                        "Please provide a valid email address."
                });
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        users.email_verified,
                        face_profiles.user_id
                    FROM users
                    LEFT JOIN face_profiles
                        ON face_profiles.user_id = users.id
                    WHERE users.email = $1
                    LIMIT 1
                    `,
                    [email]
                );

            if (
                !result.rows.length
            ) {
                return res.json({
                    success:
                        true,
                    registered:
                        false,
                    emailVerified:
                        false
                });
            }

            const row =
                result.rows[0];

            return res.json({
                success:
                    true,
                registered:
                    Boolean(
                        row.user_id
                    ),
                emailVerified:
                    Boolean(
                        row.email_verified
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
                success:
                    false,
                    message:
                        "Unable to check face status."
                });
        }
    }
);

async function createSession(
    userId
) {
    const rawToken =
        generateToken();

    const tokenHash =
        hashValue(
            rawToken
        );

    await pool.query(
        `
        INSERT INTO auth_sessions (
            user_id,
            token_hash,
            expires_at
        )
        VALUES (
            $1,
            $2,
            NOW() + ($3 * INTERVAL '1 day')
        )
        `,
        [
            userId,
            tokenHash,
            SESSION_DAYS
        ]
    );

    return rawToken;
}

async function authenticateSession(
    req,
    res,
    next
) {
    try {
        if (!pool) {
            return res.status(
                500
            ).json({
                success:
                    false,
                message:
                    "Database is not configured."
            });
        }

        const token =
            getBearerToken(req);

        if (!token) {
            return res.status(
                401
            ).json({
                success:
                    false,
                authenticated:
                    false,
                message:
                    "Authentication required."
            });
        }

        const tokenHash =
            hashValue(
                token
            );

        const result =
            await pool.query(
                `
                SELECT
                    auth_sessions.id AS session_id,
                    auth_sessions.user_id,
                    auth_sessions.expires_at,
                    users.email,
                    users.email_verified
                FROM auth_sessions
                INNER JOIN users
                    ON users.id =
                       auth_sessions.user_id
                WHERE auth_sessions.token_hash = $1
                  AND auth_sessions.revoked_at IS NULL
                  AND auth_sessions.expires_at > NOW()
                LIMIT 1
                `,
                [tokenHash]
            );

        if (
            !result.rows.length
        ) {
            return res.status(
                401
            ).json({
                success:
                    false,
                authenticated:
                    false,
                message:
                    "Session expired or invalid. Please log in again."
            });
        }

        const session =
            result.rows[0];

        await pool.query(
            `
            UPDATE auth_sessions
            SET last_used_at = NOW()
            WHERE id = $1
            `,
            [session.session_id]
        );

        req.user = {
            id:
                session.user_id,
            email:
                session.email,
            emailVerified:
                session.email_verified,
            sessionId:
                session.session_id
        };

        next();

    } catch (error) {
        console.error(
            "Session authentication error:",
            error
        );

        return res.status(
            500
        ).json({
            success:
                false,
            message:
                "Unable to authenticate session."
        });
    }
}

app.post(
    "/api/face/login",
    faceLoginLimiter,
    async (
        req,
        res
    ) => {
        try {
            if (!pool) {
                return res.status(
                    500
                ).json({
                    success:
                        false,
                    authenticated:
                        false,
                    message:
                        "Database is not configured."
                });
            }

            const email =
                normalizeEmail(
                    req.body?.email
                );

            const descriptor =
                req.body?.descriptor;

            if (
                !validEmail(
                    email
                )
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    authenticated:
                        false,
                    message:
                        "Please provide a valid email address."
                });
            }

            if (
                !validateDescriptor(
                    descriptor
                )
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,
                    authenticated:
                        false,
                    message:
                        "Invalid face data."
                });
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        users.id,
                        users.email,
                        users.email_verified,
                        face_profiles.encrypted_template,
                        face_profiles.iv,
                        face_profiles.auth_tag
                    FROM users
                    INNER JOIN face_profiles
                        ON face_profiles.user_id = users.id
                    WHERE users.email = $1
                    LIMIT 1
                    `,
                    [email]
                );

            if (
                !result.rows.length
            ) {
                return res.status(
                    404
                ).json({
                    success:
                        false,
                    authenticated:
                        false,
                    registered:
                        false,
                    message:
                        "No face is registered for this account."
                });
            }

            const user =
                result.rows[0];

            if (
                !user.email_verified
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,
                    authenticated:
                        false,
                    message:
                        "Please verify your email before using face login."
                });
            }

            const storedTemplate =
                decryptFaceData({
                    encrypted:
                        user.encrypted_template,
                    iv:
                        user.iv,
                    authTag:
                        user.auth_tag
                });

            if (
                !validateDescriptor(
                    storedTemplate
                )
            ) {
                throw new Error(
                    "Stored face template is invalid."
                );
            }

            const distance =
                faceDistance(
                    descriptor,
                    storedTemplate
                );

            const matched =
                distance <=
                FACE_MATCH_THRESHOLD;

            console.log(
                `Face comparison for ${email}: ${distance.toFixed(4)}`
            );

            if (!matched) {
                return res.status(
                    401
                ).json({
                    success:
                        false,
                    authenticated:
                        false,
                    message:
                        "Face not recognized. Please try again."
                });
            }

            const token =
                await createSession(
                    user.id
                );

            return res.json({
                success:
                    true,
                authenticated:
                    true,
                email:
                    user.email,
                token,
                expiresInDays:
                    SESSION_DAYS,
                message:
                    "Face recognized successfully."
            });

        } catch (error) {
            console.error(
                "Face login error:",
                error
            );

            return res.status(
                500
            ).json({
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

app.get(
    "/api/auth/me",
    sessionLimiter,
    authenticateSession,
    async (
        req,
        res
    ) => {
        return res.json({
            success:
                true,
            authenticated:
                true,
            user: {
                id:
                    req.user.id,
                email:
                    req.user.email,
                emailVerified:
                    req.user.emailVerified
            }
        });
    }
);

app.post(
    "/api/auth/logout",
    sessionLimiter,
    authenticateSession,
    async (
        req,
        res
    ) => {
        try {
            await pool.query(
                `
                UPDATE auth_sessions
                SET revoked_at = NOW()
                WHERE id = $1
                `,
                [req.user.sessionId]
            );

            return res.json({
                success:
                    true,
                message:
                    "Logged out successfully."
            });

        } catch (error) {
            console.error(
                "Logout error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,
                message:
                    "Unable to log out."
            });
        }
    }
);

app.post(
    "/api/auth/logout-all",
    sessionLimiter,
    authenticateSession,
    async (
        req,
        res
    ) => {
        try {
            await pool.query(
                `
                UPDATE auth_sessions
                SET revoked_at = NOW()
                WHERE user_id = $1
                  AND revoked_at IS NULL
                `,
                [req.user.id]
            );

            return res.json({
                success:
                    true,
                message:
                    "All sessions have been logged out."
            });

        } catch (error) {
            console.error(
                "Logout all error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,
                message:
                    "Unable to log out all sessions."
            });
        }
    }
);

app.post(
    "/api/face/remove",
    sessionLimiter,
    authenticateSession,
    async (
        req,
        res
    ) => {
        try {
            await pool.query(
                `
                DELETE FROM face_profiles
                WHERE user_id = $1
                `,
                [req.user.id]
            );

            return res.json({
                success:
                    true,
                removed:
                    true,
                message:
                    "Face data removed successfully."
            });

        } catch (error) {
            console.error(
                "Face removal error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,
                message:
                    "Unable to remove face data."
            });
        }
    }
);

app.use(
    (
        req,
        res
    ) => {
        return res.status(
            404
        ).json({
            success:
                false,
            message:
                "Endpoint not found."
        });
    }
);

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

        return res.status(
            500
        ).json({
            success:
                false,
            message:
                "Internal server error."
        });
    }
);

async function startServer() {
    try {
        if (!pool) {
            throw new Error(
                "DATABASE_URL is missing."
            );
        }

        await pool.query(
            "SELECT 1"
        );

        await createDatabase();

        setInterval(
            cleanupDatabase,
            60 * 60 * 1000
        );

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
                        "Database: PostgreSQL"
                    );

                    console.log(
                        `Session duration: ${SESSION_DAYS} days`
                    );

                    console.log(
                        `Face threshold: ${FACE_MATCH_THRESHOLD}`
                    );

                    console.log(
                        `Email service: ${
                            brevo
                                ? "READY"
                                : "NOT CONFIGURED"
                        }`
                    );

                    console.log(
                        `Email sender: ${
                            EMAIL_FROM ||
                            "NOT CONFIGURED"
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

    } catch (error) {
        console.error(
            "Failed to start Legacy Lens AI:",
            error
        );

        process.exit(1);
    }
}

startServer();
