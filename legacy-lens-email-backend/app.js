import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "crypto";
import { BrevoClient } from "@getbrevo/brevo";

dotenv.config();
const app = express();

app.set("trust proxy", 1);

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

const brevo = BREVO_API_KEY
    ? new BrevoClient({
        apiKey: BREVO_API_KEY,
        timeoutInSeconds: 30,
        maxRetries: 2
    })
    : null;

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
        limit: "10mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "10mb"
    })
);

app.use((req, res, next) => {
    console.log(
        `${new Date().toISOString()} ${req.method} ${req.path}`
    );

    next();
});

app.get(
    "/",
    (req, res) => {
        res.json({
            success: true,
            service: "Legacy Lens AI",
            status: "online"
        });
    }
);

app.get(
    "/api/health",
    (req, res) => {
        res.json({
            success: true,
            service: "Legacy Lens AI",
            status: "online",
            emailService: brevo
                ? "configured"
                : "not_configured",
            emailSender: EMAIL_FROM
                ? "configured"
                : "not_configured",
            faceService: "online",
            otpService: "online"
        });
    }
);

const otpRequests = new Map();

const faceUsers = new Map();

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
        .update(String(code))
        .digest("hex");
}

function cleanupExpiredOTPs() {
    const now = Date.now();

    for (
        const [
            email,
            data
        ] of otpRequests.entries()
    ) {
        if (
            !data ||
            data.expiresAt <= now
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
            "EMAIL_FROM or BREVO_SENDER_EMAIL is not configured on the server."
        );
    }

    console.log(
        `Preparing Brevo email for: ${email}`
    );

    console.log(
        `Brevo sender: ${EMAIL_FROM}`
    );

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
            "Your Legacy Lens AI Vault Verification Code",

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
Security Vault Verification
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
If you did not request a vault PIN reset, you can safely ignore this email.
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

Security Vault Verification

Your Legacy Lens AI Vault verification code is:

${code}

This code expires in 10 minutes.

If you did not request a vault PIN reset,
you can safely ignore this email.

© ${new Date().getFullYear()} Legacy Lens AI`
    };

    try {
        const result =
            await brevo
                .transactionalEmails
                .sendTransacEmail(
                    emailData
                );

        console.log(
            "Brevo email request succeeded."
        );

        if (
            result &&
            result.messageId
        ) {
            console.log(
                `Brevo message ID: ${result.messageId}`
            );
        }

        return result;

    } catch (error) {
        console.error(
            "BREVO SEND ERROR:"
        );

        console.error(
            error
        );

        if (
            error?.response
        ) {
            console.error(
                "Brevo response:",
                error.response
            );
        }

        if (
            error?.body
        ) {
            console.error(
                "Brevo body:",
                error.body
            );
        }

        throw error;
    }
}

app.post(
    "/api/send-code",
    sendCodeLimiter,
    async (req, res) => {
        let email = "";

        try {
            email =
                normalizeEmail(
                    req.body?.email
                );

            if (!email) {
                return res.status(
                    400
                ).json({
                    success: false,
                    sent: false,
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
                    success: false,
                    sent: false,
                    message:
                        "Please provide a valid email address."
                });
            }

            if (
                !BREVO_API_KEY
            ) {
                console.error(
                    "BREVO_API_KEY is missing."
                );

                return res.status(
                    500
                ).json({
                    success: false,
                    sent: false,
                    message:
                        "Email service is not configured on the server. Add BREVO_API_KEY to Render environment variables."
                });
            }

            if (!brevo) {
                console.error(
                    "Brevo client was not initialized."
                );

                return res.status(
                    500
                ).json({
                    success: false,
                    sent: false,
                    message:
                        "Brevo email service is not initialized."
                });
            }

            if (!EMAIL_FROM) {
                console.error(
                    "EMAIL_FROM is missing."
                );

                return res.status(
                    500
                ).json({
                    success: false,
                    sent: false,
                    message:
                        "Email sender is not configured. Add EMAIL_FROM or BREVO_SENDER_EMAIL to Render environment variables."
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
                const remaining =
                    Math.ceil(
                        (
                            60000 -
                            (
                                Date.now() -
                                existing.lastSentAt
                            )
                        ) / 1000
                    );

                return res.status(
                    429
                ).json({
                    success: false,
                    sent: false,
                    message:
                        `Please wait ${remaining} seconds before requesting another code.`
                });
            }

            const code =
                generateOTP();

            const codeHash =
                hashOTP(code);

            const now =
                Date.now();

            const expiresAt =
                now +
                10 * 60 * 1000;

            otpRequests.set(
                email,
                {
                    codeHash,
                    expiresAt,
                    attempts: 0,
                    lastSentAt: now,
                    verified: false,
                    verifiedAt: null
                }
            );

            try {
                await sendVerificationEmail(
                    {
                        email,
                        code
                    }
                );

                console.log(
                    `Verification email accepted by Brevo for ${email}`
                );

            } catch (
                emailError
            ) {
                console.error(
                    "Unable to send verification email:"
                );

                console.error(
                    emailError
                );

                otpRequests.delete(
                    email
                );

                let message =
                    "We couldn't send your verification email.";

                if (
                    emailError?.message
                ) {
                    message =
                        emailError.message;
                }

                return res.status(
                    500
                ).json({
                    success: false,
                    sent: false,
                    message
                });
            }

            return res.json({
                success: true,
                sent: true,
                message:
                    "Verification code sent successfully."
            });

        } catch (error) {
            console.error(
                "Send code error:",
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
                sent: false,
                message:
                    error?.message ||
                    "Unable to send verification code."
            });
        }
    }
);

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
                !email ||
                !code
            ) {
                return res.status(
                    400
                ).json({
                    success: false,
                    verified: false,
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
                    success: false,
                    verified: false,
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
                    success: false,
                    verified: false,
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
                    verified: false,
                    message:
                        "This verification code is invalid or has expired. Request a new code."
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
                    verified: false,
                    message:
                        "This verification code has expired. Request a new code."
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
                    verified: false,
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

                otpRequests.set(
                    email,
                    stored
                );

                return res.status(
                    400
                ).json({
                    success: false,
                    verified: false,
                    message:
                        "Incorrect verification code."
                });
            }

            stored.verified =
                true;

            stored.verifiedAt =
                Date.now();

            otpRequests.set(
                email,
                stored
            );

            console.log(
                `Email verified successfully: ${email}`
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
                "Verify code error:",
                error
            );

            return res.status(
                500
            ).json({
                success: false,
                verified: false,
                message:
                    "Something went wrong while verifying the code."
            });
        }
    }
);

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
        !descriptors.length
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

app.post(
    "/api/face/register",
    faceRegisterLimiter,
    async (req, res) => {
        try {
            const email =
                normalizeEmail(
                    req.body?.email
                );

            const descriptors =
                req.body?.descriptors;

            if (!email) {
                return res.status(
                    400
                ).json({
                    success: false,
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
                    success: false,
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
                    return res.status(
                        400
                    ).json({
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
                return res.status(
                    400
                ).json({
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

app.post(
    "/api/face/status",
    async (req, res) => {
        try {
            const email =
                normalizeEmail(
                    req.body?.email
                );

            if (!email) {
                return res.status(
                    400
                ).json({
                    success: false,
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

            return res.status(
                500
            ).json({
                success: false,
                message:
                    "Unable to check face status."
            });
        }
    }
);

app.post(
    "/api/face/login",
    faceLoginLimiter,
    async (req, res) => {
        try {
            const email =
                normalizeEmail(
                    req.body?.email
                );

            const descriptor =
                req.body?.descriptor;

            if (!email) {
                return res.status(
                    400
                ).json({
                    success: false,
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
                return res.status(
                    400
                ).json({
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
                return res.status(
                    404
                ).json({
                    success: false,
                    authenticated:
                        false,
                    registered:
                        false,
                    message:
                        "No face is registered for this account."
                });
            }

            const distance =
                faceDistance(
                    descriptor,
                    user.faceTemplate
                );

            const MATCH_THRESHOLD =
                0.45;

            const matched =
                distance <=
                MATCH_THRESHOLD;

            if (!matched) {
                console.warn(
                    `Face mismatch for ${email}. Distance: ${distance}`
                );

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

            const sessionToken =
                crypto
                    .randomBytes(
                        32
                    )
                    .toString(
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
                    sessionToken,
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
                success: false,
                authenticated:
                    false,
                message:
                    "Unable to complete face login."
            });
        }
    }
);

app.post(
    "/api/face/remove",
    async (req, res) => {
        try {
            const email =
                normalizeEmail(
                    req.body?.email
                );

            if (!email) {
                return res.status(
                    400
                ).json({
                    success: false,
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
                    success: false,
                    message:
                        "Please provide a valid email address."
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

            return res.status(
                500
            ).json({
                success: false,
                message:
                    "Unable to remove face data."
            });
        }
    }
);

app.use(
    (req, res) => {
        return res.status(
            404
        ).json({
            success: false,
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
            success: false,
            message:
                "Internal server error."
        });
    }
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
                "Send code: /api/send-code"
            );

            console.log(
                "Verify code: /api/verify-code"
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
                "Face remove: /api/face/remove"
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
                `Email sender name: ${EMAIL_FROM_NAME}`
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
