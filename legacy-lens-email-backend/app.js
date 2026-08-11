import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} from "@simplewebauthn/server";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();

const PORT =
    process.env.PORT || 3000;


/* =========================================================
   ENVIRONMENT VARIABLES
========================================================= */

const BREVO_API_KEY =
    process.env.BREVO_API_KEY;

const EMAIL_FROM =
    process.env.EMAIL_FROM;

const EMAIL_FROM_NAME =
    process.env.EMAIL_FROM_NAME ||
    "Legacy Lens AI";


/*
 * IMPORTANT:
 *
 * RP_ID must match the domain where your frontend is running.
 *
 * Example:
 *
 * Frontend:
 * https://legacylens.com
 *
 * RP_ID:
 * legacylens.com
 *
 * Do NOT include https://
 */

const RP_NAME =
    "Legacy Lens AI";

const RP_ID =
    process.env.WEBAUTHN_RP_ID ||
    "legacylens-lon6.onrender.com";


/*
 * This must be the EXACT frontend origin.
 *
 * Example:
 *
 * https://legacylens.com
 *
 * NOT:
 *
 * https://legacylens.com/
 */

const ORIGIN =
    process.env.FRONTEND_URL ||
    "https://legacylens-lon6.onrender.com";


/* =========================================================
   EXPRESS CONFIGURATION
========================================================= */

app.use(
    helmet()
);


app.use(
    cors({
        origin: process.env.FRONTEND_URL || true,
        methods: [
            "GET",
            "POST"
        ],
        allowedHeaders: [
            "Content-Type"
        ]
    })
);


app.use(
    express.json({
        limit: "10kb"
    })
);


/* =========================================================
   OTP STORAGE
========================================================= */

const otpRequests =
    new Map();


/* =========================================================
   PASSKEY / BIOMETRIC STORAGE
========================================================= */

/*
 * Structure:
 *
 * email -> {
 *     currentChallenge: "...",
 *
 *     credentials: [
 *         {
 *             id,
 *             publicKey,
 *             counter,
 *             transports
 *         }
 *     ]
 * }
 */

const passkeyUsers =
    new Map();


/* =========================================================
   RATE LIMITING
========================================================= */

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


/* =========================================================
   BIOMETRIC RATE LIMITING
========================================================= */

const passkeyRegistrationLimiter =
    rateLimit({
        windowMs:
            15 * 60 * 1000,

        max: 10,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,

            message:
                "Too many biometric setup requests. Please try again later."
        }
    });


const passkeyAuthenticationLimiter =
    rateLimit({
        windowMs:
            15 * 60 * 1000,

        max: 20,

        standardHeaders: true,

        legacyHeaders: false,

        message: {
            success: false,

            message:
                "Too many biometric login attempts. Please try again later."
        }
    });


/* =========================================================
   GENERATE OTP
========================================================= */

function generateOTP() {

    return crypto
        .randomInt(
            100000,
            1000000
        )
        .toString();

}


/* =========================================================
   HASH OTP
========================================================= */

function hashOTP(code) {

    return crypto
        .createHash("sha256")
        .update(code)
        .digest("hex");

}


/* =========================================================
   CLEAN EXPIRED OTPs
========================================================= */

function cleanupExpiredCodes() {

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


/* =========================================================
   CLEAN EXPIRED PASSKEY CHALLENGES
========================================================= */

function cleanupPasskeyChallenges() {

    /*
     * Challenges are short-lived.
     *
     * We simply remove registration/
     * authentication challenges after
     * 5 minutes.
     */

    const now =
        Date.now();

    for (
        const [
            email,
            user
        ]
        of passkeyUsers.entries()
    ) {

        if (
            user.challengeCreatedAt &&
            now -
                user.challengeCreatedAt >
                5 * 60 * 1000
        ) {

            user.currentChallenge =
                null;

            user.challengeCreatedAt =
                null;

            passkeyUsers.set(
                email,
                user
            );

        }

    }

}


setInterval(
    cleanupPasskeyChallenges,
    60 * 1000
);


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
    "/api/health",
    (req, res) => {

        res.json({

            success: true,

            service:
                "Legacy Lens AI Email Verification + WebAuthn",

            status:
                "online"

        });

    }
);


/* =========================================================
   SEND EMAIL THROUGH BREVO
========================================================= */

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

                method:
                    "POST",

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


/* =========================================================
   SEND VERIFICATION CODE
========================================================= */

app.post(
    "/api/send-code",
    sendCodeLimiter,
    async (req, res) => {

        let email = "";

        try {

            email =
                String(
                    req.body.email || ""
                )
                    .trim()
                    .toLowerCase();


            if (!email) {

                return res.status(400)
                    .json({

                        success:
                            false,

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

                        success:
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
                existing.lastSentAt &&
                Date.now() -
                    existing.lastSentAt <
                    60 * 1000
            ) {

                return res.status(429)
                    .json({

                        success:
                            false,

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


            const expiresAt =
                Date.now() +
                10 * 60 * 1000;


            otpRequests.set(
                email,
                {

                    codeHash,

                    expiresAt,

                    attempts:
                        0,

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

<div
style="
text-align:center;
"
>

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

If you did not request this
verification code, you can
safely ignore this email.

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

                success:
                    true,

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

                    success:
                        false,

                    message:
                        error.message ||
                        "Unable to send verification email."

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
                String(
                    req.body.email || ""
                )
                    .trim()
                    .toLowerCase();


            const code =
                String(
                    req.body.code || ""
                )
                    .trim();


            if (
                !email ||
                !code
            ) {

                return res.status(400)
                    .json({

                        success:
                            false,

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

                        success:
                            false,

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

                        success:
                            false,

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

                        success:
                            false,

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

                        success:
                            false,

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

                stored.attempts += 1;


                return res.status(400)
                    .json({

                        success:
                            false,

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

                success:
                    true,

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


            return res.status(500)
                .json({

                    success:
                        false,

                    message:
                        "Something went wrong."

                });

        }

    }
);


/* =========================================================
   PASSKEY REGISTRATION OPTIONS
========================================================= */

app.post(
    "/api/passkey/register/options",
    passkeyRegistrationLimiter,
    async (req, res) => {

        try {

            const email =
                String(
                    req.body.email || ""
                )
                    .trim()
                    .toLowerCase();


            if (!email) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Email is required."

                    });

            }


            let existing =
                passkeyUsers.get(
                    email
                );


            if (!existing) {

                existing = {

                    credentials: [],

                    currentChallenge:
                        null,

                    challengeCreatedAt:
                        null

                };

            }


            const options =
                await generateRegistrationOptions({

                    rpName:
                        RP_NAME,

                    rpID:
                        RP_ID,

                    userName:
                        email,

                    userDisplayName:
                        email,

                    attestationType:
                        "none",

                    excludeCredentials:
                        (
                            existing.credentials ||
                            []
                        ).map(
                            credential => ({

                                id:
                                    credential.id,

                                transports:
                                    credential.transports

                            })
                        ),

                    authenticatorSelection: {

                        residentKey:
                            "preferred",

                        userVerification:
                            "required"

                    },

                    supportedAlgorithmIDs: [
                        -7,
                        -257
                    ]

                });


            existing.currentChallenge =
                options.challenge;


            existing.challengeCreatedAt =
                Date.now();


            passkeyUsers.set(
                email,
                existing
            );


            return res.json({

                success:
                    true,

                options

            });


        } catch (error) {

            console.error(
                "Passkey registration options error:",
                error
            );


            return res.status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to start biometric setup."

                });

        }

    }
);


/* =========================================================
   PASSKEY REGISTRATION VERIFICATION
========================================================= */

app.post(
    "/api/passkey/register/verify",
    passkeyRegistrationLimiter,
    async (req, res) => {

        try {

            const {
                email,
                response
            } = req.body;


            const normalizedEmail =
                String(
                    email || ""
                )
                    .trim()
                    .toLowerCase();


            if (!normalizedEmail) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Email is required."

                    });

            }


            if (!response) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Credential response is required."

                    });

            }


            const user =
                passkeyUsers.get(
                    normalizedEmail
                );


            if (
                !user ||
                !user.currentChallenge
            ) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Registration session expired. Please try again."

                    });

            }


            const verification =
                await verifyRegistrationResponse({

                    response,

                    expectedChallenge:
                        user.currentChallenge,

                    expectedOrigin:
                        ORIGIN,

                    expectedRPID:
                        RP_ID,

                    requireUserVerification:
                        true

                });


            if (
                !verification.verified
            ) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Biometric registration failed."

                    });

            }


            const registrationInfo =
                verification.registrationInfo;


            if (
                !registrationInfo ||
                !registrationInfo.credential
            ) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "No biometric credential was returned."

                    });

            }


            const credential = {

                id:
                    registrationInfo
                        .credential
                        .id,

                publicKey:
                    Buffer.from(
                        registrationInfo
                            .credential
                            .publicKey
                    )
                        .toString(
                            "base64url"
                        ),

                counter:
                    registrationInfo
                        .credential
                        .counter,

                transports:
                    response
                        .response
                        ?.transports ||
                    []

            };


            if (!user.credentials) {

                user.credentials =
                    [];

            }


            /*
             * Prevent duplicate credentials.
             */

            const alreadyExists =
                user.credentials.some(
                    existingCredential =>
                        existingCredential.id ===
                        credential.id
                );


            if (!alreadyExists) {

                user.credentials.push(
                    credential
                );

            }


            user.currentChallenge =
                null;


            user.challengeCreatedAt =
                null;


            passkeyUsers.set(
                normalizedEmail,
                user
            );


            console.log(
                `Passkey registered for ${normalizedEmail}`
            );


            return res.json({

                success:
                    true,

                message:
                    "Biometric login enabled successfully."

            });


        } catch (error) {

            console.error(
                "Passkey registration verification error:",
                error
            );


            return res.status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to complete biometric setup."

                });

        }

    }
);


/* =========================================================
   PASSKEY LOGIN OPTIONS
========================================================= */

app.post(
    "/api/passkey/login/options",
    passkeyAuthenticationLimiter,
    async (req, res) => {

        try {

            const email =
                String(
                    req.body.email || ""
                )
                    .trim()
                    .toLowerCase();


            if (!email) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Email is required."

                    });

            }


            const user =
                passkeyUsers.get(
                    email
                );


            if (
                !user ||
                !user.credentials ||
                user.credentials.length === 0
            ) {

                return res.status(404)
                    .json({

                        success:
                            false,

                        message:
                            "No biometric login is registered for this account."

                    });

            }


            const options =
                await generateAuthenticationOptions({

                    rpID:
                        RP_ID,

                    userVerification:
                        "required",

                    allowCredentials:
                        user.credentials.map(
                            credential => ({

                                id:
                                    credential.id,

                                transports:
                                    credential.transports

                            })
                        )

                });


            user.currentChallenge =
                options.challenge;


            user.challengeCreatedAt =
                Date.now();


            passkeyUsers.set(
                email,
                user
            );


            return res.json({

                success:
                    true,

                options

            });


        } catch (error) {

            console.error(
                "Passkey login options error:",
                error
            );


            return res.status(500)
                .json({

                    success:
                        false,

                    message:
                        "Unable to start biometric login."

                });

        }

    }
);


/* =========================================================
   PASSKEY LOGIN VERIFICATION
========================================================= */

app.post(
    "/api/passkey/login/verify",
    passkeyAuthenticationLimiter,
    async (req, res) => {

        try {

            const {
                email,
                response
            } = req.body;


            const normalizedEmail =
                String(
                    email || ""
                )
                    .trim()
                    .toLowerCase();


            if (!normalizedEmail) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Email is required."

                    });

            }


            if (!response) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Credential response is required."

                    });

            }


            const user =
                passkeyUsers.get(
                    normalizedEmail
                );


            if (
                !user ||
                !user.currentChallenge
            ) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Authentication session expired. Please try again."

                    });

            }


            const credentialID =
                response.id;


            const authenticator =
                user.credentials.find(
                    credential =>
                        credential.id ===
                        credentialID
                );


            if (!authenticator) {

                return res.status(400)
                    .json({

                        success:
                            false,

                        message:
                            "Biometric credential not recognized."

                    });

            }


            const verification =
                await verifyAuthenticationResponse({

                    response,

                    expectedChallenge:
                        user.currentChallenge,

                    expectedOrigin:
                        ORIGIN,

                    expectedRPID:
                        RP_ID,

                    credential: {

                        id:
                            authenticator.id,

                        publicKey:
                            Uint8Array.from(
                                Buffer.from(
                                    authenticator.publicKey,
                                    "base64url"
                                )
                            ),

                        counter:
                            authenticator.counter,

                        transports:
                            authenticator.transports

                    },

                    requireUserVerification:
                        true

                });


            if (
                !verification.verified
            ) {

                return res.status(401)
                    .json({

                        success:
                            false,

                        message:
                            "Biometric authentication failed."

                    });

            }


            authenticator.counter =
                verification.authenticationInfo
                    .newCounter;


            user.currentChallenge =
                null;


            user.challengeCreatedAt =
                null;


            passkeyUsers.set(
                normalizedEmail,
                user
            );


            console.log(
                `Biometric login successful for ${normalizedEmail}`
            );


            return res.json({

                success:
                    true,

                authenticated:
                    true,

                email:
                    normalizedEmail,

                message:
                    "Biometric authentication successful."

            });


        } catch (error) {

            console.error(
                "Passkey authentication verification error:",
                error
            );


            return res.status(401)
                .json({

                    success:
                        false,

                    message:
                        "Biometric authentication failed."

                });

        }

    }
);


/* =========================================================
   404 HANDLER
========================================================= */

app.use(
    (req, res) => {

        res.status(404)
            .json({

                success:
                    false,

                message:
                    "Endpoint not found."

            });

    }
);


/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "Unhandled server error:",
            error
        );


        if (res.headersSent) {

            return next(
                error
            );

        }


        res.status(500)
            .json({

                success:
                    false,

                message:
                    "Internal server error."

            });

    }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    () => {

        console.log(
            `Legacy Lens AI backend running on port ${PORT}`
        );

        console.log(
            `WebAuthn RP ID: ${RP_ID}`
        );

        console.log(
            `WebAuthn Origin: ${ORIGIN}`
        );

    }
);
