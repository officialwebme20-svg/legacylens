import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { Resend } from "resend";
import crypto from "crypto";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;

const resend = new Resend(process.env.RESEND_API_KEY);

app.use(helmet());

app.use(cors({
    origin: process.env.FRONTEND_URL || true,
    methods: ["POST", "GET"],
    allowedHeaders: ["Content-Type"]
}));

app.use(express.json({
    limit: "10kb"
}));

const otpRequests = new Map();

const sendCodeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many verification requests. Please try again later."
    }
});

const verifyCodeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many verification attempts. Please try again later."
    }
});

function generateOTP() {
    return crypto
        .randomInt(100000, 1000000)
        .toString();
}

function hashOTP(code) {
    return crypto
        .createHash("sha256")
        .update(code)
        .digest("hex");
}

function cleanupExpiredCodes() {
    const now = Date.now();

    for (const [email, data] of otpRequests.entries()) {
        if (data.expiresAt <= now) {
            otpRequests.delete(email);
        }
    }
}

setInterval(
    cleanupExpiredCodes,
    60 * 1000
);

app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        service: "Legacy Lens AI Email Verification",
        status: "online"
    });
});

app.post(
    "/api/send-code",
    sendCodeLimiter,
    async (req, res) => {

        try {
            const email =
                String(req.body.email || "")
                    .trim()
                    .toLowerCase();

            if (!email) {
                return res.status(400).json({
                    success: false,
                    message: "Email address is required."
                });
            }

            const emailPattern =
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

            if (!emailPattern.test(email)) {
                return res.status(400).json({
                    success: false,
                    message: "Please provide a valid email address."
                });
            }

            const existing =
                otpRequests.get(email);

            if (
                existing &&
                existing.lastSentAt &&
                Date.now() - existing.lastSentAt < 60 * 1000
            ) {
                return res.status(429).json({
                    success: false,
                    message: "Please wait before requesting another code."
                });
            }

            const code = generateOTP();

            const hashedCode = hashOTP(code);

            const expiresAt =
                Date.now() + 10 * 60 * 1000;

            otpRequests.set(email, {
                codeHash: hashedCode,
                expiresAt,
                attempts: 0,
                lastSentAt: Date.now()
            });

            const { error } = await resend.emails.send({
                from: process.env.EMAIL_FROM,
                to: [email],
                subject: "Your Legacy Lens AI verification code",
                html: `
                    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:40px 20px;background:#ffffff;color:#111827;">
                        <div style="text-align:center;">
                            <h1 style="margin-bottom:10px;">Legacy Lens AI</h1>

                            <p style="font-size:16px;color:#4b5563;">
                                Verify your email address
                            </p>
                        </div>

                        <div style="margin:30px 0;padding:30px;text-align:center;background:#f8fafc;border-radius:16px;">
                            <p style="margin-bottom:15px;color:#475569;">
                                Your verification code is
                            </p>

                            <div style="font-size:36px;font-weight:700;letter-spacing:10px;color:#111827;">
                                ${code}
                            </div>

                            <p style="margin-top:20px;color:#64748b;font-size:14px;">
                                This code expires in 10 minutes.
                            </p>
                        </div>

                        <p style="font-size:14px;color:#64748b;text-align:center;">
                            If you did not request this code, you can safely ignore this email.
                        </p>

                        <p style="font-size:13px;color:#94a3b8;text-align:center;margin-top:30px;">
                            © ${new Date().getFullYear()} Legacy Lens AI
                        </p>
                    </div>
                `
            });

            if (error) {
                otpRequests.delete(email);

                console.error(
                    "Resend error:",
                    error
                );

                return res.status(500).json({
                    success: false,
                    message: "Unable to send verification email."
                });
            }

            return res.json({
                success: true,
                message: "Verification code sent."
            });

        } catch (error) {

            console.error(
                "Send code error:",
                error
            );

            return res.status(500).json({
                success: false,
                message: "Something went wrong."
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
                String(req.body.email || "")
                    .trim()
                    .toLowerCase();

            const code =
                String(req.body.code || "")
                    .trim();

            if (!email || !code) {
                return res.status(400).json({
                    success: false,
                    message: "Email and verification code are required."
                });
            }

            if (!/^\d{6}$/.test(code)) {
                return res.status(400).json({
                    success: false,
                    message: "Verification code must contain 6 digits."
                });
            }

            const stored =
                otpRequests.get(email);

            if (!stored) {
                return res.status(400).json({
                    success: false,
                    message: "This verification code is invalid or has expired."
                });
            }

            if (Date.now() > stored.expiresAt) {
                otpRequests.delete(email);

                return res.status(400).json({
                    success: false,
                    message: "This verification code has expired."
                });
            }

            if (stored.attempts >= 5) {
                otpRequests.delete(email);

                return res.status(429).json({
                    success: false,
                    message: "Too many incorrect attempts. Request a new code."
                });
            }

            const submittedHash =
                hashOTP(code);

            const isValid =
                crypto.timingSafeEqual(
                    Buffer.from(submittedHash),
                    Buffer.from(stored.codeHash)
                );

            if (!isValid) {

                stored.attempts += 1;

                return res.status(400).json({
                    success: false,
                    message: "Incorrect verification code."
                });
            }

            otpRequests.delete(email);

            return res.json({
                success: true,
                verified: true,
                message: "Email verified successfully."
            });

        } catch (error) {

            console.error(
                "Verify code error:",
                error
            );

            return res.status(500).json({
                success: false,
                message: "Something went wrong."
            });
        }
    }
);

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Endpoint not found."
    });
});

app.listen(
    PORT,
    () => {
        console.log(
            `Legacy Lens AI backend running on port ${PORT}`
        );
    }
);
