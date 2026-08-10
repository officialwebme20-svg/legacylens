import crypto from "crypto";

const otpStore = new Map();

const OTP_EXPIRATION_TIME = 10 * 60 * 1000;

export function generateOTP(email) {
    const normalizedEmail = email.trim().toLowerCase();

    const otp = crypto
        .randomInt(100000, 1000000)
        .toString();

    const expiresAt = Date.now() + OTP_EXPIRATION_TIME;

    otpStore.set(normalizedEmail, {
        otp,
        expiresAt,
        attempts: 0
    });

    return otp;
}

export function verifyOTP(email, otp) {
    const normalizedEmail = email.trim().toLowerCase();

    const storedData = otpStore.get(normalizedEmail);

    if (!storedData) {
        return {
            success: false,
            message: "No verification code was found. Please request a new code."
        };
    }

    if (Date.now() > storedData.expiresAt) {
        otpStore.delete(normalizedEmail);

        return {
            success: false,
            message: "This verification code has expired. Please request a new code."
        };
    }

    storedData.attempts++;

    if (storedData.attempts > 5) {
        otpStore.delete(normalizedEmail);

        return {
            success: false,
            message: "Too many incorrect attempts. Please request a new code."
        };
    }

    if (storedData.otp !== otp.toString().trim()) {
        return {
            success: false,
            message: "Incorrect verification code."
        };
    }

    otpStore.delete(normalizedEmail);

    return {
        success: true,
        message: "Email verified successfully."
    };
}

export function deleteOTP(email) {
    const normalizedEmail = email.trim().toLowerCase();

    otpStore.delete(normalizedEmail);
}
