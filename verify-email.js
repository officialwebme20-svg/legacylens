const API_URL = "https://legacylens-lon6.onrender.com";

const verificationForm = document.getElementById("verificationForm");
const verificationCode = document.getElementById("verificationCode");
const verifyButton = document.getElementById("verifyButton");
const resendCode = document.getElementById("resendCode");
const changeEmail = document.getElementById("changeEmail");
const authMessage = document.getElementById("authMessage");
const codeError = document.getElementById("codeError");
const emailDisplay = document.getElementById("emailDisplay");
const codeTimer = document.getElementById("codeTimer");

let email = "";
let countdown = 600;
let countdownInterval = null;
let resendCooldown = 60;
let resendInterval = null;


/* ================================
   GET STORED EMAIL
================================ */

function getStoredEmail() {

    const savedEmail =
        sessionStorage.getItem("verificationEmail") ||
        localStorage.getItem("verificationEmail");

    return savedEmail
        ? savedEmail.trim().toLowerCase()
        : "";
}


/* ================================
   MESSAGES
================================ */

function showMessage(message, type = "error") {

    if (!authMessage) return;

    authMessage.textContent = message;

    authMessage.className =
        `auth-message ${type}`;

    authMessage.hidden = false;
}


function hideMessage() {

    if (!authMessage) return;

    authMessage.hidden = true;

    authMessage.textContent = "";

    authMessage.className =
        "auth-message";
}


function showCodeError(message) {

    if (!codeError) return;

    codeError.textContent = message;

    if (verificationCode) {

        verificationCode.classList.toggle(
            "input-error",
            Boolean(message)
        );
    }
}


function clearCodeError() {

    showCodeError("");
}


/* ================================
   LOADING STATE
================================ */

function setLoading(loading) {

    if (!verifyButton) return;

    verifyButton.disabled = loading;

    verifyButton.classList.toggle(
        "loading",
        loading
    );
}


/* ================================
   TIMER
================================ */

function formatTime(seconds) {

    const minutes =
        Math.floor(seconds / 60);

    const remainingSeconds =
        seconds % 60;

    return `${String(minutes).padStart(2, "0")}:${String(
        remainingSeconds
    ).padStart(2, "0")}`;
}


function updateTimer() {

    if (!codeTimer) return;

    if (countdown <= 0) {

        codeTimer.innerHTML =
            "Code has <strong>expired</strong>";

        if (resendCode) {

            resendCode.disabled = false;

            resendCode.textContent =
                "Resend code";
        }

        return;
    }

    codeTimer.innerHTML =
        `Code expires in <strong>${formatTime(
            countdown
        )}</strong>`;
}


function startCountdown() {

    clearInterval(
        countdownInterval
    );

    countdown = 600;

    updateTimer();

    countdownInterval =
        setInterval(() => {

            countdown--;

            updateTimer();

            if (countdown <= 0) {

                clearInterval(
                    countdownInterval
                );
            }

        }, 1000);
}


/* ================================
   RESEND COOLDOWN
================================ */

function startResendCooldown() {

    clearInterval(
        resendInterval
    );

    resendCooldown = 60;

    if (!resendCode) return;

    resendCode.disabled = true;

    resendCode.textContent =
        `Resend code (${resendCooldown}s)`;


    resendInterval =
        setInterval(() => {

            resendCooldown--;

            if (resendCooldown <= 0) {

                clearInterval(
                    resendInterval
                );

                resendCode.disabled = false;

                resendCode.textContent =
                    "Resend code";

                return;
            }

            resendCode.textContent =
                `Resend code (${resendCooldown}s)`;

        }, 1000);
}


/* ================================
   STORAGE
================================ */

function saveVerificationEmail(value) {

    const normalizedEmail =
        String(value)
            .trim()
            .toLowerCase();

    sessionStorage.setItem(
        "verificationEmail",
        normalizedEmail
    );
}


function saveVerifiedStatus(value) {

    const normalizedEmail =
        String(value)
            .trim()
            .toLowerCase();


    sessionStorage.setItem(
        "emailVerified",
        "true"
    );

    sessionStorage.setItem(
        "verifiedEmail",
        normalizedEmail
    );

    localStorage.setItem(
        "emailVerified",
        "true"
    );

    localStorage.setItem(
        "verifiedEmail",
        normalizedEmail
    );


    sessionStorage.setItem(
        "customEmailVerified",
        "true"
    );

    localStorage.setItem(
        "customEmailVerified",
        "true"
    );
}


function clearVerificationEmail() {

    sessionStorage.removeItem(
        "verificationEmail"
    );

    localStorage.removeItem(
        "verificationEmail"
    );
}


/* ================================
   SEND OTP
================================ */

async function sendVerificationCode() {

    if (!email) {

        showMessage(
            "No email address was found. Please return to sign up.",
            "error"
        );

        return false;
    }


    hideMessage();

    clearCodeError();


    if (resendCode) {

        resendCode.disabled = true;
    }


    try {

        const response =
            await fetch(
                `${API_URL}/api/send-code`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        email
                    })
                }
            );


        let data;

        try {

            data =
                await response.json();

        } catch {

            throw new Error(
                "The server returned an invalid response."
            );
        }


        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.message ||
                "Unable to send verification code."
            );
        }


        showMessage(
            `A new verification code was sent to ${email}.`,
            "success"
        );


        startCountdown();

        startResendCooldown();


        return true;


    } catch (error) {

        console.error(
            "Send verification code error:",
            error
        );


        showMessage(
            error.message ||
            "Unable to send verification code. Please try again.",
            "error"
        );


        if (resendCode) {

            resendCode.disabled = false;

            resendCode.textContent =
                "Resend code";
        }


        return false;
    }
}


/* ================================
   VERIFY OTP
================================ */

async function verifyEmailCode() {

    hideMessage();

    clearCodeError();


    const code =
        verificationCode?.value.trim() || "";


    if (!code) {

        showCodeError(
            "Enter the 6-digit verification code."
        );

        verificationCode?.focus();

        return;
    }


    if (!/^\d{6}$/.test(code)) {

        showCodeError(
            "The verification code must contain 6 digits."
        );

        verificationCode?.focus();

        return;
    }


    if (!email) {

        showMessage(
            "Your email address could not be found. Please return to sign up.",
            "error"
        );

        return;
    }


    setLoading(true);


    try {

        const response =
            await fetch(
                `${API_URL}/api/verify-code`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        email,
                        code
                    })
                }
            );


        let data;

        try {

            data =
                await response.json();

        } catch {

            throw new Error(
                "The server returned an invalid response."
            );
        }


        /*
         * The backend must return:
         *
         * {
         *     success: true,
         *     verified: true
         * }
         */

        if (
            !response.ok ||
            !data.success ||
            data.verified !== true
        ) {

            throw new Error(
                data.message ||
                "Verification failed."
            );
        }


        /*
         * OTP SUCCESSFUL
         */

        clearInterval(
            countdownInterval
        );

        clearInterval(
            resendInterval
        );


        /*
         * Save verification state
         * BEFORE redirecting to vault.html.
         */

        saveVerifiedStatus(
            email
        );

        saveVerificationEmail(
            email
        );


        showMessage(
            "Your email has been verified successfully.",
            "success"
        );


        if (verificationCode) {

            verificationCode.disabled = true;
        }


        if (verifyButton) {

            verifyButton.disabled = true;
        }


        if (resendCode) {

            resendCode.disabled = true;
        }


        /*
         * Redirect to Vault page.
         */

        setTimeout(() => {

            window.location.href =
                "dashboard.html";

        }, 1000);


    } catch (error) {

        console.error(
            "Verification error:",
            error
        );


        showCodeError(
            error.message ||
            "Incorrect verification code."
        );


        verificationCode?.focus();


    } finally {

        setLoading(false);
    }
}


/* ================================
   OTP INPUT
================================ */

function setupCodeInput() {

    if (!verificationCode) return;


    verificationCode.addEventListener(
        "input",
        () => {

            verificationCode.value =
                verificationCode.value
                    .replace(/\D/g, "")
                    .slice(0, 6);


            clearCodeError();


            if (
                verificationCode.value.length === 6
            ) {

                verificationCode.blur();
            }

        }
    );


    verificationCode.addEventListener(
        "paste",
        event => {

            event.preventDefault();


            const pasted =
                event.clipboardData
                    .getData("text")
                    .replace(/\D/g, "")
                    .slice(0, 6);


            verificationCode.value =
                pasted;


            clearCodeError();
        }
    );
}


/* ================================
   FORM SUBMIT
================================ */

verificationForm?.addEventListener(
    "submit",
    async event => {

        event.preventDefault();

        await verifyEmailCode();
    }
);


/* ================================
   RESEND BUTTON
================================ */

resendCode?.addEventListener(
    "click",
    async () => {

        if (resendCode.disabled) {
            return;
        }

        await sendVerificationCode();
    }
);


/* ================================
   CHANGE EMAIL
================================ */

changeEmail?.addEventListener(
    "click",
    () => {

        clearInterval(
            countdownInterval
        );

        clearInterval(
            resendInterval
        );


        clearVerificationEmail();


        sessionStorage.removeItem(
            "emailVerified"
        );

        sessionStorage.removeItem(
            "verifiedEmail"
        );

        sessionStorage.removeItem(
            "customEmailVerified"
        );


        localStorage.removeItem(
            "emailVerified"
        );

        localStorage.removeItem(
            "verifiedEmail"
        );

        localStorage.removeItem(
            "customEmailVerified"
        );


        window.location.href =
            "signup.html";
    }
);


/* ================================
   INITIALIZE PAGE
================================ */

email =
    getStoredEmail();


if (!email) {

    showMessage(
        "No email address was found. Please return to the sign-up page.",
        "error"
    );


    if (emailDisplay) {

        emailDisplay.textContent =
            "your email address";
    }


    if (verificationForm) {

        verificationForm.style.display =
            "none";
    }


    if (resendCode) {

        resendCode.style.display =
            "none";
    }


} else {

    if (emailDisplay) {

        emailDisplay.textContent =
            email;
    }


    startCountdown();

    setupCodeInput();



    sendVerificationCode();
}