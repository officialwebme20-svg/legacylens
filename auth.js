
import {
    initializeApp
} from "https://www.gstatic.com/firebasejs/12.17.1/firebase-app.js";

import {
    getAuth,
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    GoogleAuthProvider,
    signInWithPopup,
    sendPasswordResetEmail,
    updateProfile,
    setPersistence,
    browserLocalPersistence,
    browserSessionPersistence
} from "https://www.gstatic.com/firebasejs/12.17.1/firebase-auth.js";

import {
    getFirestore,
    doc,
    setDoc,
    serverTimestamp
} from "https://www.gstatic.com/firebasejs/12.17.1/firebase-firestore.js";

const firebaseConfig = {
    apiKey: "AIzaSyAhGIk7fLhxb_z_lz-zrWXLvchbufMxwuQ",
    authDomain: "web-me-a887b.firebaseapp.com",
    projectId: "web-me-a887b",
    storageBucket: "web-me-a887b.firebasestorage.app",
    messagingSenderId: "50961568115",
    appId: "1:50961568115:web:6ee832c711b4107cd87506",
    measurementId: "G-XJE1VJNVF4"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

const googleProvider = new GoogleAuthProvider();

googleProvider.setCustomParameters({
    prompt: "select_account"
});

const BACKEND_URL =
    "https://legacylens-lon6.onrender.com";

const signupForm =
    document.getElementById("signupForm");

const loginForm =
    document.getElementById("loginForm");

const signupButton =
    document.getElementById("signupButton");

const loginButton =
    document.getElementById("loginButton");

const authMessage =
    document.getElementById("authMessage");

const passwordInput =
    document.getElementById("password");

const confirmPasswordInput =
    document.getElementById("confirmPassword");

const passwordToggle =
    document.getElementById("passwordToggle");

const confirmPasswordToggle =
    document.getElementById("confirmPasswordToggle");

const googleSignup =
    document.getElementById("googleSignup");

const googleLogin =
    document.getElementById("googleLogin");

const rememberDevice =
    document.getElementById("rememberDevice");

const strengthFill =
    document.getElementById("strengthFill");

const strengthText =
    document.getElementById("strengthText");

const reqLength =
    document.getElementById("reqLength");

const reqUpper =
    document.getElementById("reqUpper");

const reqLower =
    document.getElementById("reqLower");

const reqNumber =
    document.getElementById("reqNumber");

const reqSpecial =
    document.getElementById("reqSpecial");

function showMessage(
    text,
    type = "error"
) {
    if (!authMessage) return;

    authMessage.textContent = text;

    authMessage.className =
        `auth-message ${type}`;

    authMessage.hidden = false;
}

function hideMessage() {
    if (!authMessage) return;

    authMessage.hidden = true;
    authMessage.textContent = "";
    authMessage.className = "auth-message";
}

function setLoading(
    button,
    loading
) {
    if (!button) return;

    button.disabled = loading;

    button.classList.toggle(
        "loading",
        loading
    );
}

function setFieldError(
    id,
    errorMessage
) {
    const error =
        document.getElementById(id);

    if (error) {
        error.textContent =
            errorMessage;
    }

    const group =
        error?.closest(".form-group");

    if (!group) return;

    const input =
        group.querySelector("input");

    const wrapper =
        input?.closest(".input-wrapper");

    if (wrapper) {
        wrapper.classList.toggle(
            "input-error",
            Boolean(errorMessage)
        );
    }
}

function clearFieldErrors() {
    document
        .querySelectorAll(".field-error")
        .forEach(element => {
            element.textContent = "";
        });

    document
        .querySelectorAll(".input-wrapper")
        .forEach(wrapper => {
            wrapper.classList.remove(
                "input-error"
            );

            wrapper.classList.remove(
                "input-success"
            );
        });
}

function togglePassword(
    input,
    button
) {
    if (!input || !button) return;

    const isPassword =
        input.type === "password";

    input.type =
        isPassword
            ? "text"
            : "password";

    button.classList.toggle(
        "active",
        isPassword
    );

    button.setAttribute(
        "aria-label",
        isPassword
            ? "Hide password"
            : "Show password"
    );

    button.setAttribute(
        "aria-pressed",
        String(isPassword)
    );
}

passwordToggle?.addEventListener(
    "click",
    () => {
        togglePassword(
            passwordInput,
            passwordToggle
        );
    }
);

confirmPasswordToggle?.addEventListener(
    "click",
    () => {
        togglePassword(
            confirmPasswordInput,
            confirmPasswordToggle
        );
    }
);

function getPasswordRequirements(
    password
) {
    return {
        length:
            password.length >= 12,

        upper:
            /[A-Z]/.test(password),

        lower:
            /[a-z]/.test(password),

        number:
            /[0-9]/.test(password),

        special:
            /[^A-Za-z0-9]/.test(password)
    };
}

function updateRequirement(
    element,
    valid
) {
    if (!element) return;

    element.classList.toggle(
        "valid",
        valid
    );
}

function updatePasswordStrength(
    password
) {
    if (
        !strengthFill ||
        !strengthText
    ) {
        return;
    }

    const requirements =
        getPasswordRequirements(
            password
        );

    updateRequirement(
        reqLength,
        requirements.length
    );

    updateRequirement(
        reqUpper,
        requirements.upper
    );

    updateRequirement(
        reqLower,
        requirements.lower
    );

    updateRequirement(
        reqNumber,
        requirements.number
    );

    updateRequirement(
        reqSpecial,
        requirements.special
    );

    if (!password) {
        strengthFill.style.width =
            "0%";

        strengthText.textContent =
            "Not set";

        return;
    }

    let score = 0;

    if (requirements.length) score++;
    if (requirements.upper) score++;
    if (requirements.lower) score++;
    if (requirements.number) score++;
    if (requirements.special) score++;

    strengthFill.style.width =
        `${score * 20}%`;

    if (score <= 2) {
        strengthText.textContent =
            "Weak";
    } else if (score === 3) {
        strengthText.textContent =
            "Fair";
    } else if (score === 4) {
        strengthText.textContent =
            "Strong";
    } else {
        strengthText.textContent =
            "Very strong";
    }
}

passwordInput?.addEventListener(
    "input",
    () => {
        updatePasswordStrength(
            passwordInput.value
        );

        if (
            passwordInput.value.length > 0
        ) {
            setFieldError(
                "passwordError",
                ""
            );
        }
    }
);

confirmPasswordInput?.addEventListener(
    "input",
    () => {
        if (
            confirmPasswordInput.value &&
            confirmPasswordInput.value !==
                passwordInput?.value
        ) {
            setFieldError(
                "confirmPasswordError",
                "Passwords do not match."
            );
        } else {
            setFieldError(
                "confirmPasswordError",
                ""
            );
        }
    }
);

function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email);
}

function validatePassword(password) {
    const requirements =
        getPasswordRequirements(
            password
        );

    return (
        requirements.length &&
        requirements.upper &&
        requirements.lower &&
        requirements.number &&
        requirements.special
    );
}

function validateSignupForm() {
    clearFieldErrors();

    const fullName =
        document
            .getElementById("fullName")
            ?.value
            .trim();

    const email =
        document
            .getElementById("email")
            ?.value
            .trim()
            .toLowerCase();

    const password =
        passwordInput?.value || "";

    const confirmPassword =
        confirmPasswordInput?.value || "";

    const terms =
        document
            .getElementById("terms")
            ?.checked;

    let valid = true;

    if (
        !fullName ||
        fullName.length < 2
    ) {
        setFieldError(
            "fullNameError",
            "Please enter your full name."
        );

        valid = false;
    }

    if (
        !email ||
        !validateEmail(email)
    ) {
        setFieldError(
            "emailError",
            "Enter a valid email address."
        );

        valid = false;
    }

    if (!validatePassword(password)) {
        setFieldError(
            "passwordError",
            "Your password does not meet all security requirements."
        );

        valid = false;
    }

    if (
        !confirmPassword ||
        password !== confirmPassword
    ) {
        setFieldError(
            "confirmPasswordError",
            "Passwords do not match."
        );

        valid = false;
    }

    if (!terms) {
        setFieldError(
            "termsError",
            "You must accept the Terms and Privacy Policy."
        );

        valid = false;
    }

    return {
        valid,
        fullName,
        email,
        password
    };
}

function getFirebaseErrorMessage(
    error
) {
    const code =
        error?.code || "";

    const messages = {
        "auth/email-already-in-use":
            "An account already exists with this email address.",

        "auth/invalid-email":
            "Please enter a valid email address.",

        "auth/weak-password":
            "This password is too weak. Please choose a stronger password.",

        "auth/user-not-found":
            "We couldn't find an account with those details.",

        "auth/wrong-password":
            "The email or password is incorrect.",

        "auth/invalid-credential":
            "The email or password is incorrect.",

        "auth/too-many-requests":
            "Too many attempts were made. Please wait and try again.",

        "auth/network-request-failed":
            "Network error. Check your internet connection and try again.",

        "auth/popup-closed-by-user":
            "The Google sign-in window was closed.",

        "auth/popup-blocked":
            "Your browser blocked the sign-in window. Please allow popups for this site.",

        "auth/cancelled-popup-request":
            "The sign-in request was cancelled.",

        "auth/requires-recent-login":
            "For security, please sign in again before continuing.",

        "auth/operation-not-allowed":
            "This sign-in method is not enabled in Firebase.",

        "auth/account-exists-with-different-credential":
            "An account already exists with this email using another sign-in method.",

        "permission-denied":
            "You do not have permission to access this data.",

        "failed-precondition":
            "The database is not configured correctly yet.",

        "unavailable":
            "Firebase is temporarily unavailable. Please try again."
    };

    return (
        messages[code] ||
        "Something went wrong. Please try again."
    );
}

async function createUserProfile(
    user,
    additionalData = {}
) {
    if (!user) return;

    const userRef =
        doc(
            db,
            "users",
            user.uid
        );

    const provider =
        user.providerData?.[0]
            ?.providerId ||
        "password";

    await setDoc(
        userRef,
        {
            uid:
                user.uid,

            displayName:
                user.displayName || "",

            email:
                user.email || "",

            photoURL:
                user.photoURL || "",

            emailVerified:
                user.emailVerified,

            provider,

            ...additionalData,

            lastLogin:
                serverTimestamp()
        },
        {
            merge: true
        }
    );
}

function saveVerificationEmail(
    email,
    flow
) {
    const normalizedEmail =
        String(email || "")
            .trim()
            .toLowerCase();

    sessionStorage.setItem(
        "verificationEmail",
        normalizedEmail
    );

    sessionStorage.setItem(
        "verificationFlow",
        flow
    );

    localStorage.setItem(
        "verificationEmail",
        normalizedEmail
    );

    localStorage.setItem(
        "verificationFlow",
        flow
    );
}

function saveAuthenticatedUser(
    user
) {
    if (!user?.email) return;

    const email =
        user.email
            .trim()
            .toLowerCase();

    sessionStorage.setItem(
        "authenticatedUserEmail",
        email
    );

    sessionStorage.setItem(
        "authenticatedUserUid",
        user.uid
    );

    localStorage.setItem(
        "authenticatedUserEmail",
        email
    );

    localStorage.setItem(
        "authenticatedUserUid",
        user.uid
    );
}

async function createAccount() {
    if (!signupForm) return;

    hideMessage();

    const result =
        validateSignupForm();

    if (!result.valid) return;

    setLoading(
        signupButton,
        true
    );

    try {
        await setPersistence(
            auth,
            browserLocalPersistence
        );

        const credential =
            await createUserWithEmailAndPassword(
                auth,
                result.email,
                result.password
            );

        await updateProfile(
            credential.user,
            {
                displayName:
                    result.fullName
            }
        );

        await createUserProfile(
            credential.user,
            {
                displayName:
                    result.fullName,

                accountType:
                    "standard",

                createdAt:
                    serverTimestamp()
            }
        );

        saveVerificationEmail(
            result.email,
            "signup"
        );

        saveAuthenticatedUser(
            credential.user
        );

        showMessage(
            "Account created successfully. Opening email verification...",
            "success"
        );

        signupForm.reset();

        updatePasswordStrength("");

        setTimeout(
            () => {
                window.location.href =
                    "verify-email.html";
            },
            500
        );

    } catch (error) {
        console.error(
            "Signup error:",
            error
        );

        showMessage(
            getFirebaseErrorMessage(
                error
            ),
            "error"
        );

    } finally {
        setLoading(
            signupButton,
            false
        );
    }
}

async function signInUser() {
    if (!loginForm) return;

    hideMessage();
    clearFieldErrors();

    const email =
        document
            .getElementById("email")
            ?.value
            .trim()
            .toLowerCase();

    const password =
        document
            .getElementById("password")
            ?.value || "";

    let valid = true;

    if (
        !email ||
        !validateEmail(email)
    ) {
        setFieldError(
            "emailError",
            "Enter a valid email address."
        );

        valid = false;
    }

    if (!password) {
        setFieldError(
            "passwordError",
            "Enter your password."
        );

        valid = false;
    }

    if (!valid) return;

    setLoading(
        loginButton,
        true
    );

    try {
        const persistence =
            rememberDevice?.checked
                ? browserLocalPersistence
                : browserSessionPersistence;

        await setPersistence(
            auth,
            persistence
        );

        const credential =
            await signInWithEmailAndPassword(
                auth,
                email,
                password
            );

        saveVerificationEmail(
            credential.user.email,
            "login"
        );

        saveAuthenticatedUser(
            credential.user
        );

        if (
            !credential.user.emailVerified
        ) {
            showMessage(
                "Please verify your email before continuing.",
                "success"
            );

            setTimeout(
                () => {
                    window.location.href =
                        "verify-email.html";
                },
                500
            );

            return;
        }

        showMessage(
            "Sign in successful. Opening email verification...",
            "success"
        );

        setTimeout(
            () => {
                window.location.href =
                    "verify-email.html";
            },
            500
        );

    } catch (error) {
        console.error(
            "Login error:",
            error
        );

        showMessage(
            getFirebaseErrorMessage(
                error
            ),
            "error"
        );

    } finally {
        setLoading(
            loginButton,
            false
        );
    }
}

async function googleSignIn() {
    hideMessage();

    const button =
        googleSignup ||
        googleLogin;

    setLoading(
        button,
        true
    );

    try {
        await setPersistence(
            auth,
            browserLocalPersistence
        );

        const result =
            await signInWithPopup(
                auth,
                googleProvider
            );

        if (!result.user) {
            throw new Error(
                "Google authentication failed."
            );
        }

        const email =
            result.user.email
                ?.trim()
                .toLowerCase();

        if (!email) {
            throw new Error(
                "Google account email could not be retrieved."
            );
        }

        await createUserProfile(
            result.user,
            {
                accountType:
                    "google",

                emailVerified:
                    result.user.emailVerified
            }
        );

        saveVerificationEmail(
            email,
            "google"
        );

        saveAuthenticatedUser(
            result.user
        );

        sessionStorage.setItem(
            "faceVerificationEmail",
            email
        );

        sessionStorage.setItem(
            "faceVerificationFlow",
            "google"
        );

        showMessage(
            "Google authentication successful. Opening email verification...",
            "success"
        );

        setTimeout(
            () => {
                window.location.href =
                    "verify-email.html";
            },
            500
        );

    } catch (error) {
        console.error(
            "Google sign-in error:",
            error
        );

        showMessage(
            getFirebaseErrorMessage(
                error
            ),
            "error"
        );

    } finally {
        setLoading(
            button,
            false
        );
    }
}

const forgotPasswordLink =
    document.querySelector(
        ".forgot-password"
    );

forgotPasswordLink?.addEventListener(
    "click",
    async event => {
        event.preventDefault();

        const email =
            document
                .getElementById("email")
                ?.value
                .trim()
                .toLowerCase();

        if (
            !email ||
            !validateEmail(email)
        ) {
            setFieldError(
                "emailError",
                "Enter your email address first."
            );

            document
                .getElementById("email")
                ?.focus();

            return;
        }

        hideMessage();

        try {
            await sendPasswordResetEmail(
                auth,
                email
            );

            showMessage(
                "If an account exists for this email, a password reset link has been sent.",
                "success"
            );

        } catch (error) {
            console.error(
                "Password reset error:",
                error
            );

            showMessage(
                "Unable to process the password reset request. Please try again.",
                "error"
            );
        }
    }
);

signupForm?.addEventListener(
    "submit",
    async event => {
        event.preventDefault();
        await createAccount();
    }
);

loginForm?.addEventListener(
    "submit",
    async event => {
        event.preventDefault();
        await signInUser();
    }
);

googleSignup?.addEventListener(
    "click",
    googleSignIn
);

googleLogin?.addEventListener(
    "click",
    googleSignIn
);

updatePasswordStrength(
    passwordInput?.value || ""
);

