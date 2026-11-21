/**
 * Authentication Module: Login, Registration & 2FA Flow
 */

document.addEventListener("DOMContentLoaded", () => {
  setupPasswordToggles();
  setupRegistrationLiveValidation();
  setupLoginForm();
  setupRegisterForm();
  setup2FAVerifyForm();
});

// Toggle password visibility
function setupPasswordToggles() {
  document.querySelectorAll(".input-toggle-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      const input = document.getElementById(targetId);
      if (!input) return;

      const isPassword = input.type === "password";
      input.type = isPassword ? "text" : "password";

      btn.innerHTML = isPassword
        ? `<svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18"/></svg>`
        : `<svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>`;
    });
  });
}

// Live password strength & requirement checklist for registration
function setupRegistrationLiveValidation() {
  const pwdInput = document.getElementById("reg-password");
  const confirmInput = document.getElementById("reg-confirm-password");
  const strengthBar = document.getElementById("strength-bar");
  const strengthText = document.getElementById("strength-text");

  if (!pwdInput) return;

  const reqElements = {
    length: document.getElementById("req-length"),
    upper: document.getElementById("req-upper"),
    lower: document.getElementById("req-lower"),
    number: document.getElementById("req-number"),
    special: document.getElementById("req-special"),
  };

  pwdInput.addEventListener("input", () => {
    const val = pwdInput.value;

    const tests = {
      length: val.length >= 8,
      upper: /[A-Z]/.test(val),
      lower: /[a-z]/.test(val),
      number: /[0-9]/.test(val),
      special: /[\W_]/.test(val),
    };

    // Update requirements checklist
    let passedCount = 0;
    for (const [key, passed] of Object.entries(tests)) {
      if (reqElements[key]) {
        if (passed) {
          reqElements[key].classList.add("valid");
          reqElements[key].classList.remove("invalid");
          passedCount++;
        } else {
          reqElements[key].classList.remove("valid");
          reqElements[key].classList.add("invalid");
        }
      }
    }

    // Update strength meter
    if (strengthBar && strengthText) {
      let score = 0;
      if (val.length >= 8) score += 20;
      if (val.length >= 12) score += 10;
      if (tests.upper) score += 20;
      if (tests.lower) score += 15;
      if (tests.number) score += 15;
      if (tests.special) score += 20;

      score = Math.min(score, 100);

      strengthBar.style.width = `${score}%`;
      if (score < 40) {
        strengthBar.style.backgroundColor = "var(--danger)";
        strengthText.textContent = "Weak Password";
        strengthText.style.color = "var(--danger)";
      } else if (score < 75) {
        strengthBar.style.backgroundColor = "var(--warning)";
        strengthText.textContent = "Moderate Password";
        strengthText.style.color = "var(--warning)";
      } else {
        strengthBar.style.backgroundColor = "var(--success)";
        strengthText.textContent = "Strong Password";
        strengthText.style.color = "var(--success)";
      }
    }

    validatePasswordMatch();
  });

  if (confirmInput) {
    confirmInput.addEventListener("input", validatePasswordMatch);
  }

  function validatePasswordMatch() {
    if (!confirmInput) return;
    const matchErr = document.getElementById("confirm-password-error");
    if (!confirmInput.value) {
      if (matchErr) matchErr.textContent = "";
      confirmInput.classList.remove("has-error");
      return;
    }

    if (pwdInput.value !== confirmInput.value) {
      if (matchErr) matchErr.textContent = "Passwords do not match.";
      confirmInput.classList.add("has-error");
    } else {
      if (matchErr) matchErr.textContent = "";
      confirmInput.classList.remove("has-error");
    }
  }
}

// Clear all field-level errors
function clearFieldErrors(form) {
  form.querySelectorAll(".field-error-msg").forEach((el) => (el.textContent = ""));
  form.querySelectorAll(".form-input").forEach((el) => el.classList.remove("has-error"));
}

// Show error on specific input field
function setFieldError(fieldId, errorId, message) {
  const input = document.getElementById(fieldId);
  const err = document.getElementById(errorId);
  if (input) input.classList.add("has-error");
  if (err) err.textContent = message;
}

// Set button loading state
function setButtonLoading(btn, isLoading) {
  const spinner = btn.querySelector(".btn-spinner");
  const text = btn.querySelector(".btn-text");
  btn.disabled = isLoading;
  if (spinner) spinner.style.display = isLoading ? "inline-block" : "none";
  if (text) text.style.opacity = isLoading ? "0.7" : "1";
}

// Registration Form Handler
function setupRegisterForm() {
  const form = document.getElementById("register-form");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearFieldErrors(form);

    const submitBtn = form.querySelector("button[type='submit']");
    const name = document.getElementById("reg-name").value.trim();
    const email = document.getElementById("reg-email").value.trim();
    const password = document.getElementById("reg-password").value;
    const confirmPassword = document.getElementById("reg-confirm-password").value;

    // Client-side quick checks
    let hasError = false;
    if (name.length < 2) {
      setFieldError("reg-name", "name-error", "Please enter your full name.");
      hasError = true;
    }
    if (!email || !email.includes("@")) {
      setFieldError("reg-email", "email-error", "Please provide a valid email address.");
      hasError = true;
    }
    if (password.length < 8) {
      setFieldError("reg-password", "password-error", "Password must be at least 8 characters.");
      hasError = true;
    }
    if (password !== confirmPassword) {
      setFieldError("reg-confirm-password", "confirm-password-error", "Passwords do not match.");
      hasError = true;
    }

    if (hasError) return;

    setButtonLoading(submitBtn, true);

    try {
      const response = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name,
          email: email,
          password: password,
          confirm_password: confirmPassword,
        }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        showToast("success", "Registration Successful!", "Redirecting you to sign in...");
        form.reset();
        setTimeout(() => {
          window.location.href = "/login?registered=true";
        }, 1500);
      } else {
        const errorMsg = data.message || "Failed to register account.";
        if (response.status === 409) {
          setFieldError("reg-email", "email-error", "This email address is already registered.");
          showToast("warning", "Account Exists", "Please sign in with this email or use a different one.");
        } else if (response.status === 429) {
          showToast("error", "Rate Limit Exceeded", errorMsg);
        } else {
          showToast("error", "Registration Error", errorMsg);
        }
      }
    } catch (err) {
      showToast("error", "Network Error", "Unable to connect to the server. Please check your connection.");
    } finally {
      setButtonLoading(submitBtn, false);
    }
  });
}

// Login Form Handler
function setupLoginForm() {
  const form = document.getElementById("login-form");
  if (!form) return;

  // Check URL query parameters for notifications
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get("registered") === "true") {
    showToast("success", "Account Created", "Your account is ready. Please log in.");
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearFieldErrors(form);

    const submitBtn = form.querySelector("button[type='submit']");
    const email = document.getElementById("login-email").value.trim();
    const password = document.getElementById("login-password").value;
    const rememberMe = document.getElementById("remember-me")?.checked || false;

    if (!email) {
      setFieldError("login-email", "login-email-error", "Please enter your email.");
      return;
    }
    if (!password) {
      setFieldError("login-password", "login-password-error", "Please enter your password.");
      return;
    }

    setButtonLoading(submitBtn, true);

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email,
          password: password,
          remember_me: rememberMe,
        }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // Check if Two-Factor Authentication is triggered
        if (data.data?.requires_2fa) {
          showToast("info", "Two-Factor Authentication", "Please enter your 6-digit authenticator code.");
          // Store pre_auth_token and redirect to 2FA verification screen
          sessionStorage.setItem("pre_auth_token", data.data.pre_auth_token);
          sessionStorage.setItem("auth_email", data.data.email);
          window.location.href = `/2fa-verify?token=${encodeURIComponent(data.data.pre_auth_token)}`;
          return;
        }

        showToast("success", "Access Granted", `Welcome back, ${data.data?.user_name || "User"}!`);
        setTimeout(() => {
          window.location.href = data.data?.redirect || "/dashboard";
        }, 800);
      } else {
        const errorMsg = data.message || "Invalid credentials.";
        if (response.status === 429) {
          showToast("error", "Security Lockout", errorMsg, 6000);
          setFieldError("login-email", "login-email-error", errorMsg);
        } else {
          setFieldError("login-password", "login-password-error", errorMsg);
          showToast("error", "Authentication Failed", errorMsg);
        }
      }
    } catch (err) {
      showToast("error", "Network Error", "Server unreachable. Please check if the application is running.");
    } finally {
      setButtonLoading(submitBtn, false);
    }
  });
}

// 2FA Verification Form Handler
function setup2FAVerifyForm() {
  const form = document.getElementById("verify-2fa-form");
  if (!form) return;

  const urlParams = new URLSearchParams(window.location.search);
  const tokenFromUrl = urlParams.get("token");
  const preAuthToken = tokenFromUrl || sessionStorage.getItem("pre_auth_token");
  const userEmail = sessionStorage.getItem("auth_email");

  const emailDisplay = document.getElementById("user-email-display");
  if (emailDisplay && userEmail) {
    emailDisplay.textContent = userEmail;
  }

  if (!preAuthToken) {
    showToast("warning", "Session Missing", "No 2FA challenge found. Please log in first.");
    setTimeout(() => {
      window.location.href = "/login";
    }, 1500);
    return;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearFieldErrors(form);

    const submitBtn = form.querySelector("button[type='submit']");
    const code = document.getElementById("2fa-code").value.trim();

    if (!code || code.length !== 6) {
      setFieldError("2fa-code", "code-error", "Please enter the complete 6-digit code.");
      return;
    }

    setButtonLoading(submitBtn, true);

    try {
      const response = await fetch("/api/auth/verify-2fa", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pre_auth_token: preAuthToken,
          code: code,
        }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        sessionStorage.removeItem("pre_auth_token");
        sessionStorage.removeItem("auth_email");
        showToast("success", "Verification Complete", "Access granted. Entering dashboard...");
        setTimeout(() => {
          window.location.href = data.data?.redirect || "/dashboard";
        }, 800);
      } else {
        const errorMsg = data.message || "Invalid 2FA code.";
        setFieldError("2fa-code", "code-error", errorMsg);
        showToast("error", "Verification Failed", errorMsg);
      }
    } catch (err) {
      showToast("error", "Network Error", "Unable to verify code. Please try again.");
    } finally {
      setButtonLoading(submitBtn, false);
    }
  });
}
