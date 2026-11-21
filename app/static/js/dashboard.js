/**
 * Dashboard & Security Center Interactivity Module
 */

function getSessionToken() {
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get("session_token");
  if (token) {
    sessionStorage.setItem("active_session_token", token);
    return token;
  }
  return sessionStorage.getItem("active_session_token");
}

function authFetch(url, options = {}) {
  const token = getSessionToken();
  if (token && !url.includes("session_token")) {
    const sep = url.includes("?") ? "&" : "?";
    url = `${url}${sep}session_token=${encodeURIComponent(token)}`;
  }
  return fetch(url, options);
}

document.addEventListener("DOMContentLoaded", () => {
  initDashboard();
  setupChangePasswordForm();
  setup2FAModals();
  setupSessionControls();
  setupLogout();
});

// Load all user security data
async function initDashboard() {
  await Promise.all([
    fetchUserProfile(),
    fetchActiveSessions(),
    fetchAuditLogs(),
  ]);
}

// Fetch user profile and update UI
async function fetchUserProfile() {
  try {
    const res = await authFetch("/api/dashboard/profile");
    if (!res.ok) {
      if (res.status === 401) {
        window.location.href = "/login";
        return;
      }
      throw new Error("Failed to load profile");
    }
    const { data } = await res.json();

    // Populate welcome header and user badges
    const nameEl = document.getElementById("user-full-name");
    const emailEl = document.getElementById("user-email");
    const avatarEl = document.getElementById("user-avatar-initials");
    const lastLoginEl = document.getElementById("stat-last-login");
    const memberSinceEl = document.getElementById("stat-member-since");

    if (nameEl) nameEl.textContent = data.name;
    if (emailEl) emailEl.textContent = data.email;
    if (avatarEl) avatarEl.textContent = getInitials(data.name);

    if (lastLoginEl) {
      lastLoginEl.textContent = data.last_login_at
        ? new Date(data.last_login_at).toLocaleString()
        : "First session";
    }
    if (memberSinceEl) {
      memberSinceEl.textContent = new Date(data.created_at).toLocaleDateString();
    }

    // 2FA Badge & Button states
    update2FAStatusUI(data.is_2fa_enabled);
  } catch (err) {
    console.error("Profile error:", err);
  }
}

function getInitials(name) {
  if (!name) return "U";
  const parts = name.trim().split(" ");
  if (parts.length === 1) return parts[0][0].toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function update2FAStatusUI(isEnabled) {
  const badge = document.getElementById("2fa-status-badge");
  const desc = document.getElementById("2fa-stat-desc");
  const enableBtn = document.getElementById("btn-enable-2fa");
  const disableBtn = document.getElementById("btn-disable-2fa");

  if (isEnabled) {
    if (badge) {
      badge.textContent = "Active / Enforced";
      badge.className = "stat-value";
      badge.style.color = "var(--success)";
    }
    if (desc) desc.textContent = "Account protected with TOTP Authenticator";
    if (enableBtn) enableBtn.style.display = "none";
    if (disableBtn) disableBtn.style.display = "inline-flex";
  } else {
    if (badge) {
      badge.textContent = "Disabled";
      badge.className = "stat-value";
      badge.style.color = "var(--warning)";
    }
    if (desc) desc.textContent = "Enhanced security recommended";
    if (enableBtn) enableBtn.style.display = "inline-flex";
    if (disableBtn) disableBtn.style.display = "none";
  }
}

// Fetch Active Sessions
async function fetchActiveSessions() {
  const container = document.getElementById("sessions-container");
  const countEl = document.getElementById("stat-active-sessions");
  if (!container) return;

  try {
    const res = await authFetch("/api/dashboard/sessions");
    if (!res.ok) return;
    const { data } = await res.json();
    const sessions = data.sessions || [];

    if (countEl) countEl.textContent = `${sessions.length} Active`;

    if (sessions.length === 0) {
      container.innerHTML = `<p style="color: var(--text-muted); font-size: 0.85rem;">No active sessions found.</p>`;
      return;
    }

    container.innerHTML = sessions
      .map((s) => {
        const isCurrent = s.is_current;
        const deviceName = parseDevice(s.user_agent);
        const createdDate = new Date(s.created_at).toLocaleString();

        return `
          <div class="session-item">
            <div class="session-info">
              <div class="session-device">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                <span>${deviceName}</span>
                ${isCurrent ? '<span class="session-badge-current">This Device</span>' : ""}
              </div>
              <div class="session-meta">
                IP: ${escapeHtml(s.ip_address)} • Started: ${createdDate}
              </div>
            </div>
          </div>
        `;
      })
      .join("");
  } catch (err) {
    console.error("Sessions error:", err);
  }
}

// Fetch Audit Trail
async function fetchAuditLogs() {
  const tbody = document.getElementById("audit-table-body");
  if (!tbody) return;

  try {
    const res = await authFetch("/api/dashboard/audit-logs");
    if (!res.ok) return;
    const { data } = await res.json();
    const logs = data.logs || [];

    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1rem;">No recent security events recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs
      .map((log) => {
        const badgeClass = getEventBadgeClass(log.event_type);
        const timeStr = new Date(log.created_at).toLocaleString();
        return `
          <tr>
            <td><span class="event-badge ${badgeClass}">${escapeHtml(log.event_type)}</span></td>
            <td>${timeStr}</td>
            <td><code>${escapeHtml(log.ip_address)}</code></td>
            <td style="color: var(--text-muted); font-size: 0.78rem;">${escapeHtml(log.details || "Success")}</td>
          </tr>
        `;
      })
      .join("");
  } catch (err) {
    console.error("Audit log error:", err);
  }
}

function getEventBadgeClass(type) {
  if (type.includes("SUCCESS") || type.includes("ENABLED")) return "success";
  if (type.includes("FAILED") || type.includes("RATE_LIMITED")) return "danger";
  return "info";
}

function parseDevice(ua) {
  if (!ua) return "Web Browser";
  if (ua.includes("Windows")) return "Windows Desktop";
  if (ua.includes("Macintosh")) return "macOS Device";
  if (ua.includes("iPhone")) return "Apple iPhone";
  if (ua.includes("Android")) return "Android Mobile";
  if (ua.includes("Linux")) return "Linux Workstation";
  return "Web Client";
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/[&<>"']/g, function (m) {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    }[m];
  });
}

// Change Password Handler
function setupChangePasswordForm() {
  const form = document.getElementById("change-password-form");
  if (!form) return;

  const newPwdInput = document.getElementById("new-password");
  const strengthBar = document.getElementById("pwd-change-strength");

  if (newPwdInput && strengthBar) {
    newPwdInput.addEventListener("input", () => {
      const v = newPwdInput.value;
      let score = 0;
      if (v.length >= 8) score += 25;
      if (/[A-Z]/.test(v)) score += 25;
      if (/[0-9]/.test(v)) score += 25;
      if (/[\W_]/.test(v)) score += 25;
      strengthBar.style.width = `${score}%`;
      strengthBar.style.backgroundColor =
        score < 50 ? "var(--danger)" : score < 75 ? "var(--warning)" : "var(--success)";
    });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const curr = document.getElementById("current-password").value;
    const next = document.getElementById("new-password").value;
    const confirm = document.getElementById("confirm-new-password").value;

    if (next !== confirm) {
      showToast("error", "Password Mismatch", "New passwords do not match.");
      return;
    }

    try {
      const res = await fetch("/api/dashboard/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          current_password: curr,
          new_password: next,
          confirm_new_password: confirm,
        }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        showToast("success", "Password Updated", data.message);
        form.reset();
        if (strengthBar) strengthBar.style.width = "0%";
        fetchActiveSessions();
        fetchAuditLogs();
      } else {
        showToast("error", "Update Failed", data.message || "Failed to update password.");
      }
    } catch (err) {
      showToast("error", "Error", "Could not complete password update.");
    }
  });
}

// Two-Factor Authentication Modals & Setup
function setup2FAModals() {
  const setupModal = document.getElementById("modal-2fa-setup");
  const disableModal = document.getElementById("modal-2fa-disable");
  const btnEnable = document.getElementById("btn-enable-2fa");
  const btnDisable = document.getElementById("btn-disable-2fa");
  const closeBtns = document.querySelectorAll(".modal-close-btn");

  closeBtns.forEach((b) => {
    b.addEventListener("click", () => {
      if (setupModal) setupModal.classList.remove("active");
      if (disableModal) disableModal.classList.remove("active");
    });
  });

  if (btnEnable) {
    btnEnable.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/dashboard/2fa/setup");
        const data = await res.json();
        if (res.ok && data.success) {
          document.getElementById("qr-code-img").src = data.data.qr_code_url;
          document.getElementById("secret-key-text").textContent = data.data.secret;
          document.getElementById("setup-2fa-code").value = "";
          setupModal.classList.add("active");
        } else {
          showToast("error", "Setup Failed", data.message);
        }
      } catch (err) {
        showToast("error", "Error", "Failed to initiate 2FA setup.");
      }
    });
  }

  // Confirm 2FA setup submission
  const formConfirm2FA = document.getElementById("form-confirm-2fa");
  if (formConfirm2FA) {
    formConfirm2FA.addEventListener("submit", async (e) => {
      e.preventDefault();
      const code = document.getElementById("setup-2fa-code").value.trim();
      try {
        const res = await fetch("/api/dashboard/2fa/enable", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code }),
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast("success", "2FA Activated!", data.message);
          setupModal.classList.remove("active");
          update2FAStatusUI(true);
          fetchAuditLogs();
        } else {
          showToast("error", "Invalid Code", data.message || "Could not verify code.");
        }
      } catch (err) {
        showToast("error", "Error", "Verification request failed.");
      }
    });
  }

  // Open Disable 2FA Modal
  if (btnDisable) {
    btnDisable.addEventListener("click", () => {
      document.getElementById("disable-2fa-password").value = "";
      disableModal.classList.add("active");
    });
  }

  // Confirm Disable 2FA submission
  const formDisable2FA = document.getElementById("form-disable-2fa");
  if (formDisable2FA) {
    formDisable2FA.addEventListener("submit", async (e) => {
      e.preventDefault();
      const pwd = document.getElementById("disable-2fa-password").value;
      try {
        const res = await fetch("/api/dashboard/2fa/disable", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: pwd }),
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast("info", "2FA Disabled", data.message);
          disableModal.classList.remove("active");
          update2FAStatusUI(false);
          fetchAuditLogs();
        } else {
          showToast("error", "Action Denied", data.message || "Failed to disable 2FA.");
        }
      } catch (err) {
        showToast("error", "Error", "Failed to submit request.");
      }
    });
  }
}

// Session Controls
function setupSessionControls() {
  const btnRevokeOthers = document.getElementById("btn-revoke-others");
  if (!btnRevokeOthers) return;

  btnRevokeOthers.addEventListener("click", async () => {
    if (!confirm("Are you sure you want to log out all other devices?")) return;

    try {
      const res = await fetch("/api/dashboard/sessions/revoke-others", {
        method: "POST",
      });
      const data = await res.json();
      if (res.ok && data.success) {
        showToast("success", "Sessions Terminated", data.message);
        fetchActiveSessions();
        fetchAuditLogs();
      } else {
        showToast("error", "Action Failed", data.message);
      }
    } catch (err) {
      showToast("error", "Error", "Could not revoke other sessions.");
    }
  });
}

// Logout
function setupLogout() {
  const logoutBtns = document.querySelectorAll(".btn-trigger-logout");
  logoutBtns.forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      try {
        const res = await fetch("/api/auth/logout", { method: "POST" });
        const data = await res.json();
        showToast("info", "Logged Out", "Session safely closed.");
        setTimeout(() => {
          window.location.href = data.data?.redirect || "/login";
        }, 600);
      } catch (err) {
        window.location.href = "/login";
      }
    });
  });
}
