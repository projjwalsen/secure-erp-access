function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function pageLayout({ title, heading, body, wide = false }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <main class="card${wide ? " card-wide" : ""}">
    <h1>${escapeHtml(heading)}</h1>
    ${body}
  </main>
</body>
</html>`;
}

function loginPage(accessId) {
  const safeId = escapeHtml(accessId);

  return pageLayout({
    title: "Secure ERP Access",
    heading: "Secure ERP Access",
    body: `
      <p>Enter your temporary access code</p>
      <form method="POST" action="/access/${safeId}">
        <label for="passkey">Access code</label>
        <input id="passkey" name="passkey" type="password" autocomplete="one-time-code" required>
        <button type="submit">Continue</button>
      </form>
    `,
  });
}

function expiredPage() {
  return pageLayout({
    title: "Access expired",
    heading: "Access expired",
    body: "<p>This temporary ERP access link is no longer valid.</p>",
  });
}

function invalidPasskeyPage(accessId, attempts, maxAttempts) {
  const safeId = escapeHtml(accessId);

  return pageLayout({
    title: "Invalid access code",
    heading: "Invalid access code",
    body: `
      <p>Attempt ${escapeHtml(attempts)} of ${escapeHtml(maxAttempts)}</p>
      <p class="muted"><a href="/access/${safeId}">Try again</a></p>
    `,
  });
}

function revokedPage() {
  return pageLayout({
    title: "Access revoked",
    heading: "Access revoked",
    body: "<p>Access revoked because of too many failed attempts.</p>",
  });
}

function accessDeniedPage() {
  return pageLayout({
    title: "Access denied",
    heading: "Access denied",
    body: "<p>An authenticated ERP session is required.</p>",
  });
}

function loggedOutPage() {
  return pageLayout({
    title: "Logged out",
    heading: "Logged out",
    body: "<p>You have been securely logged out.</p>",
  });
}

function errorPage(message = "Something went wrong. Please try again.") {
  return pageLayout({
    title: "Error",
    heading: "Request failed",
    body: `<p>${escapeHtml(message)}</p>`,
  });
}

function rateLimitedPage() {
  return pageLayout({
    title: "Too many requests",
    heading: "Too many requests",
    body: "<p>Please wait a moment and try again.</p>",
  });
}

module.exports = {
  escapeHtml,
  pageLayout,
  loginPage,
  expiredPage,
  invalidPasskeyPage,
  revokedPage,
  accessDeniedPage,
  loggedOutPage,
  errorPage,
  rateLimitedPage,
};
