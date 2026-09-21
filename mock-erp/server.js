const path = require("path");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");

const PORT = Number(process.env.PORT || 4000);
const BASE_PATH = String(process.env.BASE_PATH || "/erp").replace(/\/$/, "");
const app = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "upgrade-insecure-requests": null,
        "script-src": ["'self'"],
        "style-src": ["'self'"],
      },
    },
  })
);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser(process.env.SESSION_SECRET));
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "mock-erp",
  });
});

app.get("/", (_req, res) => {
  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure ERP</title>
  <link rel="stylesheet" href="${BASE_PATH}/styles.css">
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div>
        <h1>Secure ERP Dashboard</h1>
        <p class="subtitle">Authenticated ERP session is active.</p>
      </div>
      <form class="logout" method="POST" action="/logout">
        <button type="submit">Log out</button>
      </form>
    </header>
    <section class="grid">
      <article class="card">
        <h2>Customers</h2>
        <p>Review customer records and account status.</p>
      </article>
      <article class="card">
        <h2>Sales</h2>
        <p>Track open orders and recent invoices.</p>
      </article>
      <article class="card">
        <h2>Inventory</h2>
        <p>Monitor stock levels and warehouse items.</p>
      </article>
      <article class="card">
        <h2>Accounts</h2>
        <p>View ledgers and outstanding balances.</p>
      </article>
    </section>
  </div>
</body>
</html>`);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`mock-erp listening on port ${PORT}`);
});
