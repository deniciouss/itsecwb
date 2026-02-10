const nodemailer = require("nodemailer");

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

function createTransporter() {
  const host = requireEnv("MAIL_HOST");
  const port = parseInt(requireEnv("MAIL_PORT"), 10);
  const secure = (process.env.MAIL_SECURE || "true").toLowerCase() === "true";
  const user = requireEnv("MAIL_USER");
  const pass = requireEnv("MAIL_PASS");

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure, // true for 465, false for 587
    auth: { user, pass },
  });

  return transporter;
}

async function verifyTransporter() {
  const transporter = createTransporter();
  await transporter.verify(); // throws if auth/SMTP wrong
  return true;
}

async function sendVerificationEmail({ toEmail, fullName, verifyUrl }) {
  const transporter = createTransporter();

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:16px;border:1px solid #eee;border-radius:14px">
      <h2 style="margin:0 0 8px;color:#111827">Welcome, ${escapeHtml(fullName)} 🔥</h2>
      <p style="margin:0 0 14px;color:#374151">
        Please verify your email to activate your SamgyupGrill account.
      </p>
      <a href="${verifyUrl}" style="display:inline-block;background:#e11d48;color:white;text-decoration:none;padding:12px 16px;border-radius:10px;font-weight:700">
        Verify Email
      </a>
      <p style="margin:14px 0 0;color:#6b7280;font-size:12px">
        This link will expire in 30 minutes. If you didn’t sign up, ignore this email.
      </p>
    </div>
  `;

  await transporter.sendMail({
    from: `"SamgyupGrill" <${process.env.MAIL_USER}>`,
    to: toEmail,
    subject: "Verify your SamgyupGrill account",
    html,
  });
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

module.exports = {
  sendVerificationEmail,
  verifyTransporter,
};
