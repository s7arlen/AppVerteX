const functions = require("firebase-functions");
const admin = require("firebase-admin");
const fetch = require("node-fetch");

admin.initializeApp();

// HTML Entity Encoding to prevent XSS / HTML Injection in emails
const escapeHTML = (str) => {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .trim();
};

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Contact Form Handler
 * Handles contact & upskill submissions securely with validation and concurrent notifications
 */
exports.contact = functions.https.onRequest(async (req, res) => {
  // CORS Configuration
  const allowedOrigins = [
    "https://s7arlen.github.io",
    "https://appvertex-e09c8.web.app",
    "https://appvertex-e09c8.firebaseapp.com",
    "https://appvertex.in",
    "http://localhost:5000",
    "http://127.0.0.1:5000"
  ];
  
  const origin = req.headers.origin;
  const isAllowed = origin && allowedOrigins.some(o => origin.startsWith(o));
  
  if (isAllowed) {
    res.set("Access-Control-Allow-Origin", origin);
  } else {
    res.set("Access-Control-Allow-Origin", "https://s7arlen.github.io");
  }
  
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }

  if (req.method !== "POST") {
    res.status(405).send("Method Not Allowed");
    return;
  }

  const { name, email, message, website, honeypot } = req.body || {};

  // Honeypot Bot Trap: Silently ignore bot spam submissions
  if (website || honeypot) {
    res.json({ success: true, message: "Message sent!" });
    return;
  }

  // Input Presence Validation
  if (!name || !email || !message) {
    res.status(400).json({ error: "All fields are required" });
    return;
  }

  const rawName = String(name).trim();
  const rawEmail = String(email).trim().toLowerCase();
  const rawMessage = String(message).trim();

  // Input Length & Format Validation
  if (!emailRegex.test(rawEmail) || rawEmail.length > 100) {
    res.status(400).json({ error: "Invalid email address format" });
    return;
  }

  if (rawName.length > 100 || rawMessage.length > 5000) {
    res.status(400).json({ error: "Input exceeds maximum allowed length" });
    return;
  }

  const safeName = escapeHTML(rawName);
  const safeEmail = escapeHTML(rawEmail);
  const safeMessage = escapeHTML(rawMessage);

  const runtimeConfig = functions.config() || {};
  const RESEND_API_KEY = (runtimeConfig.resend && runtimeConfig.resend.key) || process.env.RESEND_API_KEY;
  const CONTACT_RECEIVER = (runtimeConfig.contact && runtimeConfig.contact.receiver) || "info@appvertex.in";

  if (!RESEND_API_KEY) {
    console.error("Missing RESEND_API_KEY in functions config");
    res.status(500).json({ error: "Email service misconfigured" });
    return;
  }

  try {
    // Dispatch owner email notification and user auto-reply concurrently
    const ownerEmailPromise = fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: "AppVerteX <info@appvertex.in>",
        to: [CONTACT_RECEIVER],
        subject: `New message from ${safeName}`,
        html: `
          <h3>New Contact Form Submission</h3>
          <p><strong>Name:</strong> ${safeName}</p>
          <p><strong>Email:</strong> ${safeEmail}</p>
          <p><strong>Message:</strong><br>${safeMessage.replace(/\n/g, "<br>")}</p>
        `,
      }),
    });

    const autoReplyPromise = fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: "AppVerteX <info@appvertex.in>",
        to: [rawEmail],
        subject: `Thanks for reaching out, ${safeName}!`,
        html: `
          <p>Hi ${safeName},</p>
          <p>Thanks for contacting us! We've received your message and will get back to you shortly.</p>
          <br/>
          <p>— The AppVerteX Team</p>
        `,
      }),
    });

    const [ownerResult, autoReplyResult] = await Promise.allSettled([ownerEmailPromise, autoReplyPromise]);

    if (ownerResult.status === "rejected" || (ownerResult.value && !ownerResult.value.ok)) {
      const errDetail = ownerResult.status === "rejected" 
        ? ownerResult.reason.message 
        : await ownerResult.value.text();
      console.error("Owner email delivery failed:", errDetail);
      res.status(500).json({ error: "Failed to send notification email. Please try again later." });
      return;
    }

    if (autoReplyResult.status === "rejected" || (autoReplyResult.value && !autoReplyResult.value.ok)) {
      console.warn("Auto-reply delivery warning:", autoReplyResult.status === "rejected" ? autoReplyResult.reason : "Auto-reply failed");
    }

    res.json({ success: true, message: "Message sent!" });
  } catch (err) {
    console.error("EMAIL ERROR:", err.message);
    res.status(500).json({ error: "Failed to send email. Please try again later." });
  }
});
