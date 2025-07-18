require("dotenv").config();

const express = require("express");
const app = express();
const cron = require("node-cron");
const { fork } = require("child_process");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const cors = require("cors");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const server = require("http").createServer(app);
const port = process.env.PORT || 3001;
const allowedOrigins = process.env.ALLOWED_ORIGINS.split(",");
const mongoUri = process.env.MONGODB_URI;

// MongoDB Client setup
const client = new MongoClient(mongoUri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// IMPORTANT: Webhook endpoint must be the very first route, before any middleware!
app.post(
  "/purchase",
  express.raw({
    type: "application/json",
    limit: "50mb", // Add size limit to prevent issues with large payloads
  }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];

    // Add more detailed logging
    console.log("Webhook received:");
    console.log("- Headers:", req.headers);
    console.log("- Body type:", typeof req.body);
    console.log("- Body length:", req.body ? req.body.length : "undefined");
    console.log("- Signature:", sig);

    let event;

    try {
      // Ensure we have the raw body and signature
      if (!req.body) {
        throw new Error("Request body is empty");
      }

      if (!sig) {
        throw new Error("Stripe signature header is missing");
      }

      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );

      console.log("Webhook signature verified successfully");
    } catch (err) {
      console.error("Webhook signature verification failed:");
      console.error("- Error message:", err.message);
      console.error(
        "- Webhook secret exists:",
        !!process.env.STRIPE_WEBHOOK_SECRET
      );
      console.error(
        "- Webhook secret length:",
        process.env.STRIPE_WEBHOOK_SECRET?.length
      );

      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      switch (event.type) {
        case "checkout.session.completed":
          console.log("Processing checkout.session.completed event");
          const sessionId = event.data.object.id;
          const session = await stripe.checkout.sessions.retrieve(sessionId, {
            expand: ["customer", "customer_details"],
          });
          await handleSuccessfulPayment(session);
          break;

        case "payment_intent.succeeded":
          console.log("Payment succeeded:", event.data.object.id);
          break;

        case "payment_intent.payment_failed":
          console.log("Processing payment failure");
          await handleFailedPayment(event.data.object);
          break;

        default:
          console.log(`Unhandled event type: ${event.type}`);
      }

      res.json({ received: true });
    } catch (processingError) {
      console.error("Error processing webhook event:", processingError);
      // Still return 200 to avoid Stripe retries for processing errors
      res.json({ received: true, error: processingError.message });
    }
  }
);

// Express middleware for all other routes (must come AFTER webhook)
app.use(express.static("public"));
app.use(express.json({ limit: "10mb" }));

// Simple security middleware - forces HTTPS upgrade for mixed content
app.use((req, res, next) => {
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains"
  );
  res.setHeader("Content-Security-Policy", "upgrade-insecure-requests");
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  })
);

// MongoDB Connection
async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("Successfully connected to MongoDB!");
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }
}
run().catch(console.dir);

// Stripe Checkout Endpoints
app.post("/create-checkout-session", async (req, res) => {
  try {
    const {
      student_quantity,
      teacher_quantity,
      school_name,
      admin_email,
      admin_name,
    } = req.body;

    if (student_quantity > 0 && teacher_quantity === 0) {
      return res.status(400).json({
        error:
          "At least 1 teacher license is required when purchasing student licenses",
      });
    }

    if (student_quantity === 0 && teacher_quantity === 0) {
      return res.status(400).json({
        error: "Please select at least one license",
      });
    }

    const line_items = [];

    if (student_quantity > 0) {
      line_items.push({
        price: process.env.STRIPE_STUDENT_PRICE_ID,
        quantity: student_quantity,
      });
    }

    if (teacher_quantity > 0) {
      line_items.push({
        price: process.env.STRIPE_TEACHER_PRICE_ID,
        quantity: teacher_quantity,
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: line_items,
      mode: "payment",
      submit_type: "auto",
      billing_address_collection: "auto",
      success_url: `https://license-distribution.trinity-capital.net?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: "https://tcpurchasingserver-production.up.railway.app/error",
      metadata: {
        student_quantity: student_quantity.toString(),
        teacher_quantity: teacher_quantity.toString(),
        purchase_date: new Date().toISOString(),
      },
      custom_fields: [
        {
          key: "school_name",
          label: {
            type: "custom",
            custom: "School Name",
          },
          type: "text",
          optional: false,
        },
        {
          key: "district_name",
          label: {
            type: "custom",
            custom: "District Name",
          },
          type: "text",
          optional: false,
        },
      ],
    });

    res.json({ url: session.url, session_id: session.id });
  } catch (error) {
    console.error("Error creating checkout session:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/request-quote", async (req, res) => {
  try {
    const { student_quantity, teacher_quantity } = req.body;

    console.log("✅ Quote request received successfully:");
    console.log(`   - Student Licenses: ${student_quantity}`);
    console.log(`   - Teacher Licenses: ${teacher_quantity}`);

    // For now, just acknowledge receipt of the request.
    res.status(200).json({ message: "Quote request received." });
  } catch (error) {
    console.error("Error processing quote request:", error);
    res.status(500).json({ error: "Failed to process quote request." });
  }
});

app.get("/checkout-session/:session_id", async (req, res) => {
  try {
    const { session_id } = req.params;
    const session = await stripe.checkout.sessions.retrieve(session_id);
    res.json({
      payment_status: session.payment_status,
      customer_details: session.customer_details,
      metadata: session.metadata,
      amount_total: session.amount_total,
    });
  } catch (error) {
    console.error("Error retrieving checkout session:", error);
    res.status(500).json({ error: error.message });
  }
});

// Success endpoint to redirect after payment
app.get("/success", (req, res) => {
  res.redirect("https://license-distribution.trinity-capital.net");
});

// Error endpoint for cancelled or unsuccessful payments
app.get("/error", (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Payment Incomplete</title>
        <script>
          alert('Payment incomplete, try again.');
        </script>
      </head>
      <body>
        <h2>Payment Incomplete</h2>
        <p>Your payment was not successful or was cancelled. Please try again.</p>
        <a href="/">Return to Home</a>
      </body>
    </html>
  `);
});

// Update your handleSuccessfulPayment function to extract data properly:
async function handleSuccessfulPayment(session) {
  try {
    console.log("Processing successful payment...");
    console.log("Session details:", JSON.stringify(session, null, 2));

    // Extract data from session
    const school_name =
      session.custom_fields?.find((field) => field.key === "school_name")?.text
        ?.value || "Unknown School";
    const district_name =
      session.custom_fields?.find((field) => field.key === "district_name")
        ?.text?.value || "Unknown District";
    const student_quantity = parseInt(session.metadata.student_quantity) || 0;
    const teacher_quantity = parseInt(session.metadata.teacher_quantity) || 0;
    const adminEmail = session.customer_details?.email;
    // Use the first part of the email as the admin name if not provided
    const adminName = adminEmail ? adminEmail.split("@")[0] : "Administrator";

    console.log("Extracted data:", {
      school_name,
      district_name,
      student_quantity,
      teacher_quantity,
      adminEmail,
      adminName,
    });

    if (!adminEmail) {
      throw new Error("No admin email found in session");
    }

    // Debug environment variables (mask password for security)
    console.log("🔧 Environment variables check:");
    console.log("  - EMAIL_USER:", process.env.EMAIL_USER);
    console.log("  - EMAIL_PASSWORD exists:", !!process.env.EMAIL_PASSWORD);
    console.log(
      "  - EMAIL_PASSWORD length:",
      process.env.EMAIL_PASSWORD?.length
    );
    console.log(
      "  - EMAIL_PASSWORD preview:",
      process.env.EMAIL_PASSWORD?.substring(0, 4) + "****"
    );

    // Create nodemailer transport with Google Workspace SMTP
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
      },
      logger: true,
      debug: true,
    });

    // Verify email configuration
    try {
      console.log("🔍 Verifying email transport configuration...");
      await transporter.verify();
      console.log(
        "✅ Email transport verified successfully for Google Workspace"
      );
      console.log("🚀 SMTP connection is ready to send emails");
    } catch (error) {
      console.error("❌ Email transport verification failed:");
      console.error("🔍 Verification Error Details:");
      console.error("  - Error message:", error.message);
      console.error("  - Error code:", error.code);
      console.error("  - Error errno:", error.errno);
      console.error("  - Error syscall:", error.syscall);
      console.error("  - SMTP response:", error.response);
      console.error("  - SMTP responseCode:", error.responseCode);
      console.error(
        "🛠️ Check your Google Workspace email settings and app password"
      );

      // Additional troubleshooting info
      console.error("🔧 Troubleshooting steps:");
      console.error("  1. Verify EMAIL_USER is a valid Google Workspace email");
      console.error(
        "  2. Verify EMAIL_PASSWORD is a valid app password (not regular password)"
      );
      console.error("  3. Check if 2-factor authentication is enabled");
      console.error("  4. Verify app passwords are enabled for your domain");

      throw error;
    }

    // Send confirmation email
    try {
      console.log("🔄 Attempting to send confirmation email...");
      console.log("📧 Email details:");
      console.log("  - From:", process.env.EMAIL_USER);
      console.log("  - To:", adminEmail);
      console.log(
        "  - Subject: Trinity Capital - License Purchase Confirmation"
      );

      const emailResult = await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: adminEmail,
        subject: `Trinity Capital - License Purchase Confirmation for ${school_name}`,
        html: `
          <h2>License Purchase Confirmation</h2>
          <p>Dear ${adminName},</p>
          <p>Thank you for your purchase! Your Trinity Capital licenses have been successfully processed.</p>
          
          <h3>Purchase Details:</h3>
          <ul>
            <li><strong>School:</strong> ${school_name}</li>
            <li><strong>District:</strong> ${district_name}</li>
            <li><strong>Teacher Licenses:</strong> ${teacher_quantity}</li>
            <li><strong>Student Licenses:</strong> ${student_quantity}</li>
            <li><strong>Purchase Date:</strong> ${new Date().toLocaleDateString()}</li>
          </ul>
          
          <p>Your access codes will be available in your admin dashboard within 24 hours.</p>
          <p>If you have any questions, please don't hesitate to contact our support team.</p>
          
          <p>Best regards,<br>The Trinity Capital Team</p>
        `,
      });

      console.log("✅ Email sent successfully!");
      console.log("📨 Email result:", {
        messageId: emailResult.messageId,
        response: emailResult.response,
        accepted: emailResult.accepted,
        rejected: emailResult.rejected,
      });
    } catch (emailError) {
      console.error("❌ FAILED to send confirmation email:");
      console.error("📋 Email Error Details:");
      console.error("  - Error message:", emailError.message);
      console.error("  - Error code:", emailError.code);
      console.error("  - Error stack:", emailError.stack);
      console.error("  - SMTP response:", emailError.response);
      console.error("  - SMTP responseCode:", emailError.responseCode);

      // Don't throw error here - continue with license creation even if email fails
      console.log("⚠️ Continuing with license creation despite email failure");
    }

    // Save license record to database
    const licenseRecord = {
      school_name,
      district_name,
      admin_email: adminEmail, // Use full email address
      admin_name: adminName, // Use name part only
      student_licenses: student_quantity,
      teacher_licenses: teacher_quantity,
      stripe_session_id: session.id,
      stripe_customer_id: session.customer,
      payment_status: "completed",
      amount_paid: session.amount_total,
      currency: session.currency,
      purchase_date: new Date(),
      license_expiry: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      is_active: true,
    };

    await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .insertOne(licenseRecord);
    console.log("License record saved to database");

    // Generate access codes
    await generateAccessCodes(
      school_name,
      adminName,
      teacher_quantity,
      student_quantity
    );
    console.log("Access codes generated successfully");
  } catch (error) {
    console.error("Error in handleSuccessfulPayment:", error);
    throw error;
  }
}

async function handleFailedPayment(paymentIntent) {
  try {
    await client
      .db("TrinityCapital")
      .collection("Failed Payments")
      .insertOne({
        stripe_payment_intent_id: paymentIntent.id,
        failure_reason:
          paymentIntent.last_payment_error?.message || "Unknown error",
        amount: paymentIntent.amount,
        currency: paymentIntent.currency,
        failed_at: new Date(),
      });
    console.log(`Payment failed: ${paymentIntent.id}`);
  } catch (error) {
    console.error("Error handling failed payment:", error);
  }
}

// Simplified generateAccessCodes function - only generates teacher codes
async function generateAccessCodes(
  schoolName,
  adminName,
  teacherCount,
  studentCount
) {
  try {
    const accessCodes = [];

    // Generate individual teacher codes for account creation
    for (let i = 0; i < teacherCount; i++) {
      accessCodes.push({
        code: crypto.randomBytes(4).toString("hex").toUpperCase(),
        type: "teacher",
        school: schoolName,
        admin: adminName,
        used: false,
        created_at: new Date(),
        expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      });
    }

    if (accessCodes.length > 0) {
      await client
        .db("TrinityCapital")
        .collection("Access Codes")
        .insertMany(accessCodes);
    }

    console.log(
      `Generated ${teacherCount} teacher access codes for ${schoolName}`
    );
    return accessCodes;
  } catch (error) {
    console.error("Error generating access codes:", error);
    throw error;
  }
}

// Simple validation for teacher codes only
app.post("/validate-teacher-code", async (req, res) => {
  try {
    const { access_code } = req.body;

    const teacherCode = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .findOne({ code: access_code, type: "teacher" });

    if (!teacherCode) {
      return res.status(404).json({ error: "Invalid teacher access code" });
    }

    if (teacherCode.used) {
      return res
        .status(400)
        .json({ error: "Teacher access code already used" });
    }

    if (new Date() > new Date(teacherCode.expires_at)) {
      return res.status(400).json({ error: "Access code expired" });
    }

    res.json({
      valid: true,
      school: teacherCode.school,
      type: "teacher",
      code_id: teacherCode._id,
    });
  } catch (error) {
    console.error("Error validating teacher code:", error);
    res.status(500).json({ error: error.message });
  }
});

// Simple teacher code consumption
app.post("/use-teacher-code", async (req, res) => {
  try {
    const { code_id, user_email, user_name } = req.body;

    const code = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .findOne({ _id: new ObjectId(code_id) });

    if (!code) {
      return res.status(404).json({ error: "Access code not found" });
    }

    // Mark teacher code as used
    await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .updateOne(
        { _id: code._id },
        {
          $set: {
            used: true,
            used_by: user_email,
            used_at: new Date(),
          },
        }
      );

    res.json({
      success: true,
      school: code.school,
    });
  } catch (error) {
    console.error("Error using teacher code:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get school license info (just the purchased amounts)
app.get("/school-licenses/:school_name", async (req, res) => {
  try {
    const { school_name } = req.params;
    const license = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .findOne({ school_name: school_name, is_active: true });

    if (!license) {
      return res.status(404).json({ error: "No active license found" });
    }

    res.json({
      school_name: license.school_name,
      district_name: license.district_name,
      teacher_licenses: license.teacher_licenses,
      student_licenses: license.student_licenses,
      purchase_date: license.purchase_date,
      license_expiry: license.license_expiry,
      admin_email: license.admin_email,
      admin_name: license.admin_name,
    });
  } catch (error) {
    console.error("Error fetching school licenses:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get teacher codes for a school (for admin dashboard)
app.get("/teacher-codes/:school_name", async (req, res) => {
  try {
    const { school_name } = req.params;
    const codes = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .find({
        school: school_name,
        type: "teacher",
      })
      .toArray();

    res.json(codes);
  } catch (error) {
    console.error("Error fetching teacher codes:", error);
    res.status(500).json({ error: error.message });
  }
});

async function sendLicenseConfirmationEmail(
  adminEmail,
  adminName,
  schoolName,
  studentCount,
  teacherCount
) {
  try {
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: adminEmail,
      subject: `Trinity Capital - License Purchase Confirmation for ${schoolName}`,
      html: `
        <h2>License Purchase Confirmation</h2>
        <p>Dear ${adminName},</p>
        <p>Thank you for your purchase! Your Trinity Capital licenses have been successfully processed.</p>
        
        <h3>Purchase Details:</h3>
        <ul>
          <li><strong>School:</strong> ${schoolName}</li>
          <li><strong>Teacher Licenses:</strong> ${teacherCount}</li>
          <li><strong>Student Licenses:</strong> ${studentCount}</li>
          <li><strong>Purchase Date:</strong> ${new Date().toLocaleDateString()}</li>
        </ul>
        
        <p>Your access codes will be available in your admin dashboard within 24 hours.</p>
        <p>If you have any questions, please don't hesitate to contact our support team.</p>
        
        <p>Best regards,<br>The Trinity Capital Team</p>
      `,
    });

    console.log(`Confirmation email sent to ${adminEmail}`);
  } catch (error) {
    console.error("Error sending confirmation email:", error);
  }
}

// License Management Endpoints
app.get("/school-licenses/:admin_email", async (req, res) => {
  try {
    const { admin_email } = req.params;
    const licenses = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .find({ admin_email: admin_email, is_active: true })
      .toArray();
    res.json(licenses);
  } catch (error) {
    console.error("Error fetching school licenses:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/access-codes/:school_name", async (req, res) => {
  try {
    const { school_name } = req.params;
    const codes = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .find({ school: school_name })
      .toArray();
    res.json(codes);
  } catch (error) {
    console.error("Error fetching access codes:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/validate-license-capacity", async (req, res) => {
  try {
    const { access_code } = req.body;
    const code = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .findOne({ code: access_code });

    if (!code) {
      return res.status(404).json({ error: "Invalid access code" });
    }

    if (code.used) {
      return res.status(400).json({ error: "Access code already used" });
    }

    if (new Date() > new Date(code.expires_at)) {
      return res.status(400).json({ error: "Access code expired" });
    }

    const license = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .findOne({ school_name: code.school, is_active: true });

    if (!license) {
      return res
        .status(404)
        .json({ error: "No active license found for this school" });
    }

    const currentUsers = await client
      .db("TrinityCapital")
      .collection("User Profiles")
      .countDocuments({ school: code.school });

    const totalLicenses = license.student_licenses + license.teacher_licenses;

    if (currentUsers >= totalLicenses) {
      return res.status(400).json({ error: "License capacity exceeded" });
    }

    res.json({
      valid: true,
      school: code.school,
      type: code.type,
      remaining_capacity: totalLicenses - currentUsers,
    });
  } catch (error) {
    console.error("Error validating license capacity:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get admin's school information and unused teacher codes
app.get("/admin-portal/:admin_email", async (req, res) => {
  try {
    const { admin_email } = req.params;

    // Get the admin's school license
    const license = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .findOne({ admin_email: admin_email, is_active: true });

    if (!license) {
      return res
        .status(404)
        .json({ error: "No active license found for this admin" });
    }

    // Get unused teacher codes for this school
    const unusedCodes = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .find({
        school: license.school_name,
        type: "teacher",
        used: false,
      })
      .toArray();

    // Get used teacher codes for tracking
    const usedCodes = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .find({
        school: license.school_name,
        type: "teacher",
        used: true,
      })
      .toArray();

    res.json({
      school_name: license.school_name,
      district_name: license.district_name,
      admin_name: license.admin_name,
      teacher_licenses: license.teacher_licenses,
      student_licenses: license.student_licenses,
      unused_codes: unusedCodes,
      used_codes: usedCodes,
      codes_remaining: unusedCodes.length,
      purchase_date: license.purchase_date,
      license_expiry: license.license_expiry,
    });
  } catch (error) {
    console.error("Error fetching admin portal data:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get the next available teacher code and email template
app.get("/get-next-teacher-code/:admin_email", async (req, res) => {
  try {
    const { admin_email } = req.params;

    // Get the admin's school license
    const license = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .findOne({ admin_email: admin_email, is_active: true });

    if (!license) {
      return res
        .status(404)
        .json({ error: "No active license found for this admin" });
    }

    // Get the next unused teacher code
    const nextCode = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .findOne({
        school: license.school_name,
        type: "teacher",
        used: false,
      });

    if (!nextCode) {
      return res.status(404).json({
        error: "No unused teacher codes available",
        codes_exhausted: true,
      });
    }

    // Create the email template
    const emailSubject = `Your Trinity Capital Teacher Access Code - ${license.school_name}`;
    const emailBody = `Dear Teacher,

Welcome to Trinity Capital! Your school administrator has purchased Trinity Capital licenses for ${license.school_name}.

Your Teacher Access Code: ${nextCode.code}

REGISTRATION INSTRUCTIONS:
1. Go to the Trinity Capital teacher registration page: https://trinitycapitalsignup.netlify.app
2. Enter your basic information and your teacher access code: ${nextCode.code}
3. Select today's date as your registration date.
4. Click "Next Step" to complete your registration.

LOGIN INSTRUCTIONS:
- To log into the teacher dashboard, use the same username and PIN you created during registration.
- The teacher dashboard login page is: https://teacher-dashboard.trinity-capital.net

AFTER LOGIN:
- The teacher dashboard will guide you through setting up your classes and generating class codes for your students.

IMPORTANT NOTES:
• This code is unique to you and can only be used once
• Your students will receive their own class codes from you after you register
• This code expires on: ${new Date(nextCode.expires_at).toLocaleDateString()}
• Keep this code secure and do not share it with students

If you have any questions or need technical support, please contact:
- Your school administrator: ${license.admin_name} (${license.admin_email})
- Trinity Capital Support Team

Thank you for being part of the Trinity Capital educational community!

Best regards,
The Trinity Capital Team

---
This email was sent on behalf of ${license.school_name}
Purchase Date: ${new Date(license.purchase_date).toLocaleDateString()}
School District: ${license.district_name}`;

    res.json({
      code: nextCode.code,
      code_id: nextCode._id,
      subject: emailSubject,
      body: emailBody,
      school_name: license.school_name,
      admin_name: license.admin_name,
      expires_at: nextCode.expires_at,
    });
  } catch (error) {
    console.error("Error getting next teacher code:", error);
    res.status(500).json({ error: error.message });
  }
});

// Send teacher access code email
app.post("/send-teacher-code-email", async (req, res) => {
  try {
    const { admin_email, recipient_email, subject, body, code_id } = req.body;

    // Validate admin
    const license = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .findOne({ admin_email: admin_email, is_active: true });

    if (!license) {
      return res
        .status(404)
        .json({ error: "Invalid admin or no active license" });
    }

    // Validate the code exists and is unused
    const code = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .findOne({
        _id: new ObjectId(code_id),
        school: license.school_name,
        type: "teacher",
        used: false,
      });

    if (!code) {
      return res
        .status(404)
        .json({ error: "Invalid or already used teacher code" });
    }

    // Create nodemailer transport for Google Workspace
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

    // Send the email
    const emailResult = await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: recipient_email,
      subject: subject,
      text: body,
      html: body.replace(/\n/g, "<br>"), // Convert line breaks to HTML
      replyTo: admin_email, // Allow teacher to reply directly to admin
    });

    console.log("Teacher code email sent successfully:", emailResult);

    // Mark the code as sent and used (so it won't be selected again)
    await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .updateOne(
        { _id: code._id },
        {
          $set: {
            email_sent: true,
            sent_to: recipient_email,
            sent_at: new Date(),
            sent_by_admin: admin_email,
            used: true, // Mark as used
            used_by: recipient_email,
            used_at: new Date(),
          },
        }
      );

    // Log the email send event
    await client.db("TrinityCapital").collection("Email Logs").insertOne({
      type: "teacher_code_email",
      admin_email: admin_email,
      recipient_email: recipient_email,
      school_name: license.school_name,
      teacher_code: code.code,
      code_id: code._id,
      subject: subject,
      sent_at: new Date(),
      email_id: emailResult.messageId,
    });

    res.json({
      success: true,
      message: "Teacher access code email sent successfully",
      email_id: emailResult.messageId,
      sent_to: recipient_email,
    });
  } catch (error) {
    console.error("Error sending teacher code email:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get admin dashboard statistics
app.get("/admin-stats/:admin_email", async (req, res) => {
  try {
    const { admin_email } = req.params;

    const license = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .findOne({ admin_email: admin_email, is_active: true });

    if (!license) {
      return res.status(404).json({ error: "No active license found" });
    }

    // Get code statistics
    const totalCodes = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .countDocuments({
        school: license.school_name,
        type: "teacher",
      });

    const sentCodes = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .countDocuments({
        school: license.school_name,
        type: "teacher",
        email_sent: true,
      });

    const usedCodes = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .countDocuments({
        school: license.school_name,
        type: "teacher",
        used: true,
      });

    const remainingCodes = totalCodes - sentCodes;

    // Get recent email activity
    const recentEmails = await client
      .db("TrinityCapital")
      .collection("Email Logs")
      .find({
        admin_email: admin_email,
        type: "teacher_code_email",
      })
      .sort({ sent_at: -1 })
      .limit(10)
      .toArray();

    res.json({
      school_name: license.school_name,
      district_name: license.district_name,
      total_teacher_licenses: license.teacher_licenses,
      total_student_licenses: license.student_licenses,
      codes_generated: totalCodes,
      codes_sent: sentCodes,
      codes_used: usedCodes,
      codes_remaining: remainingCodes,
      purchase_date: license.purchase_date,
      license_expiry: license.license_expiry,
      recent_emails: recentEmails,
    });
  } catch (error) {
    console.error("Error fetching admin stats:", error);
    res.status(500).json({ error: error.message });
  }
});

// Validate admin access (for frontend authentication)
app.post("/validate-admin", async (req, res) => {
  try {
    const { admin_email } = req.body;

    const license = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .findOne({ admin_email: admin_email, is_active: true });

    if (!license) {
      return res.status(404).json({
        error: "No active license found for this email address",
        valid: false,
      });
    }

    res.json({
      valid: true,
      school_name: license.school_name,
      district_name: license.district_name,
      admin_name: license.admin_name,
      teacher_licenses: license.teacher_licenses,
      student_licenses: license.student_licenses,
    });
  } catch (error) {
    console.error("Error validating admin:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/send-parcel-email", async (req, res) => {
  const {
    schoolName,
    schoolDistrict,
    poNumber,
    studentQty,
    teacherQty,
    teacherLicenseTotal,
    studentLicenseTotal,
    totalPurchasePrice,
    adminEmail,
  } = req.body;

  if (
    !schoolName ||
    !schoolDistrict ||
    !poNumber ||
    !studentQty ||
    !teacherQty ||
    !teacherLicenseTotal ||
    !studentLicenseTotal ||
    !totalPurchasePrice ||
    !adminEmail
  ) {
    return res.status(400).json({ error: "Missing required fields." });
  }

  console.log("Parcel received:");
  console.log("School:", schoolName);
  console.log("School District:", schoolDistrict);
  console.log("PO Number:", poNumber);
  console.log("Student Licenses:", studentQty);
  console.log("Teacher Licenses:", teacherQty);
  console.log("Teacher License Total:", teacherLicenseTotal);
  console.log("Student License Total:", studentLicenseTotal);
  console.log("Total Purchase Price:", totalPurchasePrice);
  console.log("Admin Email:", adminEmail);

  const adminName = adminEmail.split("@")[0];
  const purchaseDate = new Date();
  const licenseExpiry = new Date(purchaseDate);
  licenseExpiry.setFullYear(licenseExpiry.getFullYear() + 1);

  // Send confirmation email with Google Workspace SMTP
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD,
    },
    tls: {
      rejectUnauthorized: false,
    },
  });

  const mailOptions = {
    from: `"Trinity Capital Support" <${process.env.EMAIL_USER}>`,
    to: adminEmail,
    subject: `License Distribution Instructions for ${schoolName}`,
    text: `
Hello,

Thank you for your purchase of Trinity Capital licenses.

Here are the details of your order:

School: ${schoolName}
School District: ${schoolDistrict}
PO Number: ${poNumber}
Student Licenses: ${studentQty}
Teacher Licenses: ${teacherQty}
Teacher License Total: $${teacherLicenseTotal}
Student License Total: $${studentLicenseTotal}
Total Purchase Price: $${totalPurchasePrice}

To distribute these licenses to your teachers, please follow the instructions below:

1. Navigate to https://license-distribution.trinity-capital.net  
2. Enter the email address you used for this purchase: ${adminEmail}  
3. Enter each teacher's email address and click "Send Code"  
4. Repeat until the page confirms all licenses have been distributed

If you encounter any issues or need assistance, contact us at support@trinitycapapp.com.

Thank you for choosing Trinity Capital.

Sincerely,  
The Trinity Capital Team
`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Confirmation email sent to ${adminEmail}`);

    // Save license record in DB with all new fields
    const licenseRecord = {
      school_name: schoolName,
      district_name: schoolDistrict,
      admin_email: adminEmail,
      admin_name: adminName,
      teacher_licenses: parseInt(teacherQty),
      student_licenses: parseInt(studentQty),
      teacher_license_total: parseFloat(teacherLicenseTotal),
      student_license_total: parseFloat(studentLicenseTotal),
      total_purchase_price: parseFloat(totalPurchasePrice),
      payment_method: "manual/ACH",
      payment_status: "completed",
      po_number: poNumber,
      amount_paid: parseFloat(totalPurchasePrice),
      currency: "USD",
      purchase_date: purchaseDate,
      license_expiry: licenseExpiry,
      is_active: true,
    };

    await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .insertOne(licenseRecord);
    console.log("License record saved for manual purchase");

    await generateAccessCodes(
      schoolName,
      adminName,
      parseInt(teacherQty),
      parseInt(studentQty)
    );
    console.log("Teacher access codes generated");

    res.status(200).json({ message: "Email and license setup complete." });
  } catch (err) {
    console.error("Failed to process parcel:", err);
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// --- Email Quote PDF endpoint ---
app.post("/send-quote-email", async (req, res) => {
  try {
    console.log("Received email request");

    const {
      pdfBase64,
      pdfFilename,
      recipientEmail,
      adminName,
      districtName,
      schoolName,
      schoolAddress,
      studentQty,
      teacherQty,
      studentTotal,
      teacherTotal,
      grandTotal,
      quoteId,
      quoteDate,
    } = req.body;

    if (!pdfBase64 || !recipientEmail) {
      return res.status(400).json({ error: "Missing PDF or recipient email" });
    }
    // Decode base64 PDF
    const pdfBuffer = Buffer.from(pdfBase64, "base64");

    // Setup nodemailer for Google Workspace
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: recipientEmail,
      subject:
        `Quote PDF from Trinity Capital` +
        (schoolName ? ` - ${schoolName}` : ""),
      text:
        `Dear ${adminName || "Administrator"},\n\n` +
        `Please find attached your requested quote.\n\n` +
        `School: ${schoolName}\nDistrict: ${districtName}\nAddress: ${schoolAddress}\n` +
        `Student Licenses: ${studentQty} ($${studentTotal})\n` +
        `Teacher Licenses: ${teacherQty} ($${teacherTotal})\n` +
        `Total: $${grandTotal}\nQuote ID: ${quoteId}\nQuote Date: ${quoteDate}\n\n` +
        `Note: W-9 tax form is available upon request.\n\n` +
        `Thank you for your interest in Trinity Capital.`,
      attachments: [
        {
          filename: pdfFilename || "Quote.pdf",
          content: pdfBuffer,
          contentType: "application/pdf",
        },
      ],
    };

    await transporter.sendMail(mailOptions);
    console.log("Email sent successfully");
    res.json({ success: true });
  } catch (error) {
    console.error("Error sending quote email:", error);
    res.status(500).json({ error: error.message });
  }
});

// Start server
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
