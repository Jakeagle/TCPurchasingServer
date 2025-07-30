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

// 🚨 CRITICAL FIX: Webhook endpoint with raw body middleware inline
app.post(
  "/purchase",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];

    // Enhanced debugging for signature issues
    console.log("🔍 EMERGENCY WEBHOOK DEBUG:");
    console.log("- Stripe signature:", sig);
    console.log("- Body is Buffer:", Buffer.isBuffer(req.body));
    console.log("- Body type:", typeof req.body);
    console.log("- Body length:", req.body?.length);
    console.log(
      "- Webhook secret exists:",
      !!process.env.STRIPE_WEBHOOK_SECRET
    );

    let event;

    try {
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

      console.log("✅ Webhook signature verified successfully!");
    } catch (err) {
      console.error("❌ Webhook signature verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      switch (event.type) {
        case "checkout.session.completed":
          console.log("🎯 Processing checkout completion...");
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
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps, curl, postman)
      if (!origin) return callback(null, true);

      if (allowedOrigins.indexOf(origin) !== -1) {
        return callback(null, true);
      } else {
        console.log("CORS blocked origin:", origin);
        console.log("Allowed origins:", allowedOrigins);
        return callback(new Error("Not allowed by CORS"), false);
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
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
      success_url: `${process.env.BASE_URL}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/error`,
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

// Free Trial Signup Endpoint
app.post("/create-free-trial", async (req, res) => {
  try {
    const {
      admin_name,
      admin_email,
      school_name,
      district_name,
      teacher_quantity,
      student_quantity,
    } = req.body;

    // Validation
    if (!admin_name || !admin_email || !school_name || !district_name) {
      return res.status(400).json({
        error: "All fields are required for free trial signup",
      });
    }

    if (teacher_quantity <= 0) {
      return res.status(400).json({
        error: "At least 1 teacher is required for free trial",
      });
    }

    if (student_quantity <= 0) {
      return res.status(400).json({
        error: "At least 1 student is required for free trial",
      });
    }

    // Check if school already has an active trial or paid license
    const existingTrial = await client
      .db("TrinityCapital")
      .collection("Free Trials")
      .findOne({
        admin_email: admin_email,
        is_active: true,
      });

    const existingLicense = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .findOne({
        admin_email: admin_email,
        is_active: true,
      });

    if (existingTrial) {
      return res.status(400).json({
        error: "This email already has an active free trial",
      });
    }

    if (existingLicense) {
      return res.status(400).json({
        error:
          "This email already has an active license. Free trial not available.",
      });
    }

    // Create trial record
    const trialRecord = {
      school_name,
      district_name,
      admin_email,
      admin_name,
      teacher_licenses: parseInt(teacher_quantity),
      student_licenses: parseInt(student_quantity),
      trial_start_date: new Date(),
      trial_end_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      is_active: true,
      license_type: "trial",
      created_at: new Date(),
    };

    const result = await client
      .db("TrinityCapital")
      .collection("Free Trials")
      .insertOne(trialRecord);

    console.log("✅ Free trial created:", result.insertedId);

    // Also create a license record in School Licenses collection for admin dashboard compatibility
    const licenseRecord = {
      school_name,
      district_name,
      admin_email,
      admin_name,
      student_licenses: parseInt(student_quantity),
      teacher_licenses: parseInt(teacher_quantity),
      stripe_session_id: null, // No Stripe session for trials
      stripe_customer_id: null, // No Stripe customer for trials
      payment_status: "trial", // Mark as trial instead of completed
      amount_paid: 0, // Free trial
      currency: "usd",
      purchase_date: new Date(),
      license_expiry: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      is_active: true,
      license_type: "trial", // Mark this as a trial license
      trial_id: result.insertedId, // Reference to the trial record
    };

    await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .insertOne(licenseRecord);

    console.log(
      "✅ Trial license record created in School Licenses collection"
    );

    // Generate teacher access codes for the trial
    await generateTrialAccessCodes(
      school_name,
      admin_name,
      teacher_quantity,
      student_quantity,
      result.insertedId
    );

    // Send trial confirmation email
    await sendTrialConfirmationEmail(
      admin_email,
      admin_name,
      school_name,
      teacher_quantity,
      student_quantity
    );

    // Return success with redirect URL to license distribution
    res.json({
      success: true,
      message: "Free trial created successfully",
      redirect_url: `https://license-distribution.trinity-capital.net?email=${encodeURIComponent(admin_email)}&trial=true`,
      trial_id: result.insertedId,
    });
  } catch (error) {
    console.error("Error creating free trial:", error);
    res.status(500).json({ error: "Failed to create free trial" });
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
    console.log("🎯 [EMAIL DEBUG] Processing successful payment...");
    console.log("🎯 [EMAIL DEBUG] This should trigger a confirmation email");
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
      console.log("🎯 [EMAIL DEBUG] About to send confirmation email...");
      console.log("🎯 [EMAIL DEBUG] Email will be sent to:", adminEmail);
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
      console.log("🎯 [EMAIL DEBUG] CONFIRMATION EMAIL SENT SUCCESSFULLY!");
      console.log("📨 Email result:", {
        messageId: emailResult.messageId,
        response: emailResult.response,
        accepted: emailResult.accepted,
        rejected: emailResult.rejected,
      });
    } catch (emailError) {
      console.error("🎯 [EMAIL DEBUG] FAILED TO SEND CONFIRMATION EMAIL!");
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
        license_type: "paid",
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

// Generate trial access codes - similar to paid but with trial expiration
async function generateTrialAccessCodes(
  schoolName,
  adminName,
  teacherCount,
  studentCount,
  trialId
) {
  try {
    const accessCodes = [];

    // Generate individual teacher codes for trial account creation
    for (let i = 0; i < teacherCount; i++) {
      accessCodes.push({
        code: crypto.randomBytes(4).toString("hex").toUpperCase(),
        type: "teacher",
        school: schoolName,
        admin: adminName,
        used: false,
        created_at: new Date(),
        expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        license_type: "trial",
        trial_id: trialId,
      });
    }

    if (accessCodes.length > 0) {
      await client
        .db("TrinityCapital")
        .collection("Access Codes")
        .insertMany(accessCodes);
    }

    console.log(
      `Generated ${teacherCount} trial teacher access codes for ${schoolName}`
    );
    return accessCodes;
  } catch (error) {
    console.error("Error generating trial access codes:", error);
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
      license_type: teacherCode.license_type || "paid",
      expires_at: teacherCode.expires_at,
      trial_id: teacherCode.trial_id || null,
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

// Send trial confirmation email
async function sendTrialConfirmationEmail(
  adminEmail,
  adminName,
  schoolName,
  teacherCount,
  studentCount
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
      subject: `Trinity Capital - Free Trial Activated for ${schoolName}`,
      html: `
        <h2>🎉 Free Trial Activated!</h2>
        <p>Dear ${adminName},</p>
        <p>Congratulations! Your Trinity Capital free trial has been successfully activated.</p>
        
        <h3>Trial Details:</h3>
        <ul>
          <li><strong>School:</strong> ${schoolName}</li>
          <li><strong>Teacher Licenses:</strong> ${teacherCount}</li>
          <li><strong>Student Licenses:</strong> ${studentCount}</li>
          <li><strong>Trial Duration:</strong> 30 days</li>
          <li><strong>Trial Start Date:</strong> ${new Date().toLocaleDateString()}</li>
          <li><strong>Trial End Date:</strong> ${new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toLocaleDateString()}</li>
        </ul>
        
        <h3>Next Steps:</h3>
        <p>1. <strong>Distribute Teacher Codes:</strong> Visit your admin dashboard to send access codes to your teachers</p>
        <p>2. <strong>Teacher Setup:</strong> Teachers will use their codes to create accounts and generate student access codes</p>
        <p>3. <strong>Start Learning:</strong> Students can begin using Trinity Capital immediately</p>
        
        <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 5px;">
          <h4>⚠️ Important Trial Information:</h4>
          <ul>
            <li>Your trial expires in <strong>30 days</strong></li>
            <li>All accounts created during the trial will have 30-day access</li>
            <li>To continue using Trinity Capital after the trial, you'll need to purchase licenses</li>
          </ul>
        </div>
        
        <p>Ready to get started? <a href="https://license-distribution.trinity-capital.net?email=${encodeURIComponent(adminEmail)}&trial=true" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Access Your Dashboard</a></p>
        
        <p>If you have any questions, please don't hesitate to contact our support team.</p>
        
        <p>Best regards,<br>The Trinity Capital Team</p>
      `,
    });

    console.log(`Trial confirmation email sent to ${adminEmail}`);
  } catch (error) {
    console.error("Error sending trial confirmation email:", error);
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

    // Check for paid license first
    let license = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .findOne({ admin_email: admin_email, is_active: true });

    let licenseType = "paid";
    let schoolName, districtName, adminName, teacherLicenses, studentLicenses;
    let purchaseDate, licenseExpiry, trialEndDate, daysRemaining;

    if (license) {
      // Check if this is a trial license and if it has expired
      if (license.license_type === "trial") {
        const now = new Date();
        const trialEnd = new Date(license.license_expiry);

        if (now > trialEnd) {
          // Trial has expired, mark both records as inactive
          await client
            .db("TrinityCapital")
            .collection("School Licenses")
            .updateOne({ _id: license._id }, { $set: { is_active: false } });

          if (license.trial_id) {
            await client
              .db("TrinityCapital")
              .collection("Free Trials")
              .updateOne(
                { _id: new ObjectId(license.trial_id) },
                { $set: { is_active: false } }
              );
          }

          return res.status(403).json({
            error: "Trial has expired",
            expired: true,
            trial_end_date: trialEnd,
          });
        }

        // Trial is still active
        licenseType = "trial";
        trialEndDate = license.license_expiry;
        daysRemaining = Math.ceil((trialEnd - now) / (1000 * 60 * 60 * 24));
      } else {
        licenseType = "paid";
        purchaseDate = license.purchase_date;
        licenseExpiry = license.license_expiry;
      }

      schoolName = license.school_name;
      districtName = license.district_name;
      adminName = license.admin_name;
      teacherLicenses = license.teacher_licenses;
      studentLicenses = license.student_licenses;
    } else {
      // No active license found in School Licenses collection
      return res
        .status(404)
        .json({ error: "No active license or trial found for this admin" });
    }

    // Get unused teacher codes for this school
    const unusedCodes = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .find({
        school: schoolName,
        type: "teacher",
        used: false,
      })
      .toArray();

    // Get used teacher codes for tracking
    const usedCodes = await client
      .db("TrinityCapital")
      .collection("Access Codes")
      .find({
        school: schoolName,
        type: "teacher",
        used: true,
      })
      .toArray();

    const response = {
      license_type: licenseType,
      school_name: schoolName,
      district_name: districtName,
      admin_name: adminName,
      teacher_licenses: teacherLicenses,
      student_licenses: studentLicenses,
      unused_codes: unusedCodes,
      used_codes: usedCodes,
      codes_remaining: unusedCodes.length,
    };

    // Add license-specific fields
    if (licenseType === "paid") {
      response.purchase_date = purchaseDate;
      response.license_expiry = licenseExpiry;
    } else {
      response.trial_end_date = trialEndDate;
      response.days_remaining = daysRemaining;
    }

    res.json(response);
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
1. Go to the Trinity Capital teacher registration page: https://registration.trinity-capital.net
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
    console.log("🎯 [EMAIL DEBUG] Teacher code email endpoint called");
    const { admin_email, recipient_email, subject, body, code_id } = req.body;
    console.log("🎯 [EMAIL DEBUG] Request data:", {
      admin_email,
      recipient_email,
      subject: subject?.substring(0, 50) + "...",
    });

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
    console.log("🎯 [EMAIL DEBUG] About to send teacher code email...");
    const emailResult = await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: recipient_email,
      subject: subject,
      text: body,
      html: body.replace(/\n/g, "<br>"), // Convert line breaks to HTML
      replyTo: admin_email, // Allow teacher to reply directly to admin
    });

    console.log("🎯 [EMAIL DEBUG] TEACHER CODE EMAIL SENT SUCCESSFULLY!");
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

    // Check for license (both paid and trial are now in School Licenses collection)
    const license = await client
      .db("TrinityCapital")
      .collection("School Licenses")
      .findOne({ admin_email: admin_email, is_active: true });

    if (!license) {
      return res.status(404).json({
        error: "No active license or trial found for this email address",
        valid: false,
      });
    }

    // Check if it's a trial license and if it has expired
    if (license.license_type === "trial") {
      const now = new Date();
      const trialEnd = new Date(license.license_expiry);

      if (now > trialEnd) {
        // Trial has expired, mark both records as inactive
        await client
          .db("TrinityCapital")
          .collection("School Licenses")
          .updateOne({ _id: license._id }, { $set: { is_active: false } });

        if (license.trial_id) {
          await client
            .db("TrinityCapital")
            .collection("Free Trials")
            .updateOne(
              { _id: new ObjectId(license.trial_id) },
              { $set: { is_active: false } }
            );
        }

        return res.status(403).json({
          error: "Trial has expired",
          valid: false,
          expired: true,
          trial_end_date: trialEnd,
        });
      }

      // Trial is still active
      return res.json({
        valid: true,
        license_type: "trial",
        school_name: license.school_name,
        district_name: license.district_name,
        admin_name: license.admin_name,
        teacher_licenses: license.teacher_licenses,
        student_licenses: license.student_licenses,
        trial_end_date: license.license_expiry,
        days_remaining: Math.ceil((trialEnd - now) / (1000 * 60 * 60 * 24)),
      });
    }

    // Paid license
    return res.json({
      valid: true,
      license_type: "paid",
      school_name: license.school_name,
      district_name: license.district_name,
      admin_name: license.admin_name,
      teacher_licenses: license.teacher_licenses,
      student_licenses: license.student_licenses,
      purchase_date: license.purchase_date,
      license_expiry: license.license_expiry,
    });
  } catch (error) {
    console.error("Error validating admin:", error);
    res.status(500).json({ error: error.message });
  }
});

// Validate user access (for app login validation)
app.post("/validate-user-access", async (req, res) => {
  try {
    const { user_email, user_type } = req.body; // user_type: "teacher" or "student"

    // For trial users, check if their trial has expired
    // This assumes users store their trial_id or school info in their profile
    const user = await client
      .db("TrinityCapital")
      .collection("Users") // Adjust collection name as needed
      .findOne({ email: user_email });

    if (!user) {
      return res.status(404).json({
        error: "User not found",
        valid: false,
      });
    }

    // If user is associated with a trial
    if (user.license_type === "trial" && user.trial_id) {
      const trial = await client
        .db("TrinityCapital")
        .collection("Free Trials")
        .findOne({ _id: new ObjectId(user.trial_id) });

      if (!trial) {
        return res.status(404).json({
          error: "Associated trial not found",
          valid: false,
        });
      }

      const now = new Date();
      const trialEnd = new Date(trial.trial_end_date);

      if (now > trialEnd) {
        return res.status(403).json({
          error: "Trial access has expired",
          valid: false,
          expired: true,
          trial_end_date: trialEnd,
          message:
            "Your 30-day trial has expired. Please contact your administrator to purchase a full license.",
        });
      }

      return res.json({
        valid: true,
        license_type: "trial",
        trial_end_date: trialEnd,
        days_remaining: Math.ceil((trialEnd - now) / (1000 * 60 * 60 * 24)),
        school_name: trial.school_name,
      });
    }

    // If user has paid license, they have full access
    return res.json({
      valid: true,
      license_type: "paid",
    });
  } catch (error) {
    console.error("Error validating user access:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/send-parcel-email", async (req, res) => {
  console.log("🎯 [EMAIL DEBUG] Parcel email endpoint called");
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

  console.log("🎯 [EMAIL DEBUG] Parcel data received:", {
    schoolName,
    adminEmail,
  });

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
    console.log("🎯 [EMAIL DEBUG] About to send parcel confirmation email...");
    await transporter.sendMail(mailOptions);
    console.log("🎯 [EMAIL DEBUG] PARCEL EMAIL SENT SUCCESSFULLY!");
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

    // Determine if this is a bulk quote
    const isBulkQuote =
      studentQty === "999" && teacherQty === "999" && grandTotal === "$20,000";

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: recipientEmail,
      subject:
        `Quote PDF from Trinity Capital` +
        (schoolName ? ` - ${schoolName}` : ""),
      text: isBulkQuote
        ? `Dear ${adminName || "Administrator"},\n\n` +
          `Please find attached your requested quote for our School-Wide License.\n\n` +
          `School: ${schoolName}\nDistrict: ${districtName}\nAddress: ${schoolAddress}\n` +
          `License Type: School-Wide (Unlimited Students & Teachers)\n` +
          `Total: ${grandTotal}\nQuote ID: ${quoteId}\nQuote Date: ${quoteDate}\n\n` +
          `The School-Wide License includes:\n` +
          `• Unlimited student access\n` +
          `• Unlimited teacher licenses\n` +
          `• Priority support and training\n` +
          `• Custom implementation assistance\n` +
          `• Multi-year discount options available\n\n` +
          `Note: W-9 tax form is available upon request.\n\n` +
          `Thank you for your interest in Trinity Capital.`
        : `Dear ${adminName || "Administrator"},\n\n` +
          `Please find attached your requested quote.\n\n` +
          `School: ${schoolName}\nDistrict: ${districtName}\nAddress: ${schoolAddress}\n` +
          `Student Licenses: ${studentQty} (${studentTotal})\n` +
          `Teacher Licenses: ${teacherQty} (${teacherTotal})\n` +
          `Total: ${grandTotal}\nQuote ID: ${quoteId}\nQuote Date: ${quoteDate}\n\n` +
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
