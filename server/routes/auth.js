const express = require('express');
const router = express.Router();
const User = require('../models/User');
const OTP = require('../models/OTP');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const crypto = require('crypto');
require('dotenv').config();

const algorithm = 'aes-256-cbc';
const key = crypto.scryptSync(process.env.JWT_SECRET, 'salt', 32);

const encrypt = (text) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
};

const decrypt = (encryptedData) => {
  try {
    if (typeof encryptedData !== 'string' || !encryptedData.includes(':')) {
      console.warn('Invalid encrypted data format, returning as-is:', encryptedData);
      return encryptedData || '';
    }
    const [ivHex, encrypted] = encryptedData.split(':');
    if (!ivHex || ivHex.length !== 32 || !encrypted) {
      console.warn('Invalid IV or encrypted data:', encryptedData);
      return encryptedData;
    }
    const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(ivHex, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error.message, 'Data:', encryptedData);
    return encryptedData;
  }
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ message: 'Invalid token' });
  }
};

// Email configuration with debugging
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // kallurbhavesh@gmail.com
    pass: process.env.EMAIL_PASS, // bptq vceb yyet anxt
  },
  debug: true, // Enable SMTP debug output
  logger: true, // Log to console
});
transporter.verify((error, success) => {
  if (error) {
    console.error('Email transporter verification failed:', error.stack);
  } else {
    console.log('Email transporter is ready to send messages');
  }
});

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

// Two separate Gemini instances
const genAIImage = new GoogleGenerativeAI(process.env.GEMINI_API_KEY); // For image processing
const modelImage = genAIImage.getGenerativeModel({ model: 'gemini-1.5-flash' });

const genAIChat = new GoogleGenerativeAI(process.env.GEMINI_API_KEY_CHAT); // For chat
const modelChat = genAIChat.getGenerativeModel({ model: 'gemini-1.5-flash' });

// Send OTP
router.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  const otp = generateOtp();
  const expiryTime = new Date(Date.now() + 10 * 60 * 1000);

  try {
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    await OTP.findOneAndUpdate(
      { email },
      { otp, createdAt: new Date(), expiresAt: expiryTime },
      { upsert: true, new: true }
    );
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'BudgetBuddy: Confirm Your Email to Get Started',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Email Verification - BudgetBuddy</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              background-color: #f8f9fa;
              margin: 0;
              padding: 0;
            }
            .container {
              max-width: 600px;
              margin: 20px auto;
              background-color: #ffffff;
              border: 1px solid #d1d5db;
              border-radius: 8px;
              padding: 20px;
              text-align: center;
              box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
            }
            h2 {
              color: #1e40af;
            }
            p {
              color: #333333;
              font-size: 16px;
              line-height: 1.5;
            }
            .otp-code {
              font-size: 24px;
              font-weight: bold;
              color: #2563eb;
              background-color: #e0f2fe;
              display: inline-block;
              padding: 10px 20px;
              border-radius: 5px;
              margin: 10px 0;
            }
            .footer {
              font-size: 12px;
              color: #6b7280;
              margin-top: 20px;
            }
            a {
              color: #2563eb;
              text-decoration: none;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Welcome to BudgetBuddy!</h2>
            <p>Hello,Buddy</p>
            <p>Thank you for Trusting us!. To complete your registration, please use the OTP code below:</p>
            <div class="otp-code">${otp}</div>
            <p>This code is valid for <strong>10 minutes</strong>. If you did not want this, please ignore this email.</p>
            <p>Happy budgeting!<br><strong>The BudgetBuddy Team</strong></p>
          </div>
        </body>
        </html>
      `,
    };
    
    

    const info = await transporter.sendMail(mailOptions);
    console.log('OTP email sent:', info.messageId);
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Error sending OTP email:', error.stack);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Signup
router.post('/signup', async (req, res) => {
  const { username, email, password, role, otp } = req.body;
  try {
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    const otpRecord = await OTP.findOne({ email, otp });
    if (!otpRecord || new Date() > otpRecord.expiresAt) {
      await OTP.deleteOne({ email, otp });
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const encryptedSalary = encrypt('0');
    const user = new User({
      username,
      email,
      password: hashedPassword,
      role: role || 'user',
      verified: true,
      salary: encryptedSalary,
    });
    await user.save();
    await OTP.deleteOne({ email, otp });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Signup successful', token });
  } catch (error) {
    console.error('Signup error:', error.stack);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Login error:', error.stack);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get Profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });

    const decryptedSalary = decrypt(user.salary);
    const decryptedExpenses = user.expenses.map(exp => ({
      id: exp.id,
      expenses: JSON.parse(decrypt(exp.expenses)),
      date: exp.date,
    }));
    const decryptedLastImageContent = user.lastImageContent ? decrypt(user.lastImageContent) : '';

    res.json({
      username: user.username,
      email: user.email,
      salary: decryptedSalary,
      expenses: decryptedExpenses,
      lastImageContent: decryptedLastImageContent,
    });
  } catch (error) {
    console.error('Profile fetch error:', error.stack);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update Profile with Email Notification
router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { salary, expenses, lastImageContent, chartImage } = req.body;
    console.log('PUT /profile request body:', { salary, expenses, lastImageContent, chartImage });

    const updates = {};
    if (salary !== undefined && salary !== null) updates.salary = encrypt(salary.toString());
    if (expenses !== undefined) {
      updates.expenses = expenses.map(exp => ({
        id: exp.id || crypto.randomUUID(),
        expenses: encrypt(JSON.stringify(exp.expenses)),
        date: new Date(exp.date),
      }));
    }
    if (lastImageContent !== undefined) updates.lastImageContent = encrypt(lastImageContent);

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password');

    if (!user) {
      console.log('User not found for ID:', req.user.id);
      return res.status(404).json({ message: 'User not found' });
    }

    console.log('Updated user:', {
      id: user._id,
      username: user.username,
      email: user.email,
      expensesCount: user.expenses.length,
    });

    // Email sending logic
    if (expenses && expenses.length > 0) {
      if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        console.error('Email credentials missing:', {
          EMAIL_USER: !!process.env.EMAIL_USER,
          EMAIL_PASS: !!process.env.EMAIL_PASS,
        });
      } else {
        const latestExpense = expenses[expenses.length - 1].expenses;
        const totalDeduction = Object.values(latestExpense).reduce((sum, val) => sum + val, 0);
        const plainSalary = salary !== undefined && salary !== null ? salary : decrypt(user.salary);
        const isHighExpended = totalDeduction > parseFloat(plainSalary) * 0.5;
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: user.email,
          subject: 'BudgetBuddy - Your Latest Expense Update',
          html: `
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Expense Update - BudgetBuddy</title>
              <style>
                body {
                  font-family: Arial, sans-serif;
                  background-color: #f9fafb;
                  margin: 0;
                  padding: 0;
                }
                .container {
                  max-width: 600px;
                  margin: 20px auto;
                  background-color: #ffffff;
                  border-radius: 10px;
                  padding: 20px;
                  box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
                }
                h2 {
                  color: #1e3a8a;
                  text-align: center;
                }
                p {
                  color: #333333;
                  font-size: 16px;
                  line-height: 1.5;
                }
                ul {
                  list-style-type: disc;
                  padding-left: 20px;
                  color: #374151;
                  font-size: 16px;
                }
                .highlight {
                  font-weight: bold;
                }
                .warning {
                  color: #dc2626;
                  font-weight: bold;
                }
                .success {
                  color: #16a34a;
                  font-weight: bold;
                }
                .footer {
                  font-size: 12px;
                  color: #6b7280;
                  text-align: center;
                  margin-top: 20px;
                }
                .chart-container {
                  text-align: center;
                  margin-top: 20px;
                }
                .chart-container img {
                  max-width: 100%;
                  border-radius: 8px;
                }
                a {
                  color: #2563eb;
                  text-decoration: none;
                }
              </style>
            </head>
            <body>
              <div class="container">
                <h2>Expense Update from BudgetBuddy</h2>
                <p>Hello ,<span class="highlight">${user.username}</span>,</p>
                <p>You’ve just saved new expenses from expenses tracker. Here’s the overview:</p>
                <ul>
                  ${Object.entries(latestExpense)
                    .map(([cat, amt]) => `<li>${cat}: ₹${amt.toFixed(2)}</li>`)
                    .join('')}
                </ul>
                <p><span class="highlight">Total Deduction:</span> ₹${totalDeduction.toFixed(2)}</p>
                <p><span class="highlight">Remaining Salary:</span> ₹${parseFloat(plainSalary).toFixed(2)}</p>
                <p class="${isHighExpended ? 'warning' : 'success'}">
                  ${isHighExpended ? '⚠ High Expenditure Warning: You’ve spent over 50% of your salary!' : '✅ You’re managing your expenses well!'}
                </p>
                ${chartImage ? `
                  <div class="chart-container">
                    <h3>Your Expense Chart:</h3>
                    <img src="cid:expense-chart" alt="Expense Chart" />
                  </div>
                ` : ''}     
                <p>Happy budgeting,<br><strong>The BudgetBuddy Team</strong></p>
              </div>
            </body>
            </html>
          `,
          attachments: chartImage
            ? [{
                filename: 'expense-chart.png',
                content: Buffer.from(chartImage.split(',')[1], 'base64'),
                cid: 'expense-chart',
              }]
            : [],
        };
        
        console.log('Attempting to send email to:', user.email);
        const info = await transporter.sendMail(mailOptions);
        console.log('Expense update email sent successfully:', info.messageId);
      }
    }

    const decryptedSalary = decrypt(user.salary);
    const decryptedExpenses = user.expenses.map(exp => ({
      id: exp.id,
      expenses: JSON.parse(decrypt(exp.expenses)),
      date: exp.date,
    }));
    const decryptedLastImageContent = user.lastImageContent ? decrypt(user.lastImageContent) : '';

    res.json({
      username: user.username,
      email: user.email,
      salary: decryptedSalary,
      expenses: decryptedExpenses,
      lastImageContent: decryptedLastImageContent,
      message: 'Profile updated successfully',
    });
  } catch (error) {
    console.error('PUT /profile error:', error.stack);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Process Expenses with Gemini (Image Processing)
// router.post('/expenses/gemini', authenticateToken, async (req, res) => {
//   try {
//     const { image } = req.body;
//     if (!image) return res.status(400).json({ message: 'Image data is required' });

//     const imgBuffer = Buffer.from(image, 'base64');
//     const result = await modelImage.generateContent([
//       {
//         inlineData: {
//           data: imgBuffer.toString('base64'),
//           mimeType: 'image/png',
//         },
//       },
//     ]);

//     const text = result.response.text();
//     const expenseMatches = text.matchAll(/\$?(\d+\.?\d{0,2})\s*\(?([A-Za-z]+)\)?|([A-Za-z]+)\s*\$?(\d+\.?\d{0,2})/g);
//     const expenses = {};
//     let totalAmount = 0;
//     const expenseLines = [];

//     for (const match of expenseMatches) {
//       let category, amount;
//       if (match[1] && match[2]) {
//         amount = parseFloat(match[1]);
//         category = match[2];
//       } else if (match[3] && match[4]) {
//         category = match[3];
//         amount = parseFloat(match[4]);
//       }
//       if (category && amount) {
//         category = category.charAt(0).toUpperCase() + category.slice(1).toLowerCase();
//         expenses[category] = (expenses[category] || 0) + amount;
//         totalAmount += amount;
//         expenseLines.push(`${category} ₹${amount.toFixed(2)}`);
//       }
//     }

//     const extractedText = expenseLines.join(', ');
//     if (Object.keys(expenses).length === 0) {
//       return res.status(400).json({ message: 'No valid expense data found in the image' });
//     }

//     res.json({
//       extractedText: extractedText || text,
//       expenses,
//       totalAmount,
//     });
//   } catch (error) {
//     console.error('Gemini Image API error:', error.stack);
//     res.status(500).json({ message: 'Failed to process image', error: error.message });
//   }
// });
// Process Expenses with Gemini (Image Processing)
router.post('/expenses/gemini', authenticateToken, async (req, res) => {
  try {
    const { image, mimeType = 'image/png' } = req.body; // Default to PNG, allow client to specify
    if (!image) return res.status(400).json({ message: 'Image data is required' });

    // Validate mimeType (only allow specific image types)
    const allowedMimeTypes = ['image/png', 'image/jpeg', 'image/jpg'];
    if (!allowedMimeTypes.includes(mimeType)) {
      return res.status(400).json({
        message: `Invalid image format. Accepted formats: ${allowedMimeTypes.join(', ')}`,
      });
    }

    // Decode base64 image
    const imgBuffer = Buffer.from(image, 'base64');

    // Prompt Gemini to extract expenses as key-value pairs
    const prompt = `
      You are an expense extractor. Analyze the provided image and extract expense data in a structured key-value format.
      Each key should be a category (e.g., Food, Transport) and each value should be a numerical amount (e.g., 50.00).
      If a currency symbol is present (e.g., $, ₹), ignore it and return only the number.
      Return the result as a JSON object like: {"Food": 50.00, "Transport": 25.50}.
      If no expenses are found, return an empty object: {}.
      Additionally, provide the raw extracted text for reference.
    `;

    const result = await modelImage.generateContent([
      prompt,
      {
        inlineData: {
          data: imgBuffer.toString('base64'),
          mimeType: mimeType, // Use the provided or default mimeType
        },
      },
    ]);

    const responseText = result.response.text().trim();
    
    // Attempt to parse the response as JSON
    let expenses = {};
    let extractedText = responseText;
    try {
      // Look for JSON-like content in the response
      const jsonMatch = responseText.match(/{[^}]+}/);
      if (jsonMatch) {
        expenses = JSON.parse(jsonMatch[0]);
        extractedText = responseText.replace(jsonMatch[0], '').trim() || responseText;
      }
    } catch (parseError) {
      console.warn('Failed to parse JSON from Gemini response:', parseError.message);
      // Fallback: Use regex to extract key-value pairs if JSON parsing fails
      const expenseMatches = responseText.matchAll(/([A-Za-z]+)\s*[:=]\s*\$?(\d+\.?\d{0,2})/g);
      for (const match of expenseMatches) {
        const category = match[1].charAt(0).toUpperCase() + match[1].slice(1).toLowerCase();
        const amount = parseFloat(match[2]);
        expenses[category] = amount;
      }
    }

    // Calculate total amount
    const totalAmount = Object.values(expenses).reduce((sum, val) => sum + val, 0);

    if (Object.keys(expenses).length === 0) {
      return res.status(400).json({
        message: 'No valid expense data found in the image',
        extractedText,
      });
    }

    // Format expenses for display
    const expenseLines = Object.entries(expenses)
      .map(([category, amount]) => `${category}: ₹${amount.toFixed(2)}`)
      .join(', ');

    res.json({
      extractedText: expenseLines || extractedText, // Display formatted expenses or raw text
      expenses, // Structured key-value object
      totalAmount: totalAmount.toFixed(2), // Total as a string with 2 decimal places
    });
  } catch (error) {
    console.error('Gemini Image API error:', error.stack);
    res.status(500).json({ message: 'Failed to process image', error: error.message });
  }
});

// Assistant (Chat)
router.post('/assistant', authenticateToken, async (req, res) => {
  try {
    const { message, salary, expensesList } = req.body;
    if (!message) return res.status(400).json({ message: 'Message is required' });

    const context = `
      You are a personal finance assistant for BudgetBuddy. The user's current salary is ₹${salary}. 
      Their saved expenses are: ${
        expensesList.length > 0
          ? expensesList.map(exp => `${exp.id}: ${JSON.stringify(exp.expenses)}`).join(', ')
          : 'None'
      }. Provide concise, actionable financial advice based on this data and the user's question: "${message}"
    `;

    const result = await modelChat.generateContent([context]);
    const responseText = result.response.text();

    res.json({ response: responseText });
  } catch (error) {
    console.error('Gemini Chat API error:', error.stack);
    res.status(500).json({ message: 'Failed to get assistant response', error: error.message });
  }
});

module.exports = router;