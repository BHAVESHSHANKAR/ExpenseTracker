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
const key = crypto.scryptSync(process.env.JWT_SECRET, 'salt', 32); // Derive a 32-byte key from JWT_SECRET

const encrypt = (text) => {
  const iv = crypto.randomBytes(16); // Unique IV for each encryption
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`; // Store IV with encrypted data
};

const decrypt = (encryptedData) => {
  try {
    // Check if encryptedData is a string and contains the expected format
    if (typeof encryptedData !== 'string' || !encryptedData.includes(':')) {
      console.warn('Invalid encrypted data format, returning as-is:', encryptedData);
      return encryptedData || ''; // Return as-is or empty string if invalid
    }

    const [ivHex, encrypted] = encryptedData.split(':');
    if (!ivHex || ivHex.length !== 32 || !encrypted) {
      console.warn('Invalid IV or encrypted data:', encryptedData);
      return encryptedData; // Return original data if IV is invalid
    }

    const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(ivHex, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error.message, 'Data:', encryptedData);
    return encryptedData; // Return original data on error to avoid breaking the app
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

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  debug: false,
  logger: false,
});

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || 'YOUR_GEMINI_API_KEY');
const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
const genChat = new GoogleGenerativeAI(process.env.GEMINI_API_KEY_CHAT || 'YOUR_GEMINI_API_KEY');
const modelChat = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
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

    

    // const mailOptions = {
    //   from: process.env.USER,
    //   to: email,
    //   subject: 'Welcome to BudgetBuddy - Verify Your Account with OTP',
    //   html: `
    //     <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f9fafb; border-radius: 10px;">
    //       <h2 style="color: #1e3a8a;">Welcome to BudgetBuddy!</h2>
    //       <p>Hello,</p>
    //       <p>Thank you for joining BudgetBuddy! Verify your email with this OTP:</p>
    //       <h3 style="color: #38bdf8; font-size: 24px;">${otp}</h3>
    //       <p>Enter this code within 10 minutes. Contact <a href="mailto:budgetbuddy004@gmail.com">budgetbuddy004@gmail.com</a> if needed.</p>
    //       <p>Happy budgeting,<br>The BudgetBuddy Team</p>
    //       <footer style="font-size: 12px; color: #6b7280; margin-top: 20px;">© 2025 BudgetBuddy.</footer>
    //     </div>
    //   `,
    // };
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'BudgetBuddy: Confirm Your Email to Get Started',
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f8f9fa; border: 1px solid #d1d5db; border-radius: 8px;">
          <h2 style="color: #1e40af; text-align: center;">Welcome to BudgetBuddy!</h2>
          <p>Hello,</p>
          <p>Thank you for joining BudgetBuddy! Please verify your email with the following OTP:</p>
          <h3 style="color: #2563eb; font-size: 22px; text-align: center;">${otp}</h3>
          <p>Note: This code will expire in 10 minutes.</p>
          <p>For any assistance, feel free to reach out to us at <a href="mailto:budgetbuddy004@gmail.com">budgetbuddy004@gmail.com</a>.</p>
          <p>Happy budgeting!<br>— The BudgetBuddy Team</p>
          <footer style="font-size: 12px; color: #6b7280; text-align: center; margin-top: 20px;">
            © 2025 BudgetBuddy | <a href="[unsubscribe_link]" style="color: #2563eb;">Unsubscribe</a>
          </footer>
        </div>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Error sending email:', error);
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
    const encryptedSalary = encrypt('0'); // Default salary encrypted
    const user = new User({
      username,
      email,
      password: hashedPassword,
      role,
      verified: true,
      salary: encryptedSalary,
    });
    await user.save();
    await OTP.deleteOne({ email, otp });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Signup successful', token });
  } catch (error) {
    console.error('Signup error:', error);
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
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error', error });
  }
});

// Get Profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Decrypt fields for response
    const decryptedSalary = decrypt(user.salary);
    const decryptedExpenses = user.expenses.map(exp => ({
      id: exp.id,
      expenses: JSON.parse(decrypt(exp.expenses)), // Decrypt and parse back to object
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
    console.error('Profile fetch error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update Profile with Email Notification
// router.put('/profile', authenticateToken, async (req, res) => {
//   try {
//     const { salary, expenses, lastImageContent, chartImage } = req.body;
//     const updates = {};

//     // Encrypt fields for database storage
//     if (salary !== undefined && salary !== null) {
//       updates.salary = encrypt(salary.toString());
//     }
//     if (expenses !== undefined) {
//       updates.expenses = expenses.map(exp => ({
//         id: exp.id,
//         expenses: encrypt(JSON.stringify(exp.expenses)), // Encrypt the expenses object as a JSON string
//         date: new Date(exp.date), // Ensure date is a Date object
//       }));
//     }
//     if (lastImageContent !== undefined) {
//       updates.lastImageContent = encrypt(lastImageContent);
//     }

//     const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true }).select('-password');
//     if (!user) return res.status(404).json({ message: 'User not found' });

//     if (expenses && expenses.length > 0) {
//       const latestExpense = expenses[expenses.length - 1].expenses; // Plain text from request
//       const totalDeduction = Object.values(latestExpense).reduce((sum, val) => sum + val, 0);
      
//       // Use plain-text salary from request, fallback to decrypted current salary if not provided
//       const plainSalary = salary !== undefined && salary !== null ? salary : decrypt(user.salary);
//       const isHighExpended = totalDeduction > parseFloat(plainSalary) * 0.5;

//       const mailOptions = {
//         from: process.env.EMAIL_USER,
//         to: user.email,
//         subject: 'BudgetBuddy - Your Latest Expense Update',
//         html: `
//           <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f9fafb; border-radius: 10px;">
//             <h2 style="color: #1e3a8a;">Expense Update from BudgetBuddy</h2>
//             <p>Hello ${user.username},</p>
//             <p>You’ve just saved new expenses. Here’s the breakdown:</p>
//             <ul style="list-style-type: disc; padding-left: 20px;">
//               ${Object.entries(latestExpense)
//                 .map(([cat, amt]) => `<li>${cat}: ₹${amt.toFixed(2)}</li>`)
//                 .join('')}
//             </ul>
//             <p>Total Deduction: ₹${totalDeduction.toFixed(2)}</p>
//             <p>Remaining Salary: ₹${parseFloat(plainSalary).toFixed(2)}</p>
//             <p style="color: ${isHighExpended ? '#dc2626' : '#16a34a'}; font-weight: bold;">
//               ${isHighExpended ? 'High Expenditure Warning: You’ve spent over 50% of your salary!' : 'You’re managing your expenses well!'}
//             </p>
//             ${chartImage ? '<h3>Your Expense Chart:</h3><img src="cid:expense-chart" alt="Expense Chart" style="max-width: 100%; border-radius: 8px;" />' : ''}
//             <p>Contact <a href="mailto:budgetbuddy004@gmail.com">budgetbuddy004@gmail.com</a> if you have questions.</p>
//             <p>Happy budgeting,<br>The BudgetBuddy Team</p>
//             <footer style="font-size: 12px; color: #6b7280; margin-top: 20px;">© 2025 BudgetBuddy.</footer>
//           </div>
//         `,
//         attachments: chartImage
//           ? [{
//               filename: 'expense-chart.png',
//               content: Buffer.from(chartImage.split(',')[1], 'base64'),
//               cid: 'expense-chart',
//             }]
//           : [],
//       };

//       await transporter.sendMail(mailOptions);
      
//     }

//     // Decrypt for response
//     const decryptedSalary = decrypt(user.salary);
//     const decryptedExpenses = user.expenses.map(exp => ({
//       id: exp.id,
//       expenses: JSON.parse(decrypt(exp.expenses)), // Decrypt and parse back to object
//       date: exp.date,
//     }));
//     const decryptedLastImageContent = user.lastImageContent ? decrypt(user.lastImageContent) : '';

//     res.json({
//       username: user.username,
//       email: user.email,
//       salary: decryptedSalary,
//       expenses: decryptedExpenses,
//       lastImageContent: decryptedLastImageContent,
//       message: 'Profile updated successfully',
//     });
//   } catch (error) {
//     console.error('Profile update error:', error);
//     res.status(500).json({ message: 'Server error', error: error.message });
//   }
// });
router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { salary, expenses, lastImageContent, chartImage } = req.body;
    console.log('Request body:', { salary, expenses, lastImageContent, chartImage }); // Log incoming data

    const updates = {};

    // Encrypt fields for database storage
    if (salary !== undefined && salary !== null) {
      updates.salary = encrypt(salary.toString());
    }
    if (expenses !== undefined) {
      updates.expenses = expenses.map(exp => ({
        id: exp.id,
        expenses: encrypt(JSON.stringify(exp.expenses)),
        date: new Date(exp.date),
      }));
      console.log('Encrypted expenses for DB:', updates.expenses); // Log before saving
    }
    if (lastImageContent !== undefined) {
      updates.lastImageContent = encrypt(lastImageContent);
    }

    console.log('Updates to apply:', updates); // Log updates object

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updates }, // Use $set to ensure only specified fields are updated
      { new: true, runValidators: true } // Return updated doc and enforce schema validation
    ).select('-password');

    if (!user) {
      console.log('User not found for ID:', req.user.id);
      return res.status(404).json({ message: 'User not found' });
    }

    console.log('Updated user from DB:', user); // Log the updated user

    // Send email notification if expenses are provided
    if (expenses && expenses.length > 0) {
      const latestExpense = expenses[expenses.length - 1].expenses;
      const totalDeduction = Object.values(latestExpense).reduce((sum, val) => sum + val, 0);
      const plainSalary = salary !== undefined && salary !== null ? salary : decrypt(user.salary);
      const isHighExpended = totalDeduction > parseFloat(plainSalary) * 0.5;

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'BudgetBuddy - Your Latest Expense Update',
        html: `
          <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f9fafb; border-radius: 10px;">
            <h2 style="color: #1e3a8a;">Expense Update from BudgetBuddy</h2>
            <p>Hello ${user.username},</p>
            <p>You’ve just saved new expenses. Here’s the breakdown:</p>
            <ul style="list-style-type: disc; padding-left: 20px;">
              ${Object.entries(latestExpense)
                .map(([cat, amt]) => `<li>${cat}: ₹${amt.toFixed(2)}</li>`)
                .join('')}
            </ul>
            <p>Total Deduction: ₹${totalDeduction.toFixed(2)}</p>
            <p>Remaining Salary: ₹${parseFloat(plainSalary).toFixed(2)}</p>
            <p style="color: ${isHighExpended ? '#dc2626' : '#16a34a'}; font-weight: bold;">
              ${isHighExpended ? 'High Expenditure Warning: You’ve spent over 50% of your salary!' : 'You’re managing your expenses well!'}
            </p>
            ${chartImage ? '<h3>Your Expense Chart:</h3><img src="cid:expense-chart" alt="Expense Chart" style="max-width: 100%; border-radius: 8px;" />' : ''}
            <p>Contact <a href="mailto:budgetbuddy004@gmail.com">budgetbuddy004@gmail.com</a> if you have questions.</p>
            <p>Happy budgeting,<br>The BudgetBuddy Team</p>
            <footer style="font-size: 12px; color: #6b7280; margin-top: 20px;">© 2025 BudgetBuddy.</footer>
          </div>
        `,
        attachments: chartImage
          ? [{
              filename: 'expense-chart.png',
              content: Buffer.from(chartImage.split(',')[1], 'base64'),
              cid: 'expense-chart',
            }]
          : [],
      };

      await transporter.sendMail(mailOptions);
      console.log('Expense update email sent to:', user.email);
    }

    // Decrypt for response
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
    console.error('Profile update error:', error.stack); // Include stack trace for better debugging
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Process Expenses with Gemini
router.post('/expenses/gemini', authenticateToken, async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) return res.status(400).json({ message: 'Image data is required' });

    const imgBuffer = Buffer.from(image, 'base64');
    const result = await model.generateContent([
      {
        inlineData: {
          data: imgBuffer.toString('base64'),
          mimeType: 'image/png',
        },
      },
    ]);

    const text = result.response.text();
    

    const expenseMatches = text.matchAll(/\$?(\d+\.?\d{0,2})\s*\(?([A-Za-z]+)\)?|([A-Za-z]+)\s*\$?(\d+\.?\d{0,2})/g);
    const expenses = {};
    let totalAmount = 0;
    const expenseLines = [];

    for (const match of expenseMatches) {
      let category, amount;
      if (match[1] && match[2]) {
        amount = parseFloat(match[1]);
        category = match[2];
      } else if (match[3] && match[4]) {
        category = match[3];
        amount = parseFloat(match[4]);
      }
      if (category && amount) {
        category = category.charAt(0).toUpperCase() + category.slice(1).toLowerCase();
        expenses[category] = (expenses[category] || 0) + amount;
        totalAmount += amount;
        expenseLines.push(`${category} ₹${amount.toFixed(2)}`);
      }
    }

    const extractedText = expenseLines.join(', ');

    if (Object.keys(expenses).length === 0) {
      return res.status(400).json({ message: 'No valid expense data found in the image' });
    }

    res.json({
      extractedText: extractedText || text,
      expenses,
      totalAmount,
    });
  } catch (error) {
    console.error('Gemini API error:', error);
    res.status(500).json({ message: 'Failed to process image', error: error.message });
  }
});
router.post('/assistant', authenticateToken, async (req, res) => {
  try {
    const { message, salary, expensesList } = req.body;
    if (!message) return res.status(400).json({ message: 'Message is required' });

    // Construct context for the assistant
    const context = `
      You are a personal finance assistant for BudgetBuddy. The user's current salary is ₹${salary}. 
      Their saved expenses are: ${
        expensesList.length > 0
          ? expensesList.map(exp => `${exp.id}: ${JSON.stringify(exp.expenses)}`).join(', ')
          : 'None'
      }. Provide concise, actionable financial advice based on this data and the user's question: "${message}"
    `;

    const result = await model.generateContent([context]);
    const responseText = result.response.text();

    res.json({ response: responseText });
  } catch (error) {
    console.error('Assistant API error:', error);
    res.status(500).json({ message: 'Failed to get assistant response', error: error.message });
  }
});
module.exports = router;