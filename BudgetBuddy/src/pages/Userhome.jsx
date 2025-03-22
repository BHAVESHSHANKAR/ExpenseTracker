import React, { useState, useEffect, useRef } from 'react';
import '../styles/Userhome.css';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { User, LogOut, MessageSquare } from 'lucide-react'; // Added MessageSquare for assistant icon
import Chart from 'chart.js/auto';
import homeImage from '../assets/userhome.png';
import logo from '../assets/icon.png';

function Userhome() {
  const [username, setUsername] = useState('');
  const [profilePicture, setProfilePicture] = useState(null);
  const [salary, setSalary] = useState('');
  const [expensesList, setExpensesList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');

  // Image-based expense tracker states
  const [imageData, setImageData] = useState(null);
  const [extractedText, setExtractedText] = useState('');
  const [tempExpenses, setTempExpenses] = useState(null);
  const [chartInstance, setChartInstance] = useState(null);
  const [isProcessingImage, setIsProcessingImage] = useState(false);
  const [isSavingImage, setIsSavingImage] = useState(false);
  const chartRef = useRef(null);
  const fileInputRef = useRef(null);

  // Manual expense entry states
  const [manualExpenseName, setManualExpenseName] = useState('');
  const [manualExpenseValue, setManualExpenseValue] = useState('');
  const [manualExpenses, setManualExpenses] = useState({});
  const [manualChartInstance, setManualChartInstance] = useState(null);
  const [isSavingManual, setIsSavingManual] = useState(false);
  const manualChartRef = useRef(null);

  // Personal Assistant states
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [isChatLoading, setIsChatLoading] = useState(false);

  const navigate = useNavigate();

  const showToastNotification = (message, duration = 3000) => {
    setToastMessage(message);
    setShowToast(true);
    setTimeout(() => setShowToast(false), duration);
  };

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      
      navigate('/authenticate', { replace: true });
      return;
    }

    const fetchUserData = async () => {
      try {
        const response = await axios.get(`${import.meta.env.VITE_API_URL}/api/auth/profile`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setUsername(response.data.username);
        setProfilePicture(response.data.picture || null);
        setSalary(response.data.salary || '0');
        setExpensesList(response.data.expenses || []);
        setExtractedText(response.data.lastImageContent || '');
        setLoading(false);
      } catch (error) {
        console.error('Error fetching user data:', error.response?.data || error.message);
        if (error.response?.status === 401 || error.response?.status === 403) {
          localStorage.removeItem('token');
          navigate('/authenticate', { replace: true });
        } else {
          showToastNotification('Failed to load user data. Please try again.');
        }
      }
    };

    fetchUserData();
  }, [navigate]);

  const handlePhotoUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => setImageData(reader.result.split(',')[1]);
      reader.readAsDataURL(file);
    }
  };

  const processImage = async () => {
    if (!imageData) {
      showToastNotification('Please upload an image first.');
      return;
    }

    setIsProcessingImage(true);
    const token = localStorage.getItem('token');
    try {
      const response = await axios.post(
        `${import.meta.env.VITE_API_URL}/api/auth/expenses/gemini`,
        { image: imageData },
        { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
      );
      
      setExtractedText(response.data.extractedText);
      setTempExpenses(response.data.expenses);
      showToastNotification('Image processed successfully!');
    } catch (error) {
      console.error('Error processing image:', error.response?.data || error.message);
      showToastNotification(error.response?.data?.message || 'Failed to process image.');
    } finally {
      setIsProcessingImage(false);
    }
  };

  const updateImageChart = () => {
    if (!tempExpenses || !chartRef.current) {
      showToastNotification('Process an image first to generate the chart.');
      return;
    }

    if (chartInstance) chartInstance.destroy();

    const ctx = chartRef.current.getContext('2d');
    const newChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: Object.keys(tempExpenses),
        datasets: [{
          label: 'Pending Image Expenses (₹)',
          data: Object.values(tempExpenses),
          backgroundColor: '#38bdf8',
          borderColor: '#1e3a8a',
          borderWidth: 1,
        }],
      },
      options: {
        scales: { y: { beginAtZero: true } },
        plugins: { legend: { display: false } },
        maintainAspectRatio: false,
      },
    });
    setChartInstance(newChart);
    showToastNotification('Image chart updated!');
  };

  const resetImageTracker = () => {
    setExtractedText('');
    setTempExpenses(null);
    setImageData(null);
    if (chartInstance) {
      chartInstance.destroy();
      setChartInstance(null);
    }
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const saveImageExpenses = async () => {
    if (!tempExpenses) {
      showToastNotification('Process an image first to save expenses.');
      return;
    }

    setIsSavingImage(true);
    const token = localStorage.getItem('token');
    try {
      const newExpense = {
        id: `Expense ${expensesList.length + 1}`,
        expenses: tempExpenses,
        date: new Date(),
      };
      const totalDeduction = Object.values(tempExpenses).reduce((sum, val) => sum + val, 0);
      const updatedSalary = (parseFloat(salary || 0) - totalDeduction).toFixed(2);
      const updatedExpensesList = [...expensesList, newExpense];

      const chartImage = chartInstance ? chartInstance.toBase64Image() : null;

      const response = await axios.put(
        `${import.meta.env.VITE_API_URL}/api/auth/profile`,
        { salary: updatedSalary, expenses: updatedExpensesList, lastImageContent: extractedText, chartImage },
        { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
      );
      

      setSalary(updatedSalary);
      setExpensesList(updatedExpensesList);
      resetImageTracker();
      showToastNotification('Image expenses saved! Check your email for details.');
    } catch (error) {
      console.error('Error saving image expenses:', error.response?.data || error.message);
      showToastNotification('Failed to save image expenses.');
    } finally {
      setIsSavingImage(false);
    }
  };

  const handleAddManualExpense = () => {
    if (!manualExpenseName || !manualExpenseValue) {
      showToastNotification('Please enter both an expense name and value.');
      return;
    }

    const value = parseFloat(manualExpenseValue);
    if (isNaN(value) || value <= 0) {
      showToastNotification('Please enter a valid positive expense value.');
      return;
    }

    setManualExpenses(prev => ({
      ...prev,
      [manualExpenseName]: (prev[manualExpenseName] || 0) + value,
    }));
    setManualExpenseName('');
    setManualExpenseValue('');
    showToastNotification('Manual expense added!');
  };

  const updateManualChart = () => {
    if (!Object.keys(manualExpenses).length || !manualChartRef.current) {
      showToastNotification('Add manual expenses first to generate the chart.');
      return;
    }

    if (manualChartInstance) manualChartInstance.destroy();

    const ctx = manualChartRef.current.getContext('2d');
    const newChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: Object.keys(manualExpenses),
        datasets: [{
          label: 'Pending Manual Expenses (₹)',
          data: Object.values(manualExpenses),
          backgroundColor: '#facc15',
          borderColor: '#b45309',
          borderWidth: 1,
        }],
      },
      options: {
        scales: { y: { beginAtZero: true } },
        plugins: { legend: { display: false } },
        maintainAspectRatio: false,
      },
    });
    setManualChartInstance(newChart);
    showToastNotification('Manual chart updated!');
  };

  const resetManualTracker = () => {
    setManualExpenses({});
    if (manualChartInstance) {
      manualChartInstance.destroy();
      setManualChartInstance(null);
    }
  };

  const saveManualExpenses = async () => {
    if (!Object.keys(manualExpenses).length) {
      showToastNotification('Add manual expenses first to save.');
      return;
    }

    setIsSavingManual(true);
    const token = localStorage.getItem('token');
    try {
      const newExpense = {
        id: `Expense ${expensesList.length + 1}`,
        expenses: manualExpenses,
        date: new Date(),
      };
      const totalDeduction = Object.values(manualExpenses).reduce((sum, val) => sum + val, 0);
      const updatedSalary = (parseFloat(salary || 0) - totalDeduction).toFixed(2);
      const updatedExpensesList = [...expensesList, newExpense];

      const chartImage = manualChartInstance ? manualChartInstance.toBase64Image() : null;

      const response = await axios.put(
        `${import.meta.env.VITE_API_URL}/api/auth/profile`,
        { salary: updatedSalary, expenses: updatedExpensesList, lastImageContent: extractedText, chartImage },
        { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
      );
      

      setSalary(updatedSalary);
      setExpensesList(updatedExpensesList);
      resetManualTracker();
      showToastNotification('Manual expenses saved! Check your email for details.');
    } catch (error) {
      console.error('Error saving manual expenses:', error.response?.data || error.message);
      showToastNotification('Failed to save manual expenses.');
    } finally {
      setIsSavingManual(false);
    }
  };

  const handleProfileClick = () => navigate('/profile');
  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userProfile');
    navigate('/authenticate', { replace: true });
  };

  // Personal Assistant Functions
  const toggleChat = () => {
    setIsChatOpen(!isChatOpen);
    if (!isChatOpen && chatMessages.length === 0) {
      setChatMessages([{ sender: 'bot', text: 'Hello! I’m your Finance Assistant. How can I help you today?' }]);
    }
  };

  const handleChatSubmit = async (e) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userMessage = { sender: 'user', text: chatInput };
    setChatMessages(prev => [...prev, userMessage]);
    setChatInput('');
    setIsChatLoading(true);

    const token = localStorage.getItem('token');
    try {
      const response = await axios.post(
        `${import.meta.env.VITE_API_URL}/api/auth/assistant`,
        { message: chatInput, salary, expensesList },
        { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
      );
      const botMessage = { sender: 'bot', text: response.data.response };
      setChatMessages(prev => [...prev, botMessage]);
    } catch (error) {
      console.error('Error with assistant:', error.response?.data || error.message);
      const errorMessage = { sender: 'bot', text: 'Sorry, I couldn’t process that. Please try again.' };
      setChatMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsChatLoading(false);
    }
  };

  return (
    <div className="uh-container">
      {loading && (
        <div className="uh-loader">
          <div className="spinner"></div>
        </div>
      )}
      {showToast && <div className="uh-toast">{toastMessage}</div>}
      <nav className="uh-navbar">
        <div className="uh-navbar-brand">
          <img src={logo} alt="BudgetBuddy Logo" className="uh-navbar-logo" />
          BudgetBuddy
        </div>
        <div className="uh-navbar-actions">
          <div className="uh-navbar-profile" onClick={handleProfileClick}>
            {profilePicture ? (
              <img src={profilePicture} alt="Profile" className="uh-navbar-avatar" />
            ) : (
              <User size={30} className="uh-navbar-avatar-default" />
            )}
            <span className="uh-navbar-username">{username || 'User'}</span>
          </div>
          <button className="uh-navbar-logout" onClick={handleLogout}>
            <LogOut size={20} /> Logout
          </button>
        </div>
      </nav>
      <section className="uh-content">
        <div className="uh-main">
          <div className="uh-image-container">
            <img src={homeImage} alt="Userhome" className="uh-image" />
          </div>
          <div className="uh-instructions-card">
            <h1>Welcome, {username || 'User'}!</h1>
            <p>Your personal finance journey starts here.</p>
            <div className="uh-instructions-list">
              <h2>Get Started</h2>
              <ul>
                <li>Click your profile picture to update your details.</li>
                <li>Use "Expense Tracker" to process expense images.</li>
                <li>Use "Manual Expense Entry" to add expenses manually.</li>
                <li>Personal Assitant Chat Bot.</li>
                
              </ul>
            </div>
          </div>
        </div>
        <div className="uh-expense-section">
          <div className="uh-expense-tracker">
            <h2>Expense Tracker (Image-Based)</h2>
            <p>If your listed items not shown here means Click Process Image again ☺️</p>
            <p>Remaining Salary: ₹{parseFloat(salary || 0).toFixed(2)}</p>
            <input
              type="file"
              accept="image/*"
              onChange={handlePhotoUpload}
              className="uh-upload-input"
              ref={fileInputRef}
              disabled={isProcessingImage || isSavingImage}
            />
            <div className="uh-buttons">
              <button
                onClick={processImage}
                className="uh-process-button"
                disabled={isProcessingImage || isSavingImage}
              >
                {isProcessingImage ? (
                  <span>
                    Processing <div className="spinner inline-spinner"></div>
                  </span>
                ) : (
                  'Process Image'
                )}
              </button>
              <button
                onClick={updateImageChart}
                className="uh-chart-button"
                disabled={isProcessingImage || isSavingImage}
              >
                Show Chart
              </button>
              <button
                onClick={saveImageExpenses}
                className="uh-save-button"
                disabled={isProcessingImage || isSavingImage}
              >
                {isSavingImage ? (
                  <span>
                    Saving <div className="spinner inline-spinner"></div>
                  </span>
                ) : (
                  'Save Expenses'
                )}
              </button>
            </div>
            {extractedText && (
              <div className="uh-extracted-text">
                <h3>Extracted Text</h3>
                <p>{extractedText}</p>
              </div>
            )}
            {tempExpenses && (
              <div className="uh-temp-expenses">
                <h3>Pending Image Expenses</h3>
                <ul>
                  {Object.entries(tempExpenses).map(([category, amount]) => (
                    <li key={category}>{category}: ₹{amount.toFixed(2)}</li>
                  ))}
                </ul>
              </div>
            )}
            <div className="uh-chart-container">
              <canvas ref={chartRef} className="uh-chart"></canvas>
            </div>
          </div>

          <div className="uh-manual-expense-entry">
            <h2>Manual Expense Entry</h2>
            <div className="uh-manual-inputs">
              <input
                type="text"
                placeholder="Expenditure Name"
                value={manualExpenseName}
                onChange={(e) => setManualExpenseName(e.target.value)}
                className="uh-manual-input"
                disabled={isSavingManual}
              />
              <input
                type="number"
                placeholder="Expenditure Value (₹)"
                value={manualExpenseValue}
                onChange={(e) => setManualExpenseValue(e.target.value)}
                className="uh-manual-input"
                min="0"
                step="0.01"
                disabled={isSavingManual}
              />
              <button
                onClick={handleAddManualExpense}
                className="uh-add-button"
                disabled={isSavingManual}
              >
                Add Expense
              </button>
            </div>
            {Object.keys(manualExpenses).length > 0 && (
              <div className="uh-manual-expenses">
                <h3>Pending Manual Expenses</h3>
                <ul>
                  {Object.entries(manualExpenses).map(([category, amount]) => (
                    <li key={category}>{category}: ₹{amount.toFixed(2)}</li>
                  ))}
                </ul>
              </div>
            )}
            <div className="uh-buttons">
              <button
                onClick={updateManualChart}
                className="uh-chart-button"
                disabled={isSavingManual}
              >
                Show Chart
              </button>
              <button
                onClick={saveManualExpenses}
                className="uh-save-button"
                disabled={isSavingManual}
              >
                {isSavingManual ? (
                  <span>
                    Saving <div className="spinner inline-spinner"></div>
                  </span>
                ) : (
                  'Save Expenses'
                )}
              </button>
            </div>
            <div className="uh-chart-container">
              <canvas ref={manualChartRef} className="uh-chart"></canvas>
            </div>
          </div>
        </div>

        <div className="uh-expenses-display">
          <h3>Saved Expenses</h3>
          {expensesList.length > 0 ? (
            expensesList.map((expense, index) => (
              <div key={index} className="uh-expense-entry">
                <h4>{expense.id} ({new Date(expense.date).toLocaleDateString()})</h4>
                <ul>
                  {Object.entries(expense.expenses).map(([category, amount]) => (
                    amount > 0 && <li key={category}>{category}: ₹{amount.toFixed(2)}</li>
                  ))}
                </ul>
              </div>
            ))
          ) : (
            <p>No expenses saved yet.</p>
          )}
        </div>

        {/* Personal Assistant Button */}
        <div className="uh-assistant-container">
          <button className="uh-assistant-btn" onClick={toggleChat}>
            <MessageSquare size={24} /> Finance Assistant
          </button>
        </div>

        {/* Chat Popup */}
        {isChatOpen && (
          <div className="uh-chat-popup">
            <div className="uh-chat-header">
              <h3>Finance Assistant</h3>
              <button className="uh-chat-close" onClick={toggleChat}>✖</button>
            </div>
            <div className="uh-chat-messages">
              {chatMessages.map((msg, index) => (
                <div key={index} className={`uh-chat-message ${msg.sender}`}>
                  <p>{msg.text}</p>
                </div>
              ))}
              {isChatLoading && (
                <div className="uh-chat-message bot">
                  <p>Thinking...</p>
                </div>
              )}
            </div>
            <form className="uh-chat-input" onSubmit={handleChatSubmit}>
              <input
                type="text"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder="Ask about your finances..."
                disabled={isChatLoading}
              />
              <button type="submit" disabled={isChatLoading}>Send</button>
            </form>
          </div>
        )}
      </section>
    </div>
  );
}

export default Userhome;