import React, { useState, useEffect, useRef } from 'react';
import '../styles/Profile.css';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import Chart from 'chart.js/auto';

function Profile() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [salary, setSalary] = useState('');
  const [editedSalary, setEditedSalary] = useState('');
  const [expensesList, setExpensesList] = useState([]);
  const [lastImageContent, setLastImageContent] = useState('');
  const [chartInstance, setChartInstance] = useState(null);
  const [isEditingSalary, setIsEditingSalary] = useState(false);
  const navigate = useNavigate();
  const chartRef = useRef(null);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/authenticate', { replace: true });
      return;
    }

    const fetchProfile = async () => {
      try {
        const response = await axios.get(`${import.meta.env.VITE_API_URL}/api/auth/profile`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setUsername(response.data.username);
        setEmail(response.data.email);
        setSalary(response.data.salary || '0');
        setEditedSalary(response.data.salary || '0');
        setExpensesList(response.data.expenses || []);
        setLastImageContent(response.data.lastImageContent || '');
        updateChart(response.data.expenses || []);
      } catch (error) {
        console.error('Error fetching profile:', error.response?.data || error.message);
        if (error.response?.status === 401 || error.response?.status === 403) {
          localStorage.removeItem('token');
          navigate('/authenticate', { replace: true });
        } else {
          // alert('Failed to load profile data. Please try again.');
        }
      }
    };

    fetchProfile();
  }, [navigate]);

  const updateChart = (expenses) => {
    if (!chartRef.current) return;

    if (chartInstance) chartInstance.destroy();

    const aggregatedExpenses = {};
    expenses.forEach(expense => {
      Object.entries(expense.expenses).forEach(([category, amount]) => {
        aggregatedExpenses[category] = (aggregatedExpenses[category] || 0) + amount;
      });
    });

    const ctx = chartRef.current.getContext('2d');
    const newChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: Object.keys(aggregatedExpenses),
        datasets: [{
          label: 'Total Expenses (₹)',
          data: Object.values(aggregatedExpenses),
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
  };

  const handleSaveSalary = async () => {
    const token = localStorage.getItem('token');
    try {
      const response = await axios.put(
        `${import.meta.env.VITE_API_URL}/api/auth/profile`,
        { salary: editedSalary },
        { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
      );
      setSalary(response.data.salary);
      setIsEditingSalary(false);
      alert('Salary updated successfully!');
    } catch (error) {
      console.error('Error updating salary:', error.response?.data || error.message);
      alert('Failed to update salary.');
    }
  };

  const handleResetExpenses = async () => {
    if (!window.confirm('Are you sure you want to reset all expenses? This cannot be undone.')) return;

    const token = localStorage.getItem('token');
    try {
      const response = await axios.put(
        `${import.meta.env.VITE_API_URL}/api/auth/profile`,
        { expenses: [], salary: editedSalary, lastImageContent: '' },
        { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
      );
      setExpensesList([]);
      setSalary(response.data.salary);
      setLastImageContent('');
      if (chartInstance) chartInstance.destroy();
      setChartInstance(null);
      alert('Expenses reset successfully!');
    } catch (error) {
      console.error('Error resetting expenses:', error.response?.data || error.message);
      alert('Failed to reset expenses.');
    }
  };

  const handleBack = () => navigate('/userhome');

  return (
    <div className="profile-container">
      <h1>Profile</h1>
      <div className="profile-details">
        <p><strong>Username:</strong> {username || 'N/A'}</p>
        <p><strong>Email:</strong> {email || 'N/A'}</p>
        <div className="profile-salary">
          <strong>Remaining Salary:</strong>
          {isEditingSalary ? (
            <div className="profile-salary-edit">
              <input
                type="number"
                value={editedSalary}
                onChange={(e) => setEditedSalary(e.target.value)}
                className="profile-salary-input"
                min="0"
                step="0.01"
              />
              <button onClick={handleSaveSalary} className="profile-save-salary-button">Save</button>
              <button onClick={() => setIsEditingSalary(false)} className="profile-cancel-button">Cancel</button>
            </div>
          ) : (
            <span>
              ₹{parseFloat(salary || 0).toFixed(2)}
              <button onClick={() => setIsEditingSalary(true)} className="profile-edit-salary-button">Edit</button>
            </span>
          )}
        </div>
        <div className="profile-expenses">
          <h3>Saved Expenses</h3>
          {expensesList.length > 0 ? (
            expensesList.map((expense, index) => (
              <div key={index} className="profile-expense-entry">
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
        {lastImageContent && (
          <div className="profile-image-content">
            <h3>Last Processed Image Content</h3>
            <p>{lastImageContent}</p>
          </div>
        )}
        <div className="profile-chart-container">
          <canvas ref={chartRef} className="profile-chart"></canvas>
        </div>
        <button onClick={handleResetExpenses} className="profile-reset-button">Reset All Expenses</button>
      </div>
      <button onClick={handleBack} className="profile-back-button">Back to Home</button>
    </div>
  );
}

export default Profile;