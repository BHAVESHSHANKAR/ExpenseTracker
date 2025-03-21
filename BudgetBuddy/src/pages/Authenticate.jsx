import React, { useState } from 'react';
import '../styles/Authenticate.css';
import logo from '../assets/icon.png';
import loginImage from '../assets/login.png';
import signupImage from '../assets/signup.png';
import { Mail, Lock, User, CheckCircle, Sun, Moon, Eye, EyeOff, Home } from 'lucide-react'; // Added Home icon
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Authenticate() {
  const navigate = useNavigate();
  const [isLogin, setIsLogin] = useState(true);
  const [otpSent, setOtpSent] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    username: '',
    otp: '',
    role: 'Student',
  });

  const handleToggle = () => {
    setIsLogin(!isLogin);
    setOtpSent(false);
  };

  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const showToastNotification = (message) => {
    setToastMessage(message);
    setShowToast(true);
    setTimeout(() => setShowToast(false), 5000);
  };

  const handleSendOtp = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/send-otp`, {
        email: formData.email,
      });
      showToastNotification(`OTP sent to ${formData.email}. Check your inbox folder.`);
      setOtpSent(true);
    } catch (error) {
      showToastNotification(error.response?.data?.message || 'Error sending OTP');
      console.error('Send OTP error:', error.response || error);
    } finally {
      setLoading(false);
    }
  };

  const handleSignupSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/signup`, {
        username: formData.username,
        email: formData.email,
        password: formData.password,
        role: formData.role,
        otp: formData.otp,
      });
      
      localStorage.setItem('token', response.data.token);
      
      showToastNotification(response.data.message);
      navigate('/userhome', { replace: true });
    } catch (error) {
      showToastNotification(error.response?.data?.message || 'Error during signup');
      console.error('Signup error:', error.response || error);
    } finally {
      setLoading(false);
    }
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/login`, {
        email: formData.email,
        password: formData.password,
      });
      localStorage.setItem('token', response.data.token);
      showToastNotification(response.data.message);
      navigate('/userhome', { replace: true });
    } catch (error) {
      console.error('Login error:', error.response || error);
      showToastNotification(error.response?.data?.message || 'Error logging in');
    } finally {
      setLoading(false);
    }
  };

  const handleBackToHome = () => {
    navigate('/'); 
  };

  return (
    <div className={`auth-container ${isDarkMode ? 'dark' : ''}`}>
      <div className="dark-mode-toggle" onClick={toggleDarkMode}>
        {isDarkMode ? <Sun className="mode-icon" size={24} /> : <Moon className="mode-icon" size={24} />}
      </div>
      <div className="auth-header slide-left">
        <img src={logo} alt="BudgetBuddy Logo" className="auth-logo" />
        <h1>BudgetBuddy</h1>
      </div>
      <div className="auth-toggle slide-left">
        <button className={`toggle-btn ${isLogin ? 'active' : ''}`} onClick={handleToggle}>
          Login
        </button>
        <button className={`toggle-btn ${!isLogin ? 'active' : ''}`} onClick={handleToggle}>
          Signup
        </button>
      </div>
      <div className="auth-content">
        {isLogin ? (
          <div className="auth-form login-form">
            <img src={loginImage} alt="Login" className="auth-image slide-right" />
            <div className="form-wrapper slide-left">
              <h2>Login</h2>
              <form onSubmit={handleLoginSubmit}>
                <div className="input-group">
                  <Mail className="input-icon" size={20} />
                  <input
                    type="email"
                    name="email"
                    placeholder="Email"
                    value={formData.email}
                    onChange={handleInputChange}
                    required
                    disabled={loading}
                  />
                </div>
                <div className="input-group">
                  <Lock className="input-icon" size={20} />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    name="password"
                    placeholder="Password"
                    value={formData.password}
                    onChange={handleInputChange}
                    required
                    disabled={loading}
                  />
                  <span className="password-toggle" onClick={togglePasswordVisibility}>
                    {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                  </span>
                </div>
                <button type="submit" className="auth-btn" disabled={loading}>
                  {loading ? 'Loading...' : 'Login'}
                </button>
              </form>
              <p className="auth-link">
                Don’t have an account?{' '}
                <span className="link" onClick={handleToggle}>
                  Create Account
                </span>
              </p>
            </div>
          </div>
        ) : (
          <div className="auth-form signup-form">
            <img src={signupImage} alt="Signup" className="auth-image slide-right" />
            <p>When you get OTP Chek you otp in email in Spam option</p>
              <p>Trust us! its not a Spam we have error on Our End</p>
            <div className="form-wrapper slide-left">
              <h2>Signup</h2>
              <form onSubmit={otpSent ? handleSignupSubmit : handleSendOtp}>
                <div className="input-group">
                  <User className="input-icon" size={20} />
                  <input
                    type="text"
                    name="username"
                    placeholder="Username"
                    value={formData.username}
                    onChange={handleInputChange}
                    required
                    disabled={otpSent || loading}
                  />
                </div>
                <div className="input-group">
                  <Mail className="input-icon" size={20} />
                  <input
                    type="email"
                    name="email"
                    placeholder="Email"
                    value={formData.email}
                    onChange={handleInputChange}
                    required
                    disabled={otpSent || loading}
                  />
                </div>
                <div className="input-group">
                  <Lock className="input-icon" size={20} />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    name="password"
                    placeholder="Password"
                    value={formData.password}
                    onChange={handleInputChange}
                    required
                    disabled={otpSent || loading}
                  />
                  <span className="password-toggle" onClick={togglePasswordVisibility}>
                    {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                  </span>
                </div>
                {otpSent && (
                  <>
                    <p className="otp-sent-message">OTP sent to: {formData.email}</p>
                    <div className="input-group slide-left">
                      <CheckCircle className="input-icon" size={20} />
                      <input
                        type="text"
                        name="otp"
                        placeholder="Enter OTP from email"
                        value={formData.otp}
                        onChange={handleInputChange}
                        required
                        disabled={loading}
                      />
                    </div>
                  </>
                )}
                <div className="input-group">
                  <select
                    name="role"
                    value={formData.role}
                    onChange={handleInputChange}
                    className="role-select"
                    disabled={otpSent || loading}
                  >
                    <option value="Student">Student</option>
                    <option value="Professor">Business Man</option>
                    <option value="Employer">Employee</option>
                    <option value="Other">Other</option>
                  </select>
                </div>
                <button type="submit" className="auth-btn" disabled={loading || (otpSent && !formData.otp)}>
                  {loading ? 'Loading...' : otpSent ? 'Verify & Signup' : 'Send OTP'}
                </button>
              </form>
              <p className="auth-link">
                Already have an account?{' '}
                <span className="link" onClick={handleToggle}>
                  Login
                </span>
              </p>
            </div>
          </div>
        )}
      </div>
      {/* Back to Home Button */}
      <div className="auth-footer">
        <button className="auth-back-btn" onClick={handleBackToHome} disabled={loading}>
          <Home size={20} style={{ marginRight: '8px' }} /> Back to Home
        </button>
      </div>
      {showToast && <div className="auth-toast">{toastMessage}</div>}
      {loading && (
        <div className="auth-loader">
          <div className="spinner"></div>
        </div>
      )}
    </div>
  );
}
export default Authenticate;