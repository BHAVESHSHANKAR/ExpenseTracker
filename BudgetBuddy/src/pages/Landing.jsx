import React, { useState, useEffect } from 'react';
import '../styles/Landing.css';
import logo from '../assets/icon.png';
import heroImage from '../assets/hero.png';
import feature1Image from '../assets/feature1.png';
import feature2Image from '../assets/feature2.png';
import feature3Image from '../assets/feature3.png';
import { useNavigate } from 'react-router-dom';
import { Sun, Moon } from 'lucide-react';

const LandingPage = () => {
  const [loading, setLoading] = useState(true);
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [showToast, setShowToast] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 2000);
    return () => clearTimeout(timer);
  }, []);

  const handleGetStarted = () => {
    setShowToast(true);
    setTimeout(() => {
      setShowToast(false);
      navigate('/authenticate');
    }, 500);
  };

  const toggleDarkMode = () => {
    setIsDarkMode(prev => !prev);
    document.documentElement.classList.toggle('dark-mode', !isDarkMode);
  };

  return (
    <div className={`landing-container ${isDarkMode ? 'dark-mode' : ''}`}>
      {loading && (
        <div className="loader">
          <div className="spinner"></div>
        </div>
      )}
      <header className="header">
        <div className="header-content">
          <img src={logo} alt="BudgetBuddy Logo" className="logo" />
          <h1>BudgetBuddy</h1>
          
        </div>
      </header>
      <section className="hero">
        <div className="hero-content">
          <h2>Welcome to BudgetBuddy</h2>
          <p>Your personal finance companion to track, manage, and master your ₹upees.</p>
          <button onClick={handleGetStarted} className="cta-button">
            Get Started
          </button>
        </div>
        <img src={heroImage} alt="Managing Finances" className="hero-image" />
      </section>
      <section id="about" className="about">
        <h3>About BudgetBuddy</h3>
        <p>
          Struggling to keep track of your expenses or stick to a budget? BudgetBuddy is here to help! Whether it’s rent, dining, or entertainment in ₹upees, our app keeps you in control. Upload receipt photos or log expenses manually—BudgetBuddy categorizes them (e.g., food, utilities). Set monthly limits, get overspending alerts, and visualize your spending with an intuitive dashboard. Take charge of your finances today!
        </p>
      </section>
      <section id="features" className="features">
        <h3>Why Choose BudgetBuddy?</h3>
        <div className="feature-cards">
          <div className="feature-card">
            <div className="card-header">
              <h4>Easy Receipt Upload</h4>
            </div>
            <div className="card-content">
              <img src={feature1Image} alt="Receipt Upload" className="feature-image" />
              <p>Snap a photo of your receipt to track ₹upee spending effortlessly.</p>
            </div>
          </div>
          <div className="feature-card">
            <div className="card-header">
              <h4>Real-Time Alerts</h4>
            </div>
            <div className="card-content">
              <img src={feature2Image} alt="Spending Alerts" className="feature-image" />
              <p>Get notified when you’re close to overspending your ₹upee budget.</p>
            </div>
          </div>
          <div className="feature-card">
            <div className="card-header">
              <h4>Insightful Dashboard</h4>
            </div>
            <div className="card-content">
              <img src={feature3Image} alt="Dashboard Insights" className="feature-image" />
              <p>See your ₹upee spending patterns with charts and summaries.</p>
            </div>
          </div>
        </div>
      </section>
      <footer className="footer">
        <p>Contact us: budgetbuddy004@gmail.com | © 2025 BudgetBuddy</p>
        <nav className="nav-links">
            <a href="#about">About</a>
            <a href="#features">Features</a>
            <button onClick={toggleDarkMode} className="dark-mode-toggle">
              {isDarkMode ? <Sun size={24} /> : <Moon size={24} />}
            </button>
          </nav>
      </footer>
      {showToast && (
        <div className="toast">
          <h4>Welcome aboard!</h4>
          <p>Let’s master your ₹upee budget.</p>
        </div>
      )}
    </div>
  );
};

export default LandingPage;