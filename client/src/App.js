// client/src/App.js - FULL CODE
import React, { useState } from 'react';
import { BrowserRouter as Router, Route, Routes, Link, useLocation } from 'react-router-dom'; // ADDED useLocation
import axios from 'axios';
import TrafficAnalysis from './components/TrafficAnalysis';
import SearchIP from './components/SearchIP';
import BlockedList from './components/BlockedList';
import './App.css'; 

const API_BASE_URL = 'https://distributed-denial-of-service-ddos.onrender.com/api';

const App = () => {
  const [message, setMessage] = useState('');

  const handleBlock = async (ip, reason, isUnblock = false) => {
    setMessage('');
    const endpoint = isUnblock ? 'unblock_ip' : 'block_ip';
    const body = isUnblock ? { ip } : { ip, reason };
    
    try {
      const response = await axios.post(`${API_BASE_URL}/${endpoint}`, body);
      if (response.data.success) {
        setMessage({ 
          text: response.data.message, 
          type: isUnblock ? 'safe' : 'ddos' 
        });
      } else {
        setMessage({ 
          text: response.data.message, 
          type: 'warning' 
        });
      }
    } catch (error) {
      setMessage({ text: `Failed to execute action on IP ${ip}.`, type: 'ddos' });
      console.error(error);
    }
  };
  
  // MODIFIED Header Component
  const Header = () => {
    const location = useLocation(); // Get the current path

    const isActive = (path) => location.pathname === path ? ' active-link' : '';

    return (
      <nav className="navbar">
        <h1 className="navbar-brand">
        DDoS Mitigation
        </h1>
        <div className="nav-links">
          <Link to="/" className={`nav-link${isActive('/')}`}>
            Traffic Analysis
          </Link>
          <Link to="/search" className={`nav-link${isActive('/search')}`}>
            Search IP Risk
          </Link>
          <Link to="/blocked" className={`nav-link${isActive('/blocked')}`}>
            Blocked IPs
          </Link>
        </div>
      </nav>
    );
  };
  
  const MessageBar = () => {
    if (!message) return null;
    return (
      <div 
        className={`card`} 
        style={{ 
          textAlign: 'center', 
          margin: '10px auto', 
          maxWidth: '600px', 
          fontWeight: 'bold',
          padding: '15px',
          color: message.type === 'ddos' ? 'var(--color-danger)' : (message.type === 'safe' ? 'var(--color-primary)' : 'var(--color-warning)'),
          borderLeftColor: message.type === 'ddos' ? 'var(--color-danger)' : (message.type === 'safe' ? 'var(--color-primary)' : 'var(--color-warning)')
        }}
      >
        {message.text}
      </div>
    );
  }

  return (
    <Router>
      <Header />
      <div className="dashboard-container">
        <MessageBar />
        <Routes>
          <Route path="/" element={<TrafficAnalysis handleBlock={handleBlock} />} />
          <Route path="/search" element={<SearchIP handleBlock={handleBlock} />} />
          <Route path="/blocked" element={<BlockedList handleBlock={handleBlock} />} />
        </Routes>
      </div>
    </Router>
  );
};

export default App;