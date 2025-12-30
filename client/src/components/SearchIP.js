// client/src/components/SearchIP.js
import React, { useState } from 'react';
import axios from 'axios';
import '../App.css'; 

const API_BASE_URL = 'https://distributed-denial-of-service-ddos.onrender.com/api';

const SearchIP = ({ handleBlock }) => {
  const [ip, setIp] = useState('');
  const [ipData, setIpData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!ip) return;
    setLoading(true);
    setIpData(null);
    setError('');

    try {
      const response = await axios.post(`${API_BASE_URL}/ip_risk`, { ip });
      setIpData(response.data);
    } catch (err) {
      setError("Error finding IP or invalid format.");
      setIpData(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="search-ip">
      <h2>🔍 Search IP Risk & Block</h2>
      
      <form onSubmit={handleSearch} className="input-group" style={{display: 'flex', alignItems: 'center'}}>
        <input 
          type="text" 
          placeholder="Enter IP Address (e.g., 203.0.113.42)" 
          value={ip} 
          onChange={(e) => setIp(e.target.value)} 
          required
        />
        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? 'Analyzing...' : 'Analyze IP'}
        </button>
      </form>

      {error && <p className="status-ddos" style={{ marginTop: '20px' }}>{error}</p>}
      
      {ipData && (
        <div className="card" style={{ marginTop: '30px' }}>
          <h3>Analysis for: {ipData.ip}</h3>
          
          <div style={{ marginBottom: '15px' }}>
            <p>
              Current Status:{" "}
              <span className={ipData.status === 'Blocked' ? 'status-ddos' : 'status-safe'}>
                <strong>{ipData.status}</strong>
              </span>
            </p>
            <p>
              Recommendation:{" "}
              <span className={ipData.risk > 90 ? 'status-ddos' : 'status-warning'}>
                <strong>{ipData.ddos_type || 'Normal Traffic'}</strong>
              </span>
            </p>
          </div>

          {/* Manual Blocking/Unblocking Action */}
          <div style={{ textAlign: 'right' }}>
            {ipData.status !== 'Blocked' ? (
              <button 
                className="btn btn-danger" 
                onClick={() => handleBlock(ipData.ip, `Manual Search: ${ipData.ddos_type || 'Normal Traffic'}`)}
              >
                Manual Block IP
              </button>
            ) : (
              <button 
                className="btn btn-primary" 
                onClick={() => handleBlock(ipData.ip, null, true)} 
                style={{ backgroundColor: '#2e7d32' }} 
              >
                Unblock IP
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SearchIP;
