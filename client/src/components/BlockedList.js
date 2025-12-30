// client/src/components/BlockedList.js
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import '../App.css'; 

const API_BASE_URL = 'https://distributed-denial-of-service-ddos.onrender.com/api';

const BlockedList = ({ handleBlock }) => {
  const [blockedList, setBlockedList] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchBlockedList = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/blocked_list`);
      // Sort by time blocked (most recent first)
      const sortedList = response.data.sort((a, b) => b.time - a.time);
      setBlockedList(sortedList);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching blocked IPs:", error);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBlockedList();
    const interval = setInterval(fetchBlockedList, 10000); // Refresh list every 10s
    return () => clearInterval(interval);
  }, []);

  if (loading) return <h3 className="status-safe">Loading Blocked List...</h3>;
  
  return (
    <div className="blocked-list">
      <h2>Currently Blocked IP Addresses ({blockedList.length})</h2>
      
      {blockedList.length === 0 ? (
        <p className="card status-safe" style={{borderLeftColor: 'var(--color-primary)'}}>No IPs are currently blocked. System is clear.</p>
      ) : (
        <div className="card" style={{borderLeftColor: 'var(--color-danger)'}}>
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Blocked Reason</th>
                <th>Blocked Time</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {blockedList.map((item) => (
                <tr key={item.ip}>
                  <td className="status-ddos">{item.ip}</td>
                  <td>{item.reason}</td>
                  <td>{new Date(item.time * 1000).toLocaleString()}</td>
                  <td>
                    <button 
                      className="btn btn-primary" 
                      onClick={() => handleBlock(item.ip, null, true)} 
                      style={{ backgroundColor: '#2e7d32' }} 
                    >
                      Unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default BlockedList;