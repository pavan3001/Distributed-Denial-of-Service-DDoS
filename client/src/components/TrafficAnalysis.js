import React, { useState, useEffect } from 'react';
import axios from 'axios';
import '../App.css'; 

const API_BASE_URL = 'http://127.0.0.1:5000/api';

// Helper function for BPS Formatting
const formatBPS = (bps) => {
    if (bps < 1000) return `${bps.toFixed(0)} BPS`;
    if (bps < 1000000) return `${(bps / 1000).toFixed(2)} kbps`;
    if (bps < 1000000000) return `${(bps / 1000000).toFixed(2)} Mbps`;
    return `${(bps / 1000000000).toFixed(2)} Gbps`;
};

const TrafficAnalysis = ({ handleBlock }) => {
  const [trafficData, setTrafficData] = useState({});
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/analyze_traffic`);
      setTrafficData(response.data);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching traffic data. Is Flask server running?", error);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000); 
    return () => clearInterval(interval); 
  }, []);

  const handleMonitoringControl = async (action) => {
    try {
        await axios.post(`${API_BASE_URL}/monitoring/control`, { action });
        fetchData(); 
    } catch (error) {
        console.error(`Failed to execute ${action} monitoring.`, error);
    }
  };

  if (loading) return <h3 className="status-safe">Loading Real-Time Data...</h3>;

  const { total_packets, inbound_rate, top_source_ips, system_status, blocked_count, monitoring_status } = trafficData;
  const isMonitoringActive = monitoring_status === 'Active';

  const getStatusClass = (status) => {
    if (status === 'DDoS Attack' || status === 'Blocked') return 'status-danger';
    if (status === 'Monitored' || status === 'HIGH ALERT' || status === 'WARNING') return 'status-warning';
    return 'status-safe'; 
  };
  
  // Separate ALL IPs into three categories
  const all_ips = top_source_ips ? top_source_ips.sort((a, b) => b.risk - a.risk) : [];
  
  const highRiskIps = all_ips.filter(ip => ip.risk >= 90);
  const monitoringChamberIps = all_ips.filter(ip => ip.risk >= 50 && ip.risk < 90);
  const normalIps = all_ips.filter(ip => ip.risk < 50); 


  return (
    <div className="traffic-analysis">
      <h2>Real-Time Traffic Analysis</h2>

      {/* --- Dashboard Cards --- */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '30px' }}>
        
        <div className="card" style={{ borderLeftColor: isMonitoringActive ? 'var(--color-primary)' : 'var(--color-danger)' }}>
            <h3>Monitoring Status</h3>
            <p className={isMonitoringActive ? 'status-safe' : 'status-danger'} style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>
              {isMonitoringActive ? 'ACTIVE' : 'STOPPED'}
            </p>
            <div style={{marginTop: '10px'}}>
                {isMonitoringActive ? (
                    <button className="btn btn-danger" onClick={() => handleMonitoringControl('stop')}>Stop Monitoring</button>
                ) : (
                    <button className="btn btn-primary" onClick={() => handleMonitoringControl('start')}>Start Monitoring</button>
                )}
            </div>
        </div>
        
        <div className="card" style={{ borderLeftColor: system_status === 'HIGH ALERT' ? 'var(--color-danger)' : (system_status === 'WARNING' ? 'var(--color-warning)' : 'var(--color-primary)') }}>
          <h3>System Status</h3>
          <p className={getStatusClass(system_status)} style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>
            {system_status}
          </p>
        </div>
        
        <div className="card">
          <h3>Inbound Rate (P/s)</h3>
          <p style={{ fontSize: '1.5rem' }} className={inbound_rate > 100 ? 'status-danger' : 'status-safe'}>
            {inbound_rate ? inbound_rate.toFixed(2) : 0}
          </p>
        </div>
        
        <div className="card" style={{ borderLeftColor: blocked_count > 0 ? 'var(--color-danger)' : 'var(--color-primary)' }}>
          <h3>Blocked IPs</h3>
          <p className="status-danger" style={{ fontSize: '1.5rem' }}>{blocked_count}</p>
        </div>
      </div>
      
      {/* 2. High Risk DDoS Attackers (90%+ Risk) */}
      <div className="card" style={{ marginBottom: '15px', borderLeftColor: highRiskIps.length > 0 ? 'var(--color-danger)' : 'var(--color-primary)' }}>
        <h3>Confirmed DDoS Attackers ({highRiskIps.length})</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Status</th>
              <th>Risk</th>
              <th>DDoS Type</th>
              <th>Packet Type</th>
              <th>PPS Rate</th>
              <th>BPS Rate</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {highRiskIps.length === 0 ? (
                <tr><td colSpan="8" style={{ textAlign: 'center', color: 'var(--color-text-dim)' }}>No IPs currently at DDoS threshold (90%+ risk).</td></tr>
            ) : (
                highRiskIps.map((ip) => (
                    <tr key={ip.ip}>
                        <td>{ip.ip}</td>
                        <td className={getStatusClass(ip.status)}>{ip.status}</td>
                        <td>
                            <span style={{ marginRight: '10px' }}>{ip.risk}%</span>
                            <div className="risk-bar"><div className="risk-level" data-risk-level='high' style={{ width: `${ip.risk}%` }}></div></div>
                        </td>
                        <td>{ip.ddos_type || 'N/A'}</td> 
                        <td>{ip.packet_type || 'N/A'}</td> 
                        <td>{ip.pps ? ip.pps.toFixed(1) : 0}</td>
                        <td>{ip.bps ? formatBPS(ip.bps) : '0 BPS'}</td>
                        <td>
                            {ip.status !== 'Blocked' && (
                                <button className="btn btn-danger" onClick={() => handleBlock(ip.ip, `Auto-Block: Risk ${ip.risk}%`)}>Block</button>
                            )}
                            {ip.status === 'Blocked' && (
                                <button className="btn btn-primary" onClick={() => handleBlock(ip.ip, null, true)} style={{ backgroundColor: '#2e7d32' }}>Unblock</button>
                            )}
                        </td>
                    </tr>
                ))
            )}
          </tbody>
        </table>
      </div>
      
      {/* 3. Monitoring Chamber (50%-89% Risk) */}
      <div className="card" style={{ marginBottom: '15px', borderLeftColor: monitoringChamberIps.length > 0 ? 'var(--color-warning)' : 'var(--color-primary)' }}>
        <h3>Monitoring Chamber ({monitoringChamberIps.length})</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Status</th>
              <th>Risk</th>
              <th>DDoS Type</th>
              <th>Packet Type</th>
              <th>PPS Rate</th>
              <th>BPS Rate</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {monitoringChamberIps.length === 0 ? (
                <tr><td colSpan="8" style={{ textAlign: 'center', color: 'var(--color-text-dim)' }}>No IPs require close monitoring (50%-89% risk).</td></tr>
            ) : (
                monitoringChamberIps.map((ip) => (
                    <tr key={ip.ip}>
                        <td>{ip.ip}</td>
                        <td className={getStatusClass(ip.status)}>{ip.status}</td>
                        <td>
                            <span style={{ marginRight: '10px' }}>{ip.risk}%</span>
                            <div className="risk-bar"><div className="risk-level" data-risk-level='medium' style={{ width: `${ip.risk}%` }}></div></div>
                        </td>
                        <td>{ip.ddos_type || 'N/A'}</td>
                        <td>{ip.packet_type || 'N/A'}</td>
                        <td>{ip.pps ? ip.pps.toFixed(1) : 0}</td>
                        <td>{ip.bps ? formatBPS(ip.bps) : '0 BPS'}</td>
                        <td>
                            {ip.status !== 'Blocked' && (
                                <button className="btn btn-danger" onClick={() => handleBlock(ip.ip, `Manual Monitor Block: Risk ${ip.risk}%`)}>Block</button>
                            )}
                            {ip.status === 'Blocked' && (
                                <button className="btn btn-primary" onClick={() => handleBlock(ip.ip, null, true)} style={{ backgroundColor: '#2e7d32' }}>Unblock</button>
                            )}
                        </td>
                    </tr>
                ))
            )}
          </tbody>
        </table>
      </div>
      
      {/* 4. Normal Traffic (Below 50% Risk) */}
      <div className="card" style={{ borderLeftColor: normalIps.length > 0 ? 'var(--color-primary)' : 'var(--color-text-dim)' }}>
        <h3>Normal Traffic ({normalIps.length})</h3>
        <table className="data-table">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Packet Type</th>
                    <th>PPS Rate</th>
                    <th>BPS Rate</th>
                </tr>
            </thead>
            <tbody>
                {normalIps.length === 0 ? (
                    <tr><td colSpan="6" style={{ textAlign: 'center', color: 'var(--color-text-dim)' }}>No low-risk traffic detected in the current window.</td></tr>
                ) : (
                    normalIps.map((ip) => (
                        <tr key={ip.ip}>
                            <td>{ip.ip}</td>
                            <td className={getStatusClass(ip.status)}>{ip.status}</td>
                            <td>
                                <span style={{ marginRight: '10px' }}>{ip.risk}%</span>
                                <div className="risk-bar"><div className="risk-level" data-risk-level='low' style={{ width: `${ip.risk}%` }}></div></div>
                            </td>
                            <td>{ip.packet_type || 'N/A'}</td>
                            <td>{ip.pps ? ip.pps.toFixed(1) : 0}</td>
                            <td>{ip.bps ? formatBPS(ip.bps) : '0 BPS'}</td>
                        </tr>
                    ))
                )}
            </tbody>
        </table>
    </div>

    </div>
  );
};

export default TrafficAnalysis;