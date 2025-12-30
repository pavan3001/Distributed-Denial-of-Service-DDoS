from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import threading
import data_collector 
import os

app = Flask(__name__)
CORS(app)

# --- Shared State (In-Memory Database for Blocked IPs) ---
BLOCKED_IPS = {} 

# --- Helper Functions (Mitigation/Auto-Block) ---
def execute_firewall_block(ip_address, action="ADD"):
    """Placeholder for Actual Mitigation."""
    print(f"[{action} BLOCK ACTION] IP {ip_address} recorded in BLOCKED_IPS list.")
    pass

def check_and_auto_block(ip_list):
    """Checks the list of high-risk IPs from the collector and auto-blocks those above 90% risk."""
    for ip_data in ip_list:
        if ip_data['risk'] > 90 and ip_data['ip'] not in BLOCKED_IPS:
            reason = f"Auto-Blocked (Risk {ip_data['risk']}%)"
            BLOCKED_IPS[ip_data['ip']] = {"time": time.time(), "reason": reason}
            execute_firewall_block(ip_data['ip'], "ADD")
            print(f"[AUTO-BLOCK TRIGGERED] IP {ip_data['ip']} added to block list.")

# --- API Endpoints ---

@app.route('/api/analyze_traffic', methods=['GET'])
def get_traffic_analysis():
    """Returns real-time traffic data from the data_collector thread."""
    
    latest_data = data_collector.LATEST_ANALYSIS
    top_ips = latest_data.get('high_risk_ips', [])
    
    if data_collector.get_monitoring_state():
        check_and_auto_block(top_ips)
    
    return jsonify({
        "timestamp": latest_data['timestamp'],
        "total_packets": latest_data['total_packets'],
        "inbound_rate": latest_data['inbound_rate'],
        "outbound_rate": 0, 
        "anomalous_flows": len(top_ips),
        "top_source_ips": [{**ip, "status": "Blocked"} if ip['ip'] in BLOCKED_IPS else ip for ip in top_ips],
        "system_status": "HIGH ALERT" if len(top_ips) > 0 else "Nominal",
        "monitoring_status": "Active" if data_collector.get_monitoring_state() else "Stopped",
        "blocked_count": len(BLOCKED_IPS)
    })

# --- Monitoring Control Endpoints ---

@app.route('/api/monitoring/status', methods=['GET'])
def get_monitoring_status():
    """Returns the current monitoring status (Active/Stopped)."""
    return jsonify({
        "status": data_collector.get_monitoring_state()
    })

@app.route('/api/monitoring/control', methods=['POST'])
def control_monitoring():
    """Starts or stops monitoring based on the request."""
    data = request.json
    action = data.get('action') # 'start' or 'stop'
    
    if action == 'start':
        data_collector.set_monitoring_state(True)
        return jsonify({"success": True, "message": "Monitoring Started."})
    elif action == 'stop':
        data_collector.set_monitoring_state(False)
        return jsonify({"success": True, "message": "Monitoring Stopped. Live analysis paused."})
    else:
        return jsonify({"success": False, "message": "Invalid action. Use 'start' or 'stop'."}), 400

# --- Search and Mitigation Endpoints ---

@app.route('/api/ip_risk', methods=['POST'])
def search_ip_risk():
    """Searches a specific IP, calculates a mock risk, and returns its status."""
    data = request.json
    ip_address = data.get('ip')
    
    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    ip_parts = ip_address.split('.')
    try:
        mock_score = 15 + (int(ip_parts[-1]) % 2 * 75 if ip_parts else 0)
    except:
        mock_score = 10
        
    status = "BLOCKED" if ip_address in BLOCKED_IPS else "Monitored"
    risk = mock_score

    response = {
        "ip": ip_address,
        "risk_score": risk,
        "is_ddos": risk > 80,
        "status": status,
        "recommendation": "Block Immediately" if risk > 90 else ("Monitor Closely" if risk > 50 else "Normal")
    }
    return jsonify(response)


@app.route('/api/block_ip', methods=['POST'])
def block_ip_action():
    """Handles manual IP blocking."""
    data = request.json
    ip_address = data.get('ip')
    reason = data.get('reason', 'Manual Block by Admin')
    
    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    if ip_address not in BLOCKED_IPS:
        BLOCKED_IPS[ip_address] = {"time": time.time(), "reason": reason}
        execute_firewall_block(ip_address, "ADD")
        return jsonify({"success": True, "message": f"IP {ip_address} blocked successfully."})
    else:
        return jsonify({"success": False, "message": f"IP {ip_address} is already blocked."})

@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip_action():
    """Handles manual IP unblocking."""
    data = request.json
    ip_address = data.get('ip')
    
    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    if ip_address in BLOCKED_IPS:
        del BLOCKED_IPS[ip_address]
        execute_firewall_block(ip_address, "DELETE")
        return jsonify({"success": True, "message": f"IP {ip_address} unblocked successfully."})
    else:
        return jsonify({"success": False, "message": f"IP {ip_address} is not currently blocked."})

@app.route('/api/blocked_list', methods=['GET'])
def get_blocked_list():
    """Returns the list of currently blocked IPs."""
    blocked_list = [{"ip": ip, **details} for ip, details in BLOCKED_IPS.items()]
    return jsonify(blocked_list)


# --- Main Runner ---
if __name__ == '__main__':
    
    # Start the Data Collector threads in the background
    sniffer_thread = threading.Thread(target=data_collector.start_sniffer)
    analysis_thread = threading.Thread(target=data_collector.start_analysis_loop)
    
    sniffer_thread.daemon = True
    analysis_thread.daemon = True
    
    sniffer_thread.start()
    analysis_thread.start()
    
    print("[*] Background sniffer/analyzer threads started.")
    
    # Start the Flask Web Server
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

    # Stop the collector gracefully on exit
    data_collector.stop_analysis()
    
