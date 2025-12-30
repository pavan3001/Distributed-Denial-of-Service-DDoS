from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import queue
import pandas as pd
import joblib 
import numpy as np
import threading
import sys

# --- Configuration (Unchanged) ---
INTERFACE_NAME = "Wi-Fi"  # !!! REPLACE with your actual Wi-Fi interface name !!!
PACKET_QUEUE = queue.Queue(maxsize=10000)
FEATURE_WINDOW = 5

# --- Global State Flags (Unchanged) ---
MONITORING_ACTIVE = False 
RUNNING = False           

# --- Model Loading (Unchanged) ---
ML_MODEL_FILE = 'random_forest_model.pkl'
try:
    ML_MODEL = joblib.load(ML_MODEL_FILE)
    print(f"[*] ML Model '{ML_MODEL_FILE}' loaded successfully.")
    CLASS_INDEX = 1 
except FileNotFoundError:
    ML_MODEL = None
    print(f"!!! WARNING: ML Model '{ML_MODEL_FILE}' not found. Using simple threshold logic. !!!")
    CLASS_INDEX = 0

# --- Helper Function for Protocol (Unchanged) ---
def get_protocol(pkt):
    if TCP in pkt: return 'TCP'
    if UDP in pkt: return 'UDP'
    if ICMP in pkt: return 'ICMP'
    return 'Other'

# server/data_collector.py - CORRECTED extract_and_classify function

# ... (Previous code remains the same up to here) ...

def extract_and_classify(packet_list):
    """
    Extracts features, aggregates into flows, runs ML, and determines packet type/DDoS type.
    Returns ALL IPs including low-risk (<50%) for full visibility.
    """
    flow_features = []
    
    # --- 1. Feature Extraction ---
    for pkt in packet_list:
        if IP in pkt:
            flow_features.append({
                'src_ip': pkt[IP].src,
                'length': len(pkt),
                'protocol': get_protocol(pkt)
            })

    if not flow_features:
        return []

    df = pd.DataFrame(flow_features)
    
    # --- 2. Aggregation ---
    ip_stats = df.groupby('src_ip').agg(
        packet_count=('src_ip', 'size'),
        total_bytes=('length', 'sum'),
        tcp_count=('protocol', lambda x: (x == 'TCP').sum()),
        udp_count=('protocol', lambda x: (x == 'UDP').sum()),
        icmp_count=('protocol', lambda x: (x == 'ICMP').sum()),
    ).reset_index()

    # --- 3. ML Risk Classification ---
    if ML_MODEL:
        ip_stats['Mean_Packet_Length'] = ip_stats['total_bytes'] / ip_stats['packet_count']
        ip_stats['Flow_Duration'] = FEATURE_WINDOW
        features_for_model = ip_stats[['packet_count', 'Flow_Duration', 'Mean_Packet_Length']].fillna(0)
        try:
            probabilities = ML_MODEL.predict_proba(features_for_model.values)
            risk_scores = (probabilities[:, CLASS_INDEX] * 100).astype(int)
        except Exception as e:
            print(f"ML Model Prediction Error: {e}. Falling back to threshold.", file=sys.stderr)
            risk_scores = (ip_stats['packet_count'] * 1.5).clip(upper=100).astype(int)
    else:
        risk_scores = (ip_stats['packet_count'] * 1.5).clip(upper=100).astype(int)

    ip_stats['risk_score'] = risk_scores

    # --- 4. Format and Assign DDoS Type ---
    formatted_results = []
    for _, item in ip_stats.iterrows():
        risk = item['risk_score']
        ddos_type = "Normal"
        status = "Normal"
        dominant_packet = "Mixed"

        # Determine dominant packet type
        max_count = max(item['tcp_count'], item['udp_count'], item['icmp_count'])
        if max_count == item['tcp_count']:
            dominant_packet = 'TCP'
        elif max_count == item['udp_count']:
            dominant_packet = 'UDP'
        elif max_count == item['icmp_count']:
            dominant_packet = 'ICMP'
        else:
            dominant_packet = 'Other'

        # Status based on risk level
        if risk >= 90:
            status = "DDoS Attack"
            if item['tcp_count'] > item['udp_count'] * 2 and item['tcp_count'] > 50:
                ddos_type = "SYN/TCP Flood"
            elif item['udp_count'] > item['tcp_count'] * 2 and item['udp_count'] > 50:
                ddos_type = "UDP Flood"
            elif item['icmp_count'] > item['tcp_count'] + item['udp_count'] and item['icmp_count'] > 50:
                ddos_type = "ICMP Flood"
            else:
                ddos_type = "Complex Flood"
        elif risk >= 50:
            status = "Monitored"
            ddos_type = "Potential Anomaly"
        else:
            status = "Normal"
            ddos_type = "Low-Risk Flow"

        formatted_results.append({
            'ip': item['src_ip'],
            'risk': risk,
            'flow_count': item['packet_count'],
            'status': status,
            'ddos_type': ddos_type,
            'packet_type': dominant_packet,
        })

    return formatted_results


def packet_callback(packet):
    """Callback function for Scapy sniff - adds packet to the queue."""
    if IP in packet and MONITORING_ACTIVE:
        try:
            PACKET_QUEUE.put_nowait(packet)
        except queue.Full:
            pass 

def start_sniffer():
    """Starts the Scapy sniffer loop."""
    global RUNNING
    RUNNING = True
    print(f"[*] Starting sniffer on interface: {INTERFACE_NAME}...")
    try:
        sniff(iface=INTERFACE_NAME, prn=packet_callback, store=0, filter="ip", stop_filter=lambda x: not RUNNING)
    except Exception as e:
        print(f"[ERROR] Sniffer failed. Check permissions/interface name: {e}", file=sys.stderr)
    print("[*] Sniffer stopped.")

LATEST_ANALYSIS = {
    'timestamp': 0,
    'total_packets': 0,
    'inbound_rate': 0,
    'high_risk_ips': []
}

def start_analysis_loop():
    """The main analysis loop."""
    global LATEST_ANALYSIS
    global RUNNING
    
    RUNNING = True
    print(f"[*] Starting analysis loop (every {FEATURE_WINDOW} seconds)...")

    while RUNNING:
        time.sleep(FEATURE_WINDOW)
        
        if MONITORING_ACTIVE:
            collected_packets = []
            while not PACKET_QUEUE.empty():
                collected_packets.append(PACKET_QUEUE.get())
            
            total_in_window = len(collected_packets)
            
            if total_in_window > 0:
                high_risk_flows = extract_and_classify(collected_packets)

                LATEST_ANALYSIS = {
                    'timestamp': int(time.time()),
                    'total_packets': total_in_window,
                    'inbound_rate': total_in_window / FEATURE_WINDOW,
                    'high_risk_ips': high_risk_flows
                }
                print(f"[Analysis] Detected {len(high_risk_flows)} high-risk IPs. Rate: {LATEST_ANALYSIS['inbound_rate']:.2f} p/s")
            else:
                LATEST_ANALYSIS['inbound_rate'] *= 0.8
                LATEST_ANALYSIS['total_packets'] = 0
        else:
            # Monitoring is stopped: zero out the live data for the dashboard
            LATEST_ANALYSIS = {
                'timestamp': int(time.time()),
                'total_packets': 0,
                'inbound_rate': 0,
                'high_risk_ips': []
            }


def stop_analysis():
    global RUNNING
    RUNNING = False
    
# --- New Control Functions for Flask (Unchanged) ---

def set_monitoring_state(is_active):
    """Sets the global MONITORING_ACTIVE flag."""
    global MONITORING_ACTIVE
    MONITORING_ACTIVE = is_active

def get_monitoring_state():
    """Returns the current state."""
    return MONITORING_ACTIVE