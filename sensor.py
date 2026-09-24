import os
import sys
import time
import json
import socket
import logging
from collections import defaultdict

# Suppress scapy IPv6 warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    print("Error: Scapy not installed. Run 'pip install scapy'")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Error: Requests not installed. Run 'pip install requests'")
    sys.exit(1)

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
except ImportError:
    print("Error: Scikit-learn not installed. Run 'pip install scikit-learn numpy'")
    sys.exit(1)

BACKEND_URL = "http://localhost:8080/api/events"
ALERT_URL = "http://localhost:8080/api/alerts"
REPORT_INTERVAL = 5  # Reporting interval in seconds

# Feature storage for ML
flow_data = defaultdict(lambda: {"count": 0, "bytes": 0})
ml_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
is_model_trained = False

def get_protocol_name(proto):
    if proto == 6: return "TCP"
    if proto == 17: return "UDP"
    if proto == 1: return "ICMP"
    return str(proto)

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = get_protocol_name(packet[IP].proto)
        size = len(packet)
        
        flow_key = f"{src_ip}->{dst_ip}:{proto}"
        flow_data[flow_key]["count"] += 1
        flow_data[flow_key]["bytes"] += size

def train_and_predict(features):
    global is_model_trained, ml_model
    # features shape: [[count, bytes], ...]
    X = np.array(features)
    
    # We need a minimum amount of unique flows to train IF reasonably
    if len(X) < 5:
        return [1] * len(X)  # Return 'normal' if not enough data
        
    if not is_model_trained or len(X) > 20:
        # Retrain online (simplified)
        ml_model.fit(X)
        is_model_trained = True
        
    return ml_model.predict(X) # 1 = normal, -1 = anomaly

def report_flows():
    while True:
        time.sleep(REPORT_INTERVAL)
        if not flow_data:
            continue
            
        keys = list(flow_data.keys())
        features = [[flow_data[k]["count"], flow_data[k]["bytes"]] for k in keys]
        
        # ML Analysis
        predictions = train_and_predict(features)
        
        for idx, key in enumerate(keys):
            pred = predictions[idx]
            count = features[idx][0]
            bytes_sz = features[idx][1]
            
            # Reset bucket
            flow_data[key]["count"] = 0
            flow_data[key]["bytes"] = 0
            if count == 0: continue
            
            src_dst, proto = key.split(':')
            src_ip, dst_ip = src_dst.split('->')
            
            if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1": continue # Ignore localhost chatter
            
            # Scoring mock (since IF just gives 1/-1, we synthesize a score)
            if pred == -1:
                score = min(0.99, 0.70 + (count / 1000.0) + (bytes_sz / 100000.0))
                event_type = 'threat' if score > 0.85 else 'suspicious'
                msg = f"Anomalous Volumetric Flow Detected ({count} pkts, {bytes_sz} bytes)"
            else:
                score = min(0.30, count / 1000.0)
                event_type = 'safe'
                msg = f"Standard Flow Profile ({count} pkts, {bytes_sz} bytes)"
                
            payload = {
                "type": event_type,
                "protocol": proto,
                "ip_address": src_ip,
                "message": msg,
                "score": score,
                "model": "Isolation Forest (Sklearn)"
            }
            
            try:
                # Send to backend
                requests.post(BACKEND_URL, json=payload, timeout=2)
                
                # If high threat, also raise an alert
                if event_type == 'threat':
                    alert_payload = {
                        "severity": "critical" if score > 0.95 else "high",
                        "title": msg,
                        "source": f"{src_ip} -> {dst_ip}"
                    }
                    requests.post(ALERT_URL, json=alert_payload, timeout=2)
            except Exception as e:
                print(f"Error publishing to {BACKEND_URL}: {e}")

if __name__ == "__main__":
    import threading
    print("====================================================")
    print("   🛡 SIH26145 AI Threat Sensor (Scapy + sklearn)     ")
    print("====================================================")
    print("Initializing promiscuous capture Mode...")
    
    # Start reporting thread
    reporter = threading.Thread(target=report_flows, daemon=True)
    reporter.start()
    
    print("Sniffing network traffic... (Press Ctrl+C to stop)")
    try:
        # Sniff indefinitely (store=0 means don't keep in memory to prevent leak)
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Sensor shutting down.")
