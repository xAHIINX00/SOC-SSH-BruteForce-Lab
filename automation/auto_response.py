from flask import Flask, request, jsonify
import paramiko
import requests
import json
import datetime
import os

app = Flask(__name__)

# Lab config — update these for your environment
VICTIM_IP = "192.168.56.102"
VICTIM_USER = "labuser"
VICTIM_PASS = "your_password_here"
INCIDENT_LOG = "incidents.log"
ABUSEIPDB_KEY = ""  # Optional: add your AbuseIPDB API key

def log_incident(ip, attempts, action, abuse_score=None):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "attacker_ip": ip,
        "failed_attempts": attempts,
        "abuse_confidence_score": abuse_score,
        "action_taken": action
    }
    with open(INCIDENT_LOG, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    print(f"[{timestamp}] INCIDENT LOGGED: {ip} | Attempts: {attempts} | Action: {action}")

def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=5)
        return r.json()["data"]["abuseConfidenceScore"]
    except:
        return None

def block_ip_on_victim(ip):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(VICTIM_IP, username=VICTIM_USER, password=VICTIM_PASS)
        stdin, stdout, stderr = ssh.exec_command(f"echo {VICTIM_PASS} | sudo -S ufw deny from {ip}")
        stdout.read()
        ssh.close()
        return True
    except Exception as e:
        print(f"Block failed: {e}")
        return False

@app.route("/alert", methods=["POST"])
def handle_alert():
    data = request.json
    print(f"\n[ALERT RECEIVED] {data}")
    ip = data.get("attacker_ip", "unknown")
    attempts = data.get("attempts", 0)
    abuse_score = check_abuseipdb(ip)
    if ip != "unknown":
        blocked = block_ip_on_victim(ip)
        action = "BLOCKED via ufw" if blocked else "BLOCK FAILED"
    else:
        action = "NO ACTION - IP unknown"
    log_incident(ip, attempts, action, abuse_score)
    return jsonify({"status": "processed", "action": action}), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running"}), 200

if __name__ == "__main__":
    print("[*] SOC Auto-Response Server starting on port 5000...")
    app.run(host="0.0.0.0", port=5000, debug=True)
