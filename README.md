# 🔐 SOC SSH Brute Force Detection Lab

![SOC](https://img.shields.io/badge/SOC-Blue_Team-blue)
![Splunk](https://img.shields.io/badge/SIEM-Splunk-orange)
![Python](https://img.shields.io/badge/Automation-Python-green)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

> A fully functional Security Operations Center (SOC) lab that simulates, detects, and automatically responds to SSH brute force attacks — built from scratch using real tools used in production environments.

---
## 📹 Demo Video
[![Watch Demo](https://img.youtube.com/vi/XzOOZSmnecM/0.jpg)](https://youtu.be/XzOOZSmnecM)

## 📌 Project Summary

This project demonstrates the **complete SOC analyst workflow** for handling an SSH brute force incident:

- **Attack simulation** using Hydra from a Kali Linux attacker VM
- **Real-time detection** via Splunk SIEM ingesting live auth logs
- **Multi-query threat hunting** with 4 distinct SPL detection patterns
- **Automated incident response** — Splunk alert triggers a Python webhook that SSHes into the victim and blocks the attacker IP via UFW
- **System hardening** using Fail2Ban and SSH configuration lockdown
- **Full audit trail** — every action logged to a structured JSON incident file

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Windows Host                        │
│  ┌─────────────────┐    ┌────────────────────────┐  │
│  │ Splunk Enterprise│    │ Python Flask Webhook   │  │
│  │  localhost:8000  │───▶│   auto_response.py     │  │
│  │  port 9997 recv  │    │   localhost:5000        │  │
│  └────────▲─────────┘    └──────────┬─────────────┘  │
│           │ logs                     │ SSH block       │
└───────────┼──────────────────────────┼────────────────┘
            │                          │
┌───────────┼──────────────────────────▼────────────────┐
│           │      VirtualBox Host-Only Network          │
│           │         192.168.56.0/24                    │
│  ┌────────┴────────────────────────────────────┐      │
│  │         Ubuntu Server 22.04 (Victim)        │      │
│  │         192.168.56.102                      │      │
│  │  - OpenSSH Server                           │      │
│  │  - Splunk Universal Forwarder               │      │
│  │  - Fail2Ban                                 │      │
│  │  - UFW Firewall                             │      │
│  └─────────────────────────────────────────────┘      │
│                        ▲                              │
│                        │ SSH attack                   │
│  ┌─────────────────────┴───────────────────────┐      │
│  │         Kali Linux (Attacker)               │      │
│  │         192.168.56.101                      │      │
│  │  - Hydra brute force tool                   │      │
│  └─────────────────────────────────────────────┘      │
└───────────────────────────────────────────────────────┘
```

---

## 🛠️ Tools & Technologies

| Category | Tool |
|---|---|
| SIEM | Splunk Enterprise 10.x |
| Log Shipping | Splunk Universal Forwarder |
| Attack Simulation | Hydra 9.6 |
| Automation | Python 3.13, Flask, Paramiko |
| Intrusion Prevention | Fail2Ban |
| Firewall | UFW |
| Attacker OS | Kali Linux |
| Victim OS | Ubuntu Server 22.04 LTS |
| Hypervisor | Oracle VirtualBox |

---

## 📋 Phase Breakdown

### Phase 1 — Lab Setup
- Configured VirtualBox with Host-Only + NAT dual-adapter networking
- Deployed Ubuntu Server 22.04 as victim with OpenSSH
- Installed Splunk Enterprise on Windows host
- Deployed Splunk Universal Forwarder on victim
- Configured real-time `/var/log/auth.log` ingestion into Splunk index

### Phase 2 — Attack Simulation
- Conducted password brute force attack using Hydra targeting SSH
- Conducted username spray attack (multiple usernames, single password)
- Verified live attack events appearing in Splunk in real time

### Phase 3 — SPL Detection Queries
Four detection queries written covering different attack patterns:

**Query 1 — Brute Force Threshold**
```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as attempts by src_ip
| where attempts >= 5
| sort -attempts
| rename src_ip as "Attacker IP", attempts as "Failed Attempts"
```

**Query 2 — Username Spray Detection**
```spl
index=main sourcetype=linux_secure "Invalid user"
| rex field=_raw "Invalid user (?<username>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats dc(username) as unique_users count as attempts by src_ip
| where unique_users >= 3
| sort -unique_users
```

**Query 3 — Attack Burst Timeline**
```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=1m
| stats count as attempts by _time src_ip
| where attempts >= 3
| sort _time
```

**Query 4 — Successful Login After Failures (Breach Detection)**
```spl
index=main sourcetype=linux_secure
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval status=if(match(_raw,"Failed password"),"failed","success")
| stats count(eval(status="failed")) as failures,
        count(eval(status="success")) as successes by src_ip
| where failures >= 3 AND successes >= 1
| sort -failures
```

### Phase 4 — Dashboard & Alerting
- Built 4-panel real-time Splunk dashboard with 1-minute auto-refresh
- Panels: Top Attacking IPs, Attack Timeline, Targeted Usernames, 24hr Summary
- Configured scheduled alert firing every 5 minutes — severity: Critical

### Phase 5 — Automated Response (SOAR-lite) ⭐
The standout feature of this project. When Splunk detects a brute force:

1. Splunk alert fires → hits Python Flask webhook
2. Flask server receives attacker IP + attempt count
3. (Optional) AbuseIPDB API called for IP reputation score
4. Python SSHes into victim VM via Paramiko
5. Executes `ufw deny from [attacker_ip]` automatically
6. Structured JSON incident record written to log file

**Sample incident log entry:**
```json
{
  "timestamp": "2026-04-25 14:58:20",
  "attacker_ip": "192.168.56.101",
  "failed_attempts": 17,
  "abuse_confidence_score": null,
  "action_taken": "BLOCKED via ufw"
}
```

### Phase 6 — Hardening & Verification
- Deployed Fail2Ban with custom jail: ban after 5 failures within 60s
- SSH hardened: `PasswordAuthentication no`, `PermitRootLogin no`, `MaxAuthTries 3`
- Re-ran Hydra post-hardening: `Connection refused` — attack completely neutralised
- Fail2Ban ban events ingested into Splunk via `/var/log/fail2ban.log`

---

## 🎯 Skills Demonstrated

- SIEM configuration and log pipeline management
- SPL (Search Processing Language) threat hunting queries
- Incident detection, triage and response workflow
- SOAR-lite automation using Python + webhooks
- Linux system hardening and firewall management
- Network segmentation in virtualised lab environments
- Structured incident documentation

---

## 📁 Repository Structure

```
SOC-SSH-BruteForce-Lab/
├── README.md
├── splunk/
│   ├── queries/
│   │   ├── brute_force_threshold.spl
│   │   ├── username_spray.spl
│   │   ├── attack_timeline.spl
│   │   └── breach_detection.spl
│   └── dashboard/
│       └── ssh_bruteforce_soc_monitor.xml
├── automation/
│   └── auto_response.py
├── hardening/
│   ├── fail2ban_jail.local
│   └── sshd_config_hardened
└── docs/
    └── incident_report.md
```

---

## 📄 Sample Incident Report

**Incident ID:** INC-2026-001
**Date:** 2026-04-25
**Severity:** Critical
**Status:** Resolved

| Field | Details |
|---|---|
| Attack Type | SSH Brute Force |
| Attacker IP | 192.168.56.101 |
| Target | ubuntu-victim (192.168.56.102) |
| Start Time | 2026-04-25 11:08:56 |
| Detection Time | 2026-04-25 11:09:09 |
| Response Time | 2026-04-25 14:58:20 |
| Total Attempts | 17 |
| Outcome | Blocked — no successful login |

**Timeline:**
- `11:08:56` — Hydra brute force initiated from Kali
- `11:09:09` — Splunk detected first failed password events
- `11:09:11` — 15 attempts completed, attack finished first wave
- `12:14:45` — Fail2Ban banned `192.168.56.101` after threshold breach
- `14:58:20` — Automated Python response executed UFW block

**Actions Taken:**
1. Attacker IP blocked via UFW (automated)
2. Fail2Ban jail activated for SSH
3. SSH password authentication disabled
4. Incident logged to structured JSON audit file

**Recommendations:**
- Implement key-based SSH authentication across all servers
- Deploy centralised SIEM alerting to SOC team communication channel
- Consider GeoIP blocking for SSH from unexpected regions

---

## 🚀 How to Reproduce

1. Set up VirtualBox with Host-Only network `192.168.56.0/24`
2. Deploy Ubuntu Server 22.04 VM — assign static IP `192.168.56.102`
3. Install Splunk Enterprise on host, configure receiving on port `9997`
4. Install Splunk Universal Forwarder on Ubuntu, monitor `/var/log/auth.log`
5. Deploy Kali Linux VM on same Host-Only network
6. Run `hydra -l labuser -P passwords.txt ssh://192.168.56.102 -t 4 -V`
7. Observe live detection in Splunk Search & Reporting
8. Run `auto_response.py` and trigger webhook to test automated blocking
9. Install Fail2Ban with provided `jail.local` config
10. Apply SSH hardening from `sshd_config_hardened`

---

## 👤 Author

**xAHIINX00**
- GitHub: [@xAHIINX00](https://github.com/xAHIINX00)

---

*Built as a portfolio project demonstrating real-world SOC analyst skills.*
