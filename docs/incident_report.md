# Incident Report — INC-2026-001

**Date:** 2026-04-25
**Severity:** Critical
**Status:** Resolved
**Analyst:** xAHIINX00

## Summary
SSH brute force attack detected against ubuntu-victim (192.168.56.102) originating from 192.168.56.101. Attack involved 17 failed login attempts across two waves. No successful authentication occurred. Automated response blocked the attacker IP within seconds of detection threshold being reached.

## Timeline
| Time | Event |
|---|---|
| 11:08:56 | Hydra brute force initiated from Kali (192.168.56.101) |
| 11:09:09 | Splunk detected first Failed password events |
| 11:09:11 | First wave completed — 15 attempts, 0 successful |
| 12:14:45 | Fail2Ban banned 192.168.56.101 after threshold breach |
| 14:58:20 | Python auto-response executed UFW block |

## Indicators of Compromise (IOCs)
- Attacker IP: 192.168.56.101
- Target port: 22 (SSH)
- Targeted username: labuser
- Attack tool signature: Hydra 9.6

## Actions Taken
1. Attacker IP blocked via UFW (automated response)
2. Fail2Ban jail activated — 1 hour ban applied
3. SSH password authentication disabled system-wide
4. PermitRootLogin set to no
5. MaxAuthTries reduced to 3
6. Incident logged to JSON audit file

## Recommendations
1. Implement SSH key-based authentication across all servers
2. Deploy GeoIP-based SSH access restrictions
3. Integrate Splunk alerts with team communication channel (Slack/Teams)
4. Consider port knocking or non-standard SSH port
5. Schedule regular review of Fail2Ban ban lists
