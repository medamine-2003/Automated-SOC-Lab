#!/usr/bin/env python3
"""
Wazuh Auto-Tuner for Pentest Noise Suppression
-----------------------------------------------
Automatically detects excessive failed login attempts from pentest IPs
and creates suppression rules to reduce alert fatigue.
"""

import os
import json
from collections import defaultdict
from datetime import datetime, timedelta

# --- CONFIGURATION ---
THRESHOLD = 40  # Number of failed logins before suppression
PENTEST_SUBNET = "41.230.91."  # Target subnet to monitor
FAILED_LOGIN_RULES = ["60122", "60204"]  # Rule IDs for failed logins

CONTAINER_NAME = "single-node-wazuh.manager-1"
WAZUH_RULES_PATH = "/var/ossec/etc/rules/local_rules.xml"
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
ID_TRACKER_FILE = "/opt/tuning-engine/auto_id.txt"


# --- RULE ID MANAGEMENT ---
def get_next_rule_id():
    """Generate sequential rule IDs starting from 100100"""
    if not os.path.exists(ID_TRACKER_FILE):
        with open(ID_TRACKER_FILE, "w") as f:
            f.write("100100")
        return "100100"

    with open(ID_TRACKER_FILE, "r") as f:
        current = int(f.read().strip())

    next_id = current + 1
    with open(ID_TRACKER_FILE, "w") as f:
        f.write(str(next_id))

    return str(next_id)


# --- ALERT COLLECTION ---
def get_recent_alerts():
    """Read alerts directly from Wazuh container's JSON log file"""
    tmp_file = "/tmp/alerts_tmp.json"
    
    # Extract last 1000 alerts from container
    cmd = f"docker exec {CONTAINER_NAME} tail -1000 {ALERTS_FILE} > {tmp_file}"
    if os.system(cmd) != 0:
        print("[-] Failed to read alerts from container")
        return []

    # Parse JSON alerts and filter by time (last 15 minutes)
    alerts = []
    cutoff = datetime.utcnow() - timedelta(minutes=15)
    
    with open(tmp_file, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    alert = json.loads(line)
                    # Filter by timestamp
                    ts = alert.get('timestamp', '').replace('+0000', '+00:00')
                    alert_time = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    if alert_time.replace(tzinfo=None) > cutoff:
                        alerts.append(alert)
                except:
                    continue
    
    return alerts if alerts else []


# --- THREAT ANALYSIS ---
def extract_srcip(alert):
    """Extract source IP from alert structure"""
    data = alert.get('data', {})
    
    # Check for direct srcip field (common in SSH/firewall alerts)
    if 'srcip' in data:
        srcip = data['srcip']
        if isinstance(srcip, list) and srcip:
            return srcip[0]
        elif isinstance(srcip, str):
            return srcip
    
    # Check Windows event data fields
    win_data = data.get('win', {}).get('eventdata', {})
    for field in ['ipAddress', 'sourceAddress', 'sourceNetworkAddress']:
        if field in win_data and win_data[field] not in [None, '-', '']:
            return win_data[field]
    
    return None


def analyze_alerts(alerts):
    """Analyze alerts for pentest patterns"""
    freq = defaultdict(int)
    
    for alert in alerts:
        rule_id = alert.get('rule', {}).get('id')
        
        # Only process failed login rules
        if rule_id not in FAILED_LOGIN_RULES:
            continue
        
        srcip = extract_srcip(alert)
        if not srcip:
            continue
        
        # Filter for pentest subnet only
        if not srcip.startswith(PENTEST_SUBNET):
            continue
        
        # Skip internal IPs
        if srcip.startswith(("127.", "10.", "192.168.")):
            continue
        
        freq[(rule_id, srcip)] += 1
    
    return freq


# --- SUPPRESSION RULE GENERATION ---
def apply_suppression(rule_id, srcip):
    """Create Wazuh rule to suppress alerts matching criteria"""
    new_rule_id = get_next_rule_id()
    
    print(f"\n[+] Creating suppression rule {new_rule_id}")
    print(f"    Suppressing Rule {rule_id} for IP {srcip}")
    
    # Generate suppression rule XML
    suppression_xml = f"""
  <!-- AUTO TUNER {new_rule_id} -->
  <rule id="{new_rule_id}" level="0">
    <if_sid>{rule_id}</if_sid>
    <srcip>{srcip}</srcip>
    <description>Auto-suppressed pentest noise from {srcip}</description>
  </rule>
"""
    
    tmp = "/tmp/local_rules.xml"
    
    # Copy current rules from container
    os.system(f"docker cp {CONTAINER_NAME}:{WAZUH_RULES_PATH} {tmp}")
    
    with open(tmp, "r") as f:
        content = f.read()
    
    # Avoid duplicate rules
    if srcip in content:
        print("[!] Suppression already exists, skipping")
        return False
    
    # Inject new rule before closing </group> tag
    if "</group>" in content:
        content = content.replace("</group>", suppression_xml + "\n</group>")
    else:
        print("[-] Invalid rules file structure")
        return False
    
    # Write modified rules back to container
    with open(tmp, "w") as f:
        f.write(content)
    
    os.system(f"docker cp {tmp} {CONTAINER_NAME}:{WAZUH_RULES_PATH}")
    os.system(f"docker exec {CONTAINER_NAME} chown wazuh:wazuh {WAZUH_RULES_PATH}")
    os.system(f"docker exec {CONTAINER_NAME} chmod 640 {WAZUH_RULES_PATH}")
    
    # Restart Wazuh manager to apply changes
    os.system(f"docker restart {CONTAINER_NAME}")
    
    print("[+] Suppression applied successfully")
    return True


# --- MAIN EXECUTION ---
def main():
    print("[*] Wazuh Auto-Tuner Started")
    print(f"[*] Monitoring subnet: {PENTEST_SUBNET}*")
    print(f"[*] Failed login rules: {FAILED_LOGIN_RULES}")
    print(f"[*] Suppression threshold: {THRESHOLD} alerts")
    print()
    
    # Collect and analyze alerts
    alerts = get_recent_alerts()
    print(f"[*] Retrieved {len(alerts)} recent alerts")
    
    if not alerts:
        print("[*] No alerts found in the last 15 minutes")
        return
    
    # Analyze for pentest patterns
    threat_groups = analyze_alerts(alerts)
    print(f"[*] Found {len(threat_groups)} potential threat groups")
    
    # Display findings
    for (rule_id, ip), count in threat_groups.items():
        print(f"    Rule {rule_id} | IP {ip} | {count} attempts")
        
        # Apply suppression if threshold exceeded
        if count > THRESHOLD:
            print(f"    [!] THRESHOLD EXCEEDED - Applying suppression...")
            apply_suppression(rule_id, ip)
    
    print("\n[*] Auto-tuning complete")


if __name__ == "__main__":
    main()
