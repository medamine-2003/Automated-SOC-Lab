from flask import Flask, request, jsonify
import json
import os
import time

app = Flask(__name__)

# Paths
DB_PATH = "/opt/tuning-engine/context_db.json"
WAZUH_RULES_PATH = "/var/ossec/etc/rules/local_rules.xml"

# Simple state management for Custom Rule IDs (Starts at 100050)
ID_TRACKER_FILE = "/opt/tuning-engine/last_id.txt"

def get_next_rule_id():
    if not os.path.exists(ID_TRACKER_FILE):
        with open(ID_TRACKER_FILE, 'w') as f:
            f.write("100050")
        return "100050"
    
    with open(ID_TRACKER_FILE, 'r') as f:
        current_id = int(f.read().strip())
    
    next_id = current_id + 1
    with open(ID_TRACKER_FILE, 'w') as f:
        f.write(str(next_id))
    return str(next_id)

@app.route('/api/v1/recommend', methods=['POST'])
def recommend_tuning():
    """
    Stage 1: Recommendation Mode
    Shuffle sends the parsed data here first to get a Confidence Score.
    """
    data = request.json
    attacker_ip = data.get("ipAddress")
    rule_id = str(data.get("rule_id"))

    with open(DB_PATH, 'r') as f:
        db = json.load(f)

    confidence_score = 0
    reasoning = []

    # 1. Check if IP is a known asset
    if attacker_ip in db["known_assets"]:
        confidence_score += 50
        reasoning.append(f"IP {attacker_ip} is a known asset: {db['known_assets'][attacker_ip]['role']}")
        
        # 2. Check if this specific rule is allowed for this asset
        if rule_id in db["known_assets"][attacker_ip]["allowed_noisy_rules"]:
            confidence_score += 45
            reasoning.append(f"Rule {rule_id} is explicitly authorized for this asset.")

    # 3. Check rule criticality
    if rule_id in db["rule_metadata"]:
        if db["rule_metadata"][rule_id]["criticality"] == "High":
            confidence_score -= 20
            reasoning.append("Rule is High Criticality. Proceed with caution.")

    # Final Decision
    recommend_tune = confidence_score >= 75

    return jsonify({
        "confidence_score": confidence_score,
        "recommend_tune": recommend_tune,
        "reasoning": reasoning
    })


@app.route('/api/v1/apply', methods=['GET', 'POST'])
def apply_tuning():
    if request.method == 'GET':
        attacker_ip = request.args.get("ip")
        rule_id = request.args.get("rule")
    else:
        data = request.json
        attacker_ip = data.get("ipAddress")
        rule_id = str(data.get("rule_id"))
    
    new_rule_id = get_next_rule_id()

    xml_block = f"""
  <!-- AUTO-TUNED RULE {new_rule_id}: Suppressing noise from {attacker_ip} for rule {rule_id} -->
  <rule id="{new_rule_id}" level="0">
    <if_sid>{rule_id}</if_sid>
    <srcip>{attacker_ip}</srcip>
    <description>Auto-Muted by Tuning Engine</description>
  </rule>
"""

    tmp_path = "/tmp/local_rules.xml"
    os.system(f"sudo docker cp single-node-wazuh.manager-1:{WAZUH_RULES_PATH} {tmp_path}")
    
    with open(tmp_path, "r") as f:
        content = f.read()
        
    content = content.replace("</group>", f"{xml_block}\n</group>")
    
    with open(tmp_path, "w") as f:
        f.write(content)
        
    os.system(f"sudo docker cp {tmp_path} single-node-wazuh.manager-1:{WAZUH_RULES_PATH}")
    os.system("sudo docker restart single-node-wazuh.manager-1")

    return jsonify({"status": "Success", "applied_rule_id": new_rule_id, "message": "Wazuh restarted successfully."})

if __name__ == '__main__':
    # Listen on port 8000
    app.run(host='0.0.0.0', port=8000)
