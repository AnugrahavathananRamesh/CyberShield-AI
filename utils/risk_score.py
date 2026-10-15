"""
Risk scoring.

IMPORTANT: the severity weights and the LOW/MEDIUM/HIGH thresholds below are
PROTOTYPE values chosen for this academic project. They are NOT an industry
or universal cybersecurity standard.

Risk score = 100 * sum( P(class) * severity(class) )
where P(class) is the probability the Random Forest gives to each class.
"""

SEVERITY = {
    "Normal": 0.00,
    "Port Scan": 0.55,
    "Brute Force": 0.90,
    "Data Exfiltration": 0.95,
    "DoS": 1.00,
}

LOW_MAX = 30      # 0-30   -> Low
MEDIUM_MAX = 70   # 31-70  -> Medium, 71-100 -> High

THREAT_NAMES = {
    "Normal": "None",
    "Port Scan": "Possible Port Scan",
    "Brute Force": "Possible Brute Force",
    "Data Exfiltration": "Possible Data Exfiltration",
    "DoS": "Possible DoS Attack",
}


def calculate_risk_score(probabilities):
    """probabilities: {class_name: probability}. Returns an int from 0 to 100."""
    score = sum(p * SEVERITY.get(name, 0.5) for name, p in probabilities.items())
    return int(round(max(0.0, min(1.0, score)) * 100))


def get_risk_level(score):
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"
