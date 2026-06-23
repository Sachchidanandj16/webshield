from typing import List, Dict, Any

def calculate_compliance_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculates an overall security score from 0 to 100.
    Starts at 100, and subtracts weighted points based on non-compliant items.
    """
    score = 100
    deductions = {
        "Critical": 25,
        "High": 15,
        "Medium": 10,
        "Low": 5,
        "Info": 0
    }
    
    for finding in findings:
        if finding.get("status") not in ["Compliant", "No Action Required"]:
            severity = finding.get("severity", "Info")
            score -= deductions.get(severity, 0)
            
    # Normalize lower boundaries
    return max(0, score)