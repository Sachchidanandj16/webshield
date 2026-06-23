from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import datetime

from app.database import engine, get_db
from app.models import Base, Scan, Finding
from app.auditors.header_auditor import audit_http_headers
from app.auditors.ssl_auditor import audit_ssl_certificate
from app.utils.scoring import calculate_compliance_score

app = FastAPI(title="WebShield Compliance Auditor API")

class AuditRequest(BaseModel):
    url: str

@app.post("/api/v1/audit")
def trigger_audit(payload: AuditRequest, db: Session = Depends(get_db)):
    url = payload.url
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
        
    # Execute non-intrusive scans
    header_findings = audit_http_headers(url)
    ssl_findings = audit_ssl_certificate(url)
    
    all_findings = header_findings + ssl_findings
    score = calculate_compliance_score(all_findings)
    
    # Save results to DB
    scan_record = Scan(target_url=url, overall_score=score, timestamp=datetime.datetime.utcnow())
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)
    
    for item in all_findings:
        finding_record = Finding(
            scan_id=scan_record.id,
            category=item["category"],
            item_checked=item["item_checked"],
            status=item["status"],
            severity=item["severity"],
            description=item["description"],
            recommendation=item["recommendation"]
        )
        db.add(finding_record)
        
    db.commit()
    
    return {
        "scan_id": scan_record.id,
        "target_url": scan_record.target_url,
        "overall_score": scan_record.overall_score,
        "findings_count": len(all_findings),
        "timestamp": scan_record.timestamp.isoformat()
    }

@app.get("/api/v1/history")
def get_history(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.timestamp.desc()).all()
    results = []
    for s in scans:
        results.append({
            "id": s.id,
            "target_url": s.target_url,
            "score": s.overall_score,
            "date": s.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    return results