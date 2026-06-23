from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    target_url = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    overall_score = Column(Integer, nullable=False)  # Derived value from 0 to 100
    
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    category = Column(String, nullable=False)          # e.g., "HTTP Header", "SSL/TLS"
    item_checked = Column(String, nullable=False)      # e.g., "X-Frame-Options", "Cert Expiration"
    status = Column(String, nullable=False)            # e.g., "Missing", "Weak", "Compliant"
    severity = Column(String, nullable=False)          # e.g., "High", "Medium", "Low", "Info"
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    
    scan = relationship("Scan", back_populates="findings")