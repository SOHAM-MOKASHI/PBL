from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import json
import logging

Base = declarative_base()

class Alert(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)
    timestamp = Column(Float)
    src_ip = Column(String)
    dst_ip = Column(String)
    dst_port = Column(Integer)
    protocol = Column(String)
    threat_score = Column(Float)
    severity = Column(String)
    attack_label = Column(String)
    raw_log = Column(JSON)
    
    xai = relationship("XAINarrative", back_populates="alert", uselist=False)

class XAINarrative(Base):
    __tablename__ = 'xai_narratives'
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, ForeignKey('alerts.alert_id'))
    mitre_technique_id = Column(String)
    mitre_technique_name = Column(String)
    mitre_tactic = Column(String)
    narrative = Column(String)
    playbook = Column(String)
    confidence = Column(Float)
    
    alert = relationship("Alert", back_populates="xai")

class Config(Base):
    __tablename__ = 'configs'
    key = Column(String, primary_key=True, index=True)
    value = Column(JSON)

engine = create_engine('sqlite:///soc_prototype.db', connect_args={'check_same_thread': False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Create all tables in the SQLite database"""
    Base.metadata.create_all(bind=engine)

def save_alert(alert_data: dict):
    """Save a processed alert and its XAI narrative to the database"""
    db = SessionLocal()
    try:
        raw_log = {k: v for k, v in alert_data.items() if k != "xai"}
        db_alert = Alert(
            alert_id=alert_data.get("alert_id"),
            timestamp=alert_data.get("timestamp"),
            src_ip=alert_data.get("src_ip"),
            dst_ip=alert_data.get("dst_ip"),
            dst_port=alert_data.get("dst_port"),
            protocol=alert_data.get("protocol"),
            threat_score=alert_data.get("threat_score"),
            severity=alert_data.get("severity"),
            attack_label=alert_data.get("attack_label", "DEFAULT"),
            raw_log=raw_log
        )
        db.add(db_alert)
        
        xai_data = alert_data.get("xai")
        if xai_data:
            db_xai = XAINarrative(
                alert_id=alert_data.get("alert_id"),
                mitre_technique_id=xai_data.get("mitre_technique_id"),
                mitre_technique_name=xai_data.get("mitre_technique_name"),
                mitre_tactic=xai_data.get("mitre_tactic"),
                narrative=xai_data.get("narrative"),
                playbook=xai_data.get("playbook"),
                confidence=xai_data.get("confidence")
            )
            db.add(db_xai)
        
        db.commit()
    except Exception as e:
        logging.error(f"Failed to save alert to DB: {e}")
        db.rollback()
    finally:
        db.close()

def save_config(threshold: float, whitelist: set):
    """Persist threshold and whitelist to the database"""
    db = SessionLocal()
    try:
        conf = db.query(Config).filter_by(key="threshold").first()
        if not conf:
            conf = Config(key="threshold", value=threshold)
            db.add(conf)
        else:
            conf.value = threshold
            
        wl = db.query(Config).filter_by(key="whitelist").first()
        if not wl:
            wl = Config(key="whitelist", value=list(whitelist))
            db.add(wl)
        else:
            wl.value = list(whitelist)
            
        db.commit()
    except Exception as e:
        logging.error(f"Failed to save config to DB: {e}")
        db.rollback()
    finally:
        db.close()

def load_config():
    """Load threshold and whitelist from database on startup"""
    db = SessionLocal()
    try:
        t = db.query(Config).filter_by(key="threshold").first()
        w = db.query(Config).filter_by(key="whitelist").first()
        return (t.value if t else 85.0), (set(w.value) if w else set())
    finally:
        db.close()
