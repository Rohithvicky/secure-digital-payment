from sqlalchemy.orm import Session
from app.db import models
import datetime

def log_event(db: Session, event_type: str, description: str, user_id: int = None, ip_address: str = None):
    """
    Logs a security event to the audit_logs table.
    """
    new_log = models.AuditLog(
        event_type=event_type,
        user_id=user_id,
        description=description,
        ip_address=ip_address,
        timestamp=datetime.datetime.utcnow()
    )
    db.add(new_log)
    db.commit()
