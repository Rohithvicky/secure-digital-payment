import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float
from app.db.database import Base

class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    account_number = Column(String, unique=True, index=True)
    password_hash = Column(String)
    public_key = Column(Text, nullable=True)  # Client's RSA public key (if applicable)
    totp_secret = Column(String, nullable=True) # Used for OTP functionality
    balance = Column(Float, default=25000.0) # User's current account balance

class Transaction(Base):
    __tablename__ = "transactions"

    txn_id = Column(String, primary_key=True, index=True)  # Using String for unique text-based ID (UUID or generated)
    user_id = Column(Integer, ForeignKey("users.user_id"))
    amount = Column(Integer)  # Requested field
    receiver = Column(String)  # Requested field
    encrypted_data = Column(Text) # The AES-encrypted JSON string representation of the transaction payload
    hmac_value = Column(String)
    status = Column(String, default="PENDING")
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class OtpLog(Base):
    """
    Tracks OTP generation logs and status.
    """
    __tablename__ = "otp_logs"

    otp_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"))
    txn_id = Column(String, ForeignKey("transactions.txn_id"), nullable=True)
    hashed_otp = Column(String, nullable=True)
    expiry_time = Column(DateTime)
    used = Column(Boolean, default=False)
    attempts = Column(Integer, default=0)

class AuditLog(Base):
    """
    Records security-sensitive events for auditing.
    """
    __tablename__ = "audit_logs"

    log_id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String)  # LOGIN_SUCCESS, PAYMENT_INIT, HMAC_FAILURE, etc.
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=True)
    description = Column(Text)
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class UsedNonce(Base):
    """
    Prevents Replay Attacks by tracking used nonces.
    """
    __tablename__ = "used_nonces"

    id = Column(Integer, primary_key=True, index=True)
    nonce = Column(String, unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
