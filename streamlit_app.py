import streamlit as st
import time
import json
import base64
import os
import uuid
import random
from datetime import datetime
from Crypto.PublicKey import RSA
from app.core import crypto, security
from app.db import database, models
import pandas as pd

# --- Page Configuration ---
st.set_page_config(
    page_title="Secure Digital Payment Authentication System",
    page_icon="⚡",
    layout="centered", 
    initial_sidebar_state="collapsed",
)

# --- Modern SaaS Dark Theme Custom CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    
    /* Full Page Background */
    .stApp {
        background: radial-gradient(circle at right center, rgba(14, 165, 233, 0.15), transparent 50%), linear-gradient(135deg, #0f172a 0%, #020617 100%) !important;
        color: #ffffff;
        font-family: 'Inter', sans-serif;
    }

    /* Hide top header and footer for cleaner app feel */
    header {visibility: hidden;}
    footer {visibility: hidden;}

    /* Global Dashboard Layout Wrapper (Wide, Transparent, Top-Aligned) */
    .block-container {
        padding: 2rem 1rem !important;
        background: transparent !important;
        backdrop-filter: none !important;
        -webkit-backdrop-filter: none !important;
        border: none !important;
        box-shadow: none !important;
        max-width: 95% !important; 
        margin-top: 2rem !important; 
        margin-bottom: 4rem !important;
    }
    
    @media (min-width: 600px) {
        .block-container {
            padding: 3rem 2rem !important;
            max-width: 760px !important; /* Comfortably wide open dashboard */
        }
    }

    /* Logo / Icon container */
    .logo-container {
        display: flex;
        justify-content: center;
        margin-bottom: 1.5rem;
    }
    .logo-badge {
        background: rgba(99, 102, 241, 0.15);
        width: 56px;
        height: 56px;
        border-radius: 14px;
        display: flex;
        align-items: center;
        justify-content: center;
        border: 1px solid rgba(99, 102, 241, 0.3);
        box-shadow: 0 0 20px rgba(99, 102, 241, 0.2);
    }

    /* Responsive Typography */
    .main-title {
        color: #ffffff;
        font-size: clamp(1.35rem, 5vw, 1.85rem);
        font-weight: 700;
        text-align: center;
        margin-bottom: 0.35rem;
        letter-spacing: -0.02em;
    }
    .sub-title {
        color: #9ca3af;
        font-size: clamp(0.85rem, 3.5vw, 0.95rem);
        text-align: center;
        margin-bottom: 2rem;
        font-weight: 400;
    }

    /* Hide Streamlit Instruction Overlays ('Press Enter to apply') */
    [data-testid="InputInstructions"],
    .stTextInput div > small,
    .stTextInput small {
        display: none !important;
        visibility: hidden !important;
    }

    /* Input Fields Wrapper */
    div[data-baseweb="input"] {
        background-color: transparent !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 16px !important; 
        min-height: 3.5rem !important; 
        align-items: center !important;
        transition: border 0.3s, box-shadow 0.3s !important;
        overflow: hidden !important; 
    }
    div[data-baseweb="input"]:focus-within {
        border-color: #8b5cf6 !important;
        box-shadow: 0 0 0 1px #8b5cf6 !important;
    }
    
    /* Labels */
    .stTextInput label, .stNumberInput label {
        color: #94a3b8 !important;
        font-size: 0.9rem !important;
        font-weight: 600 !important;
        margin-bottom: 0.4rem !important;
    }
    
    /* Text Inputs */
    .stTextInput input, .stNumberInput input {
        color: #f1f5f9 !important;
        background-color: transparent !important;
        padding: 0.85rem 1.25rem !important;
        font-size: 1.05rem !important;
        line-height: 1.5 !important;
    }

    /* Force deep internal Streamlit wrappers to remain entirely transparent */
    div[data-baseweb="base-input"] {
        background-color: transparent !important;
    }

    /* Block Chrome/Edge Autofill from injecting grey/yellow opaque bounding boxes */
    .stTextInput input:-webkit-autofill,
    .stTextInput input:-webkit-autofill:hover, 
    .stTextInput input:-webkit-autofill:focus, 
    .stTextInput input:-webkit-autofill:active {
        -webkit-text-fill-color: #f1f5f9 !important;
        transition: background-color 5000s ease-in-out 0s !important;
        background-color: transparent !important;
    }
    
    /* Placeholders */
    .stTextInput input::placeholder, .stNumberInput input::placeholder {
        color: #475569 !important; 
        letter-spacing: normal !important;
        font-weight: 400 !important;
    }
    
    /* Password Special Styling */
    .stTextInput input[type="password"] {
        letter-spacing: 0.4em !important;
        font-weight: 900 !important;
        color: #8b5cf6 !important;
    }
    
    /* Disable Internal Focus Rings */
    .stTextInput input:focus, .stNumberInput input:focus {
        border: none !important;
        box-shadow: none !important;
        outline: none !important;
    }
    
    /* Hide Browser Native Password Reveal Icons */
    input[type="password"]::-ms-reveal,
    input[type="password"]::-ms-clear,
    input[type="password"]::-webkit-reveal {
        display: none !important;
    }

    /* Isolate Password Toggle SVG securely without hitting the Clear Input X button */
    .stTextInput [data-testid="stTextInputPasswordToggle"] svg,
    .stTextInput button[aria-label*="password"] svg {
        display: none !important;
        visibility: hidden !important;
    }
    
    /* Base Font & Fallback styling solely for the password toggle button */
    .stTextInput [data-testid="stTextInputPasswordToggle"]:after,
    .stTextInput button[aria-label*="password"]:after {
        content: "👁️" !important; 
        font-size: 1.25rem !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        opacity: 0.85;
        transition: opacity 0.2s, transform 0.2s;
        margin-right: 2px;
    }
    
    /* Dynamic Toggle: Password Hidden -> Show Eye Emoji */
    .stTextInput:has(input[type="password"]) [data-testid="stTextInputPasswordToggle"]:after,
    .stTextInput:has(input[type="password"]) button[aria-label*="password"]:after {
        content: "👁️" !important;
    }
    
    /* Dynamic Toggle: Password Visible -> Show Closed Eye Emoji */
    .stTextInput:has(input[type="text"]) [data-testid="stTextInputPasswordToggle"]:after,
    .stTextInput:has(input[type="text"]) button[aria-label*="password"]:after {
        content: "🙈" !important;
    }

    /* Hover States / Feedback */
    .stTextInput [data-testid="stTextInputPasswordToggle"]:hover:after,
    .stTextInput button[aria-label*="password"]:hover:after {
        opacity: 1;
        transform: scale(1.1);
    }

    /* Single and Primary Buttons */
    .stButton button {
        background: linear-gradient(90deg, #6366f1, #7c3aed) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.75rem 1rem !important;
        font-weight: 600 !important;
        font-size: 1rem !important;
        width: 100% !important;
        margin-top: 1rem !important;
        transition: transform 0.2s ease, opacity 0.2s ease !important;
    }
    .stButton button:hover {
        opacity: 0.95 !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4) !important;
    }

    /* Secondary outline button styling using empty background trick */
    .secondary-btn button {
        background: rgba(255,255,255,0.05) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        box-shadow: none !important;
        color: #e2e8f0 !important;
    }
    .secondary-btn button:hover {
        background: rgba(255,255,255,0.1) !important;
    }

    /* Danger outline button */
    .danger-btn button {
        background: rgba(239, 68, 68, 0.1) !important;
        border: 1px solid rgba(239, 68, 68, 0.3) !important;
        color: #ef4444 !important;
        box-shadow: none !important;
    }
    .danger-btn button:hover {
        background: rgba(239, 68, 68, 0.2) !important;
    }

    /* Tab Layout Override */
    .stTabs [data-baseweb="tab-list"] {
        background-color: transparent;
        border-bottom: 2px solid rgba(255,255,255,0.05);
        gap: 1rem;
        margin-bottom: 1rem;
    }
    .stTabs [data-baseweb="tab"] {
        color: #9ca3af;
        padding: 0.5rem 1rem;
        font-weight: 500;
        background-color: transparent !important;
    }
    .stTabs [aria-selected="true"] {
        color: #fff !important;
        border-bottom-color: #8b5cf6 !important;
        background-color: transparent !important;
    }

    /* Footer text */
    .footer-text {
        text-align: center;
        color: #475569;
        font-size: 0.75rem;
        margin-top: 2rem;
        line-height: 1.4;
    }
</style>
""", unsafe_allow_html=True)


# --- Helpers ---
db = database.SessionLocal()
models.Base.metadata.create_all(database.engine)

class SessionUser:
    def __init__(self, u):
        self.user_id = u.user_id
        self.username = u.username
        self.account_number = u.account_number
        self.totp_secret = u.totp_secret

def navigate(page):
    st.session_state.page = page
    st.rerun()

def render_logo(svg_path, color="#8b5cf6"):
    st.markdown(f"""
        <div class="logo-container">
            <div class="logo-badge">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="{svg_path}"></path>
                </svg>
            </div>
        </div>
    """, unsafe_allow_html=True)


# --- State Management ---
if 'user' not in st.session_state: st.session_state.user = None
if 'page' not in st.session_state: st.session_state.page = "Login"
if 'txn_data' not in st.session_state: st.session_state.txn_data = None


# --- Page: Login ---
def page_login():
    # Force Login Page to strictly render as a floating glassmorphic card viewport
    st.markdown("""
    <style>
    .block-container {
        background: rgba(15, 23, 42, 0.65) !important;
        backdrop-filter: blur(16px) !important;
        -webkit-backdrop-filter: blur(16px) !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        border-radius: 20px !important;
        box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5) !important;
        margin-top: max(2rem, 12vh) !important;
        padding: 2rem 1.5rem !important;
    }
    @media (min-width: 600px) {
        .block-container {
            max-width: 440px !important;
            border-radius: 24px !important;
            margin-top: max(2rem, 18vh) !important;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5) !important;
            padding: 3rem 2.5rem !important;
        }
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Lightning Bolt Logo
    render_logo("M13 2L3 14h9l-1 8 10-12h-9l1-8z")
    
    st.markdown("<div class='main-title'>SecurePay Login</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Secure Digital Payment System</div>", unsafe_allow_html=True)
    
    tabs = st.tabs(["Login", "Sign Up"])
    
    with tabs[0]:
        u = st.text_input("Username / Email", key="login_u", value="")
        p = st.text_input("Password", type="password", key="login_p", placeholder="••••••••")
        if st.button("Log In", key="btn_signin"):
            user = db.query(models.User).filter(models.User.username == u).first()
            if user and security.verify_password(p, user.password_hash):
                st.session_state.user = SessionUser(user)
                print(f"\n[AUTH SERVICE] login SUCCESS for {u}")
                navigate("Dashboard")
            else:
                print(f"\n[AUTH SERVICE] login FAILED for {u}")
                st.error("Invalid credentials.")
                
    with tabs[1]:
        ru = st.text_input("Choose a Username", key="reg_u", placeholder="admin")
        rp = st.text_input("Create Password", type="password", key="reg_p", placeholder="••••••••")
        if st.button("Create Account", key="btn_reg"):
            secret = crypto.generate_totp_secret()
            # Generate a random starting balance between ₹5,000 and ₹150,000
            start_bal = round(random.uniform(5000.0, 150000.0), 2)
            acc_num = str(random.randint(1000000000, 9999999999))
            new = models.User(username=ru, account_number=acc_num, password_hash=security.get_password_hash(rp), totp_secret=secret, balance=start_bal)
            db.add(new)
            db.commit()
            st.success("Account successfully created.")
            st.info(f"Your Account Number is: **{acc_num}** (Give this to others so they can pay you)")
            st.warning(f"Please save this 2FA Secret Key for your Authenticator App: {secret}")


# --- Page: Dashboard ---
def page_dashboard():
    st.markdown("<div class='main-title'>Dashboard</div>", unsafe_allow_html=True)
    
    # Fetch fresh user data from DB for accurate balance
    current_user = db.query(models.User).filter(models.User.user_id == st.session_state.user.user_id).first()
    st.session_state.user = SessionUser(current_user)
    
    st.markdown(f"<div class='sub-title'>Acc. No: {current_user.account_number} | Username: {current_user.username}</div>", unsafe_allow_html=True)
    st.markdown(f"<div style='text-align: center; color: #fff; font-size: 2.25rem; font-weight: 700; margin-bottom: 2rem;'>₹{current_user.balance:,.2f}</div>", unsafe_allow_html=True)
    
    if st.button("Send Money"): navigate("Payment")
    
    st.markdown("<div class='secondary-btn'>", unsafe_allow_html=True)
    if st.button("View Past Transactions"): navigate("History")
    st.markdown("</div>", unsafe_allow_html=True)
    
    st.markdown("<div class='danger-btn'>", unsafe_allow_html=True)
    if st.button("Log Out"):
        st.session_state.user = None
        navigate("Login")
    st.markdown("</div>", unsafe_allow_html=True)


# --- Page: Payment ---
def page_payment():
    # Send icon
    render_logo("M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z", color="#0ea5e9")
    
    st.markdown("<div class='main-title'>Send Money</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Secure Encrypted Transfer</div>", unsafe_allow_html=True)
    
    rec = st.text_input("Recipient Account Number", placeholder="e.g. 1234567890")
    amt = st.number_input("Amount (INR)", min_value=1.0, value=1000.0, step=100.0)
    
    if st.button("Proceed to Pay"):
        if not rec:
            st.error("Invalid destination.")
        else:
            recipient_node = db.query(models.User).filter(models.User.account_number == rec).first()
            if not recipient_node:
                st.error("Account Number not found in system.")
            elif hasattr(st.session_state.user, 'account_number') and rec == str(st.session_state.user.account_number):
                st.error("You cannot send money to yourself.")
            else:
                print("\n[TRANSACTION SERVICE] Initiating crypto handshake...")
                aes_key = crypto.generate_aes_key()
                payload = json.dumps({"u": st.session_state.user.user_id, "amount": amt, "rec": rec, "ts": datetime.now().isoformat()})
                enc_payload = crypto.encrypt_aes(aes_key, payload)
                hmac_val = crypto.generate_hmac(aes_key, json.dumps(enc_payload))
                with open("public_key.pem", "r") as f: pub_key = f.read()
                wrapped_key = crypto.encrypt_rsa(pub_key, aes_key)
                txn_id = "TXN-" + str(uuid.uuid4().hex)[:8].upper()
    
                st.session_state.txn_data = {
                    "txn_id": txn_id, "aes_key": aes_key.hex(), "enc": enc_payload,
                    "hmac": hmac_val, "wrapped": wrapped_key, "amount": amt, "receiver": rec
                }
                navigate("Confirmation")
    
    st.markdown("<div class='secondary-btn'>", unsafe_allow_html=True)
    if st.button("Cancel"): navigate("Dashboard")
    st.markdown("</div>", unsafe_allow_html=True)


# --- Page: Confirmation ---
def page_confirmation():
    # Shield icon
    render_logo("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z", color="#fbbf24")
    
    st.markdown("<div class='main-title'>Security Verification</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Please confirm your identity to proceed with the payment.</div>", unsafe_allow_html=True)
    
    if st.button("Continue"):
        navigate("OTP_Verify")


# --- Page: OTP Verification ---
def page_otp_verify():
    st.markdown("<div class='main-title'>Two-Factor Authentication</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Enter the code from your Authenticator app.</div>", unsafe_allow_html=True)
    
    otp = st.text_input("6-Digit Code", max_chars=6, placeholder="000000")
    
    if st.button("Confirm Payment"):
        data = st.session_state.txn_data
        aes_key = bytes.fromhex(data['aes_key'])
        
        # 1. Anti-Replay Attack Check
        print("\n[SECURITY ENGINE] Validating Transaction Nonce uniqueness...")
        existing_txn = db.query(models.Transaction).filter(models.Transaction.txn_id == data['txn_id']).first()
        if existing_txn:
            st.session_state.fail_reason = f"Security Violation: Duplicate Transaction ID Detected ({data['txn_id']}). Request Rejected due to Replay Attack."
            print("FAILED: REPLAY ATTACK (DUPLICATE TXN ID)")
            navigate("Failure")
            return
            
        # 2. Tampering & Integrity Check
        print("\n[CRYPTO ENGINE] Performing integrity check...")
        if crypto.verify_hmac(aes_key, json.dumps(data['enc']), data['hmac']):
            print("[OTP SERVICE] Verifying TOTP...")
            if crypto.verify_totp(st.session_state.user.totp_secret, otp):
                # 3. Balance verification & deduction
                db_sender = db.query(models.User).filter(models.User.user_id == st.session_state.user.user_id).first()
                if db_sender.balance < data['amount']:
                    st.session_state.fail_reason = "Insufficient Balance."
                    print("FAILED: Insufficient Balance")
                    navigate("Failure")
                    return
                
                # Deduct balance from sender
                db_sender.balance -= data['amount']
                db.add(db_sender)
                
                # Add balance to receiver if they exist as a user
                db_receiver = db.query(models.User).filter(models.User.account_number == data['receiver']).first()
                if db_receiver:
                    db_receiver.balance += data['amount']
                    db.add(db_receiver)

                new_t = models.Transaction(
                    txn_id=data['txn_id'], user_id=st.session_state.user.user_id,
                    amount=data['amount'], receiver=data['receiver'],
                    encrypted_data=json.dumps(data['enc']), hmac_value=data['hmac'],
                    status="SUCCESS"
                )
                db.add(new_t)
                db.commit()
                
                # Update session
                st.session_state.user = SessionUser(db_sender)
                print("Transaction SUCCESS.")
                navigate("Success")
            else:
                st.session_state.fail_reason = "Authentication Failed: Incorrect Token"
                print("FAILED: Wrong OTP")
                navigate("Failure")
        else:
            st.session_state.fail_reason = "Security Violation: Integrity Mismatch"
            print("FAILED: HMAC INTEGRITY CHECK")
            navigate("Failure")
            
    st.markdown("<div class='secondary-btn'>", unsafe_allow_html=True)
    if st.button("Cancel"): navigate("Dashboard")
    st.markdown("</div>", unsafe_allow_html=True)


# --- Page: Success ---
def page_success():
    # Check icon
    render_logo("M20 6L9 17l-5-5", color="#10b981")
    
    st.markdown("<div class='main-title' style='color:#10b981;'>Payment Successful</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Your money has been securely transferred.</div>", unsafe_allow_html=True)
    
    d = st.session_state.txn_data
    st.markdown(f"<div class='footer-text'>Transaction ID: {d['txn_id']}<br>Recipient: {d['receiver']}<br>Amount: ₹{d['amount']}</div>", unsafe_allow_html=True)
        
    if st.button("Back to Dashboard"): navigate("Dashboard")


# --- Page: Failure ---
def page_failure():
    # X icon
    render_logo("M18 6L6 18M6 6l12 12", color="#ef4444")
    
    st.markdown("<div class='main-title' style='color:#ef4444;'>Payment Failed</div>", unsafe_allow_html=True)
    
    msg = st.session_state.get('fail_reason', 'Security protocols blocked the request.')
    st.markdown(f"<div class='sub-title' style='color:#fca5a5;'>Reason: {msg}</div>", unsafe_allow_html=True)
    
    if st.button("Try Again"): navigate("Payment")
    
    st.markdown("<div class='secondary-btn'>", unsafe_allow_html=True)
    if st.button("Back to Dashboard"): navigate("Dashboard")
    st.markdown("</div>", unsafe_allow_html=True)


# --- Page: History ---
def page_history():
    st.markdown("<div class='main-title'>Transaction History</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Record of your past payments</div>", unsafe_allow_html=True)
    
    from sqlalchemy import or_
    uid = st.session_state.user.user_id
    acc = st.session_state.user.account_number
    
    txns = db.query(models.Transaction).filter(
        or_(
            models.Transaction.user_id == uid,
            models.Transaction.receiver == acc
        )
    ).order_by(models.Transaction.timestamp.desc()).all()
    
    if txns:
        data = []
        for t in txns:
            is_sender = (t.user_id == uid)
            data.append({
                "Transaction ID": t.txn_id,
                "Type": "Sent" if is_sender else "Received",
                "Amount": f"-₹{t.amount}" if is_sender else f"+₹{t.amount}",
                "Counterparty": t.receiver if is_sender else "Received from system",
                "Status": t.status,
                "Date & Time": t.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })
        st.dataframe(pd.DataFrame(data), use_container_width=True, hide_index=True)
    else:
        st.markdown("<div class='sub-title'>No transaction history found.</div>", unsafe_allow_html=True)
        
    st.markdown("<div class='secondary-btn'>", unsafe_allow_html=True)
    if st.button("Back to Dashboard"): navigate("Dashboard")
    st.markdown("</div>", unsafe_allow_html=True)


# --- Route Logic ---
try:
    if st.session_state.get('user') is None:
        page_login()
    else:
        p = st.session_state.page
        if p == "Dashboard": page_dashboard()
        elif p == "Payment": page_payment()
        elif p == "Confirmation": page_confirmation()
        elif p == "OTP_Verify": page_otp_verify()
        elif p == "Success": page_success()
        elif p == "Failure": page_failure()
        elif p == "History": page_history()
        else: page_dashboard()
finally:
    db.close()

