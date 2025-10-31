# database/models.py

from flask_login import UserMixin
from passlib.hash import bcrypt
from datetime import datetime
from sqlalchemy import CheckConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import BIGINT as MyBigInt
import enum
from datetime import date

# Import the shared SQLAlchemy instance
from . import db


# ---------- Users ----------
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name  = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    # Relationships
    customer = relationship("Customer", back_populates="user", uselist=False)

    def set_password(self, password: str) -> None:
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password: str) -> bool:
        return bcrypt.verify(password, self.password_hash)


# ---------- Roles ----------
class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)  # CUSTOMER, EMPLOYEE, ADMIN


class UserRole(db.Model):
    __tablename__ = "user_roles"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    user_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("users.id"), nullable=False, index=True)
    role_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("roles.id"), nullable=False, index=True)


# ---------- Enums ----------
class KYCStatus(enum.Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class AccountStatus(enum.Enum):
    APPROVAL_PENDING = "APPROVAL_PENDING"
    ACTIVE = "ACTIVE"
    FROZEN = "FROZEN"


class TxType(enum.Enum):
    DEPOSIT = "DEPOSIT"
    TRANSFER = "TRANSFER"
    LOAN_DISBURSAL = "LOAN_DISBURSAL"
    EMI_PAYMENT = "EMI_PAYMENT"


class TxStatus(enum.Enum):
    PENDING = "PENDING"
    POSTED = "POSTED"
    FAILED = "FAILED"


class RequestStatus(enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class LoanStatus(enum.Enum):
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"
    DEFAULT = "DEFAULT"


# Reference GL codes
GL_CASH_VAULT = "CASH_VAULT"
GL_BANK_LOAN = "BANK_LOAN_GL"


# ---------- Customer / Branch / Accounts ----------
class Customer(db.Model):
    __tablename__ = "customers"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    user_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("users.id"), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(160), nullable=False)
    phone = db.Column(db.String(24))
    address = db.Column(db.Text)
    kyc_status = db.Column(db.Enum(KYCStatus), nullable=False, default=KYCStatus.PENDING)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    # Relationships
    user = relationship("User", back_populates="customer")
    accounts = relationship("Account", back_populates="customer", cascade="all, delete-orphan")
    account_requests = relationship("AccountRequest", back_populates="customer", cascade="all, delete-orphan")
    loan_applications = relationship("LoanApplication", back_populates="customer", cascade="all, delete-orphan")
    loans = relationship("Loan", back_populates="customer", cascade="all, delete-orphan")
    credit_card_applications = relationship("CreditCardApplication", back_populates="customer", cascade="all, delete-orphan")


class Branch(db.Model):
    __tablename__ = "branches"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)   # e.g., B001
    name = db.Column(db.String(120), nullable=False)
    ifsc = db.Column(db.String(16), unique=True, nullable=False)
    address = db.Column(db.Text)

    # Relationships
    accounts = relationship("Account", back_populates="branch")
    requests = relationship("AccountRequest", back_populates="branch")
    number_seq = relationship("AccountNumberSeq", back_populates="branch", uselist=False)


class AccountNumberSeq(db.Model):
    __tablename__ = "account_number_seq"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    branch_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("branches.id"), nullable=False, unique=True)
    next_serial = db.Column(MyBigInt(unsigned=True), nullable=False, default=1000000001)

    # Relationships
    branch = relationship("Branch", back_populates="number_seq")


class AccountRequest(db.Model):
    __tablename__ = "account_requests"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    customer_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("customers.id"), nullable=False, index=True)
    branch_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("branches.id"), nullable=False)

    # Product / account type
    product = db.Column(db.String(32), nullable=False)  # SAVINGS, CURRENT, SALARY, JOINT

    # KYC + form fields
    dob = db.Column(db.Date, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    aadhaar_no = db.Column(db.String(12), nullable=False)      # 12 digits
    pan_no = db.Column(db.String(10), nullable=False)           # e.g., ABCDE1234F
    perm_address = db.Column(db.Text, nullable=False)           # with PIN code
    comm_address = db.Column(db.Text, nullable=True)            # if different
    occupation_type = db.Column(db.String(30), nullable=False)  # Salaried/Self-Employed/Student/Retired
    annual_income_range = db.Column(db.String(30), nullable=False)

    # Uploaded document paths (relative)
    aadhaar_file_path = db.Column(db.String(255))
    pan_file_path = db.Column(db.String(255))
    photo_file_path = db.Column(db.String(255))

    status = db.Column(db.Enum(RequestStatus), nullable=False, default=RequestStatus.PENDING)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    # Relationships
    customer = relationship("Customer", back_populates="account_requests")
    branch = relationship("Branch", back_populates="requests")


class Account(db.Model):
    __tablename__ = "accounts"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    customer_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("customers.id"), nullable=False, index=True)
    branch_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("branches.id"), nullable=False)
    account_no = db.Column(db.String(32), unique=True, nullable=False, index=True)
    product = db.Column(db.String(32), nullable=False)
    status = db.Column(db.Enum(AccountStatus), nullable=False, default=AccountStatus.APPROVAL_PENDING)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    # Relationships
    customer = relationship("Customer", back_populates="accounts")
    branch = relationship("Branch", back_populates="accounts", lazy="joined")
    ib = relationship("InternetBanking", back_populates="account", uselist=False, cascade="all, delete-orphan")
    ledger_entries = relationship("LedgerEntry", back_populates="account", cascade="all, delete-orphan")


# ---------- Internet Banking (per account) ----------
class InternetBanking(db.Model):
    __tablename__ = "internet_banking"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    account_id = db.Column(
        MyBigInt(unsigned=True),
        db.ForeignKey("accounts.id"),
        nullable=False,
        unique=True,
        index=True,
    )
    pin_hash = db.Column(db.String(255), nullable=False)
    pin_hint = db.Column(db.String(2))  # store ONLY last 2 digits for display
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    # Relationships
    account = relationship("Account", back_populates="ib")


# ---------- Transactions & Ledger ----------
class Transaction(db.Model):
    __tablename__ = "transactions"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    type = db.Column(db.Enum(TxType), nullable=False)
    status = db.Column(db.Enum(TxStatus), nullable=False, default=TxStatus.PENDING)
    created_by = db.Column(MyBigInt(unsigned=True), db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())


class LedgerEntry(db.Model):
    __tablename__ = "ledger_entries"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    transaction_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("transactions.id"), nullable=False, index=True)
    account_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("accounts.id"), nullable=True, index=True)
    gl_code = db.Column(db.String(64), nullable=True)  # e.g., CASH_VAULT, BANK_LOAN_GL
    dr_cr = db.Column(db.String(2), nullable=False)    # "DR" or "CR"
    amount = db.Column(db.Numeric(14, 2), nullable=False)
    posted_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    __table_args__ = (
        CheckConstraint("(account_id IS NOT NULL) OR (gl_code IS NOT NULL)", name="chk_account_or_gl"),
    )

    # Relationships
    account = relationship("Account", back_populates="ledger_entries")


# ---------- Loans ----------
class LoanApplication(db.Model):
    __tablename__ = "loan_applications"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    customer_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("customers.id"), nullable=False, index=True)
    amount = db.Column(db.Numeric(14, 2), nullable=False)
    product = db.Column(db.String(32), nullable=False)   # PERSONAL, EDUCATION...
    purpose = db.Column(db.Text, nullable=True)          # <-- required by /api/loans/apply
    pan_num = db.Column(db.String(10), nullable=True)     # match DB column
    aadhaar_no = db.Column(db.String(12), nullable=True)     # new column
    occupation = db.Column(db.String(120), nullable=True)    # match DB size

    status = db.Column(db.Enum(RequestStatus), nullable=False, default=RequestStatus.PENDING)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    # Relationships
    customer = relationship("Customer", back_populates="loan_applications")


class LoanApplicationDetail(db.Model):
    __tablename__ = "loan_application_details"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    application_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("loan_applications.id"), unique=True, nullable=False, index=True)

    tenure_months = db.Column(db.Integer, nullable=False, default=12)
    purpose = db.Column(db.Text)
    monthly_income = db.Column(db.Numeric(14, 2))
    employment_type = db.Column(db.String(32))  # SALARIED/SELF/OTHER
    rate_pa = db.Column(db.Numeric(5, 2))       # set during approval
    stage = db.Column(db.String(24), nullable=False, default="SUBMITTED")  # SUBMITTED/UNDER_REVIEW/APPROVED/REJECTED

    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())


class LoanApplicationDoc(db.Model):
    __tablename__ = "loan_application_docs"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    application_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("loan_applications.id"), nullable=False, index=True)
    doc_type = db.Column(db.String(32), nullable=False)  # AADHAAR, PAN, INCOME_PROOF, PHOTO
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())


class LoanAppHistory(db.Model):
    __tablename__ = "loan_app_history"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    application_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("loan_applications.id"), nullable=False, index=True)
    from_stage = db.Column(db.String(24))
    to_stage = db.Column(db.String(24), nullable=False)
    remarks = db.Column(db.Text)
    actor_user_id = db.Column(MyBigInt(unsigned=True))
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())


class Loan(db.Model):
    __tablename__ = "loans"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    customer_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("customers.id"), nullable=False, index=True)
    principal = db.Column(db.Numeric(14, 2), nullable=False)
    rate_pa = db.Column(db.Numeric(5, 2), nullable=False)  # % per annum
    term_months = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Enum(LoanStatus), nullable=False, default=LoanStatus.ACTIVE)
    start_date = db.Column(db.Date, nullable=False, default=date.today)

    # Relationships
    customer = relationship("Customer", back_populates="loans")


class RepaymentSchedule(db.Model):
    __tablename__ = "repayment_schedule"
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    loan_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("loans.id"), nullable=False, index=True)
    due_date = db.Column(db.Date, nullable=False)
    emi = db.Column(db.Numeric(14, 2), nullable=False)
    principal_part = db.Column(db.Numeric(14, 2), nullable=False)
    interest_part = db.Column(db.Numeric(14, 2), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="PENDING")  # PENDING/PAID/LATE



# ---------- Credit Card Applications ----------
# ---------- Credit Card Applications ----------
class CreditCardApplication(db.Model):
    __tablename__ = "credit_card_applications"

    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    customer_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("customers.id"), nullable=False)
    account_no = db.Column(db.String(32), nullable=False)
    card_type = db.Column(db.String(32), nullable=False)
    delivery_address = db.Column(db.Text, nullable=True)
    monthly_income = db.Column(db.Numeric(14, 2), nullable=False)
    employment_type = db.Column(db.String(32), nullable=False)
    company_name = db.Column(db.String(120))
    designation = db.Column(db.String(80))
    preferred_limit = db.Column(db.Numeric(14, 2), nullable=False, default=0)
    requested_limit = db.Column(db.Numeric(14, 2), nullable=True)   # ✅ keep only this one
    approved_limit = db.Column(db.Numeric(14, 2))
    pincode = db.Column(db.String(6))
    pan_file_path = db.Column(db.String(255))
    aadhaar_file_path = db.Column(db.String(255))
    income_proof_file_path = db.Column(db.String(255))
    status = db.Column(db.Enum(RequestStatus), default=RequestStatus.PENDING, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)




    # Relationships
    customer = relationship("Customer", back_populates="credit_card_applications")


# ---------- Debit Card Applications ----------
class DebitCardApplication(db.Model):
    __tablename__ = "debit_card_applications"

    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    customer_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("customers.id"), nullable=False)
    account_no = db.Column(db.String(32), nullable=False)
    card_type = db.Column(db.String(32), nullable=False)
    card_network = db.Column(db.String(32), nullable=False)   # ✅ NEW field
    delivery_address = db.Column(db.Text, nullable=True)
    monthly_income = db.Column(db.Numeric(14, 2), nullable=False)
    employment_type = db.Column(db.String(32), nullable=False)
    preferred_limit = db.Column(db.Numeric(14, 2), nullable=False, default=0)
    requested_limit = db.Column(db.Numeric(14, 2))
    approved_limit = db.Column(db.Numeric(14, 2))
    pincode = db.Column(db.String(6))
    pan_file_path = db.Column(db.String(255))
    aadhaar_file_path = db.Column(db.String(255))
    status = db.Column(db.Enum(RequestStatus), default=RequestStatus.PENDING, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    customer = relationship("Customer", backref="debit_card_applications")


# ---------- SIP (Systematic Investment Plan) ----------
class SIPApplication(db.Model):
    __tablename__ = "sip_applications"
    
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    customer_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("customers.id"), nullable=False, index=True)
    account_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("accounts.id"), nullable=False, index=True)
    
    # SIP Details
    fund_name = db.Column(db.String(120), nullable=False)  # e.g., "Equity Fund", "Debt Fund", "Hybrid Fund"
    fund_type = db.Column(db.String(32), nullable=False)   # EQUITY, DEBT, HYBRID
    monthly_amount = db.Column(db.Numeric(14, 2), nullable=False)
    tenure_months = db.Column(db.Integer, nullable=False)  # SIP duration in months
    start_date = db.Column(db.Date, nullable=False)
    
    # Expected returns (for display)
    expected_return_pa = db.Column(db.Numeric(5, 2), nullable=False)  # Expected return % per annum
    
    # Status and tracking
    status = db.Column(db.Enum(RequestStatus), default=RequestStatus.PENDING, nullable=False)
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    current_value = db.Column(db.Numeric(14, 2), default=0)
    total_invested = db.Column(db.Numeric(14, 2), default=0)
    
    # Documents
    kyc_file_path = db.Column(db.String(255))
    
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    
    # Relationships
    customer = relationship("Customer", backref="sip_applications")
    account = relationship("Account", backref="sip_applications")


class SIPTransaction(db.Model):
    __tablename__ = "sip_transactions"
    
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    sip_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("sip_applications.id"), nullable=False, index=True)
    account_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("accounts.id"), nullable=False, index=True)
    
    # Transaction details
    amount = db.Column(db.Numeric(14, 2), nullable=False)
    transaction_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Enum(TxStatus), default=TxStatus.PENDING, nullable=False)
    
    # Market simulation (for demo purposes)
    nav_at_purchase = db.Column(db.Numeric(8, 4))  # Net Asset Value
    units_purchased = db.Column(db.Numeric(14, 6))
    
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    
    # Relationships
    sip = relationship("SIPApplication", backref="transactions")
    account = relationship("Account", backref="sip_transactions")


# ---------- Sovereign Gold Bonds (SGB) ----------
class SGBApplication(db.Model):
    __tablename__ = "sgb_applications"
    
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    customer_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("customers.id"), nullable=False, index=True)
    account_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("accounts.id"), nullable=False, index=True)
    
    # SGB Details
    series = db.Column(db.String(50), nullable=False)  # e.g., "SGB Series 2024-25"
    investment_amount = db.Column(db.Numeric(14, 2), nullable=False)
    units = db.Column(db.Numeric(10, 4), nullable=False)  # Grams of gold
    pan_number = db.Column(db.String(10), nullable=False)  # PAN number
    
    # Current status and tracking
    status = db.Column(db.Enum(RequestStatus), default=RequestStatus.PENDING, nullable=False)
    current_value = db.Column(db.Numeric(14, 2), default=0)
    interest_earned = db.Column(db.Numeric(14, 2), default=0)
    
    # Documents
    kyc_file_path = db.Column(db.String(255))
    
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    
    # Relationships
    customer = relationship("Customer", backref="sgb_applications")
    account = relationship("Account", backref="sgb_applications")


class SGBTransaction(db.Model):
    __tablename__ = "sgb_transactions"
    
    id = db.Column(MyBigInt(unsigned=True), primary_key=True)
    sgb_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("sgb_applications.id"), nullable=False, index=True)
    account_id = db.Column(MyBigInt(unsigned=True), db.ForeignKey("accounts.id"), nullable=False, index=True)
    
    # Transaction details
    transaction_type = db.Column(db.String(20), nullable=False)  # PURCHASE, INTEREST, MATURITY, EXIT
    amount = db.Column(db.Numeric(14, 2), nullable=False)
    transaction_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Enum(TxStatus), default=TxStatus.PENDING, nullable=False)
    
    # Gold price at transaction
    gold_price_per_gram = db.Column(db.Numeric(10, 2))
    
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    
    # Relationships
    sgb = relationship("SGBApplication", backref="transactions")
    account = relationship("Account", backref="sgb_transactions")
