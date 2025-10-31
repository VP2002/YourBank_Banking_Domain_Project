# backend/api.py
from decimal import Decimal, InvalidOperation
from datetime import datetime, date
import os
from flask_migrate import Migrate

from flask import Blueprint, request, jsonify, current_app, abort, send_from_directory
from flask_login import login_required, current_user
from sqlalchemy import func, desc, and_, or_
from sqlalchemy.orm import joinedload
from passlib.hash import bcrypt
from werkzeug.utils import secure_filename

# Models
from database.models import (
    db,
    Customer,
    Branch,
    AccountRequest,
    Account,
    LedgerEntry,
    Transaction,
    AccountNumberSeq,
    Role,
    UserRole,
    AccountStatus,
    RequestStatus,
    TxType,
    TxStatus,
    GL_CASH_VAULT,
    GL_BANK_LOAN,
    InternetBanking,
    LoanApplication,
    LoanApplicationDetail,
    LoanApplicationDoc,
    LoanAppHistory,
    Loan,
    CreditCardApplication,
    DebitCardApplication,
    SIPApplication,
    SIPTransaction,
    SGBApplication,
    SGBTransaction,
)

api_bp = Blueprint("api", __name__)

# -----------------------
# Helpers / Utilities
# -----------------------
def _json():
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form.to_dict()

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf"}

def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def _ensure_kyc_root() -> str:
    kyc_root = current_app.config.get("KYC_ROOT")
    if not kyc_root:
        kyc_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uploads", "kyc"))
    os.makedirs(kyc_root, exist_ok=True)
    return kyc_root

def _ensure_loans_root() -> str:
    loans_root = current_app.config.get("LOANS_ROOT")
    if not loans_root:
        loans_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uploads", "loans"))
    os.makedirs(loans_root, exist_ok=True)
    return loans_root

def _save_upload(fileobj, prefix: str, is_loan=False) -> str:
    if not fileobj or not fileobj.filename:
        return ""
    if not _allowed_file(fileobj.filename):
        raise ValueError("Only PDF/PNG/JPG/JPEG/WEBP files allowed")
    fname = secure_filename(fileobj.filename)
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    _, ext = os.path.splitext(fname)
    final_name = f"{prefix}_{ts}{ext.lower()}"
    upload_dir = _ensure_loans_root() if is_loan else _ensure_kyc_root()
    fileobj.save(os.path.join(upload_dir, final_name))
    return final_name

def _get_customer():
    return Customer.query.filter_by(user_id=current_user.id).first()

def _first_account_for_user(active_only: bool = False):
    cust = _get_customer()
    if not cust:
        return None
    q = Account.query.filter_by(customer_id=cust.id)
    if active_only:
        q = q.filter(Account.status == AccountStatus.ACTIVE)
    return q.order_by(Account.created_at.asc()).first()

def _require_any_account(active_only: bool = False):
    acc = _first_account_for_user(active_only=active_only)
    if not acc:
        msg = "No active account found. Please open an account first." if active_only \
              else "No account found. Please open an account first."
        return None, (jsonify(ok=False, message=msg), 409)
    return acc, None

def _has_role(role_name: str) -> bool:
    if not current_user.is_authenticated:
        return False
    role = Role.query.filter_by(name=role_name).first()
    if not role:
        return False
    link = UserRole.query.filter_by(user_id=current_user.id, role_id=role.id).first()
    return link is not None

def _require_employee_or_admin():
    if _has_role("EMPLOYEE") or _has_role("ADMIN"):
        return
    abort(403)

@api_bp.get("/ping")
def ping():
    return jsonify(ok=True, message="api alive")

# -----------------------
# SECURE KYC FILE PREVIEW
# -----------------------
@api_bp.get("/employee/file/kyc/<path:filename>")
@login_required
def employee_file_kyc(filename: str):
    _require_employee_or_admin()
    safe_name = secure_filename(os.path.basename(filename))
    if not safe_name:
        return abort(404)
    kyc_root = _ensure_kyc_root()
    abs_path = os.path.abspath(os.path.join(kyc_root, safe_name))
    if not abs_path.startswith(os.path.abspath(kyc_root)):
        return abort(403)
    if not os.path.exists(abs_path):
        return abort(404)
    directory, fname = os.path.split(abs_path)
    return send_from_directory(directory, fname)

# -----------------------
# Presence probe
# -----------------------
@api_bp.get("/me/account_presence")
@login_required
def me_account_presence():
    any_acc = _first_account_for_user(active_only=False) is not None
    active_acc = _first_account_for_user(active_only=True) is not None
    return jsonify(ok=True, has_account=any_acc, has_active_account=active_acc, can_open_new_account=True)

# -----------------------
# Customer profile
# -----------------------
@api_bp.post("/customers/init")
@login_required
def customers_init():
    data = _json()
    full_name = (data.get("full_name") or "").strip()
    phone = (data.get("phone") or "").strip()
    address = (data.get("address") or "").strip()
    if not full_name:
        return jsonify(ok=False, message="full_name required"), 400
    cust = _get_customer()
    if not cust:
        cust = Customer(user_id=current_user.id, full_name=full_name, phone=phone, address=address)
        db.session.add(cust)
    else:
        cust.full_name = full_name or cust.full_name
        cust.phone = phone or cust.phone
        cust.address = address or cust.address
    db.session.commit()
    return jsonify(ok=True, customer_id=cust.id)

# -----------------------
# Account request (customer) with KYC uploads
# -----------------------
@api_bp.post("/accounts/request")
@login_required
def accounts_request():
    form = request.form
    files = request.files
    cust = _get_customer()
    if not cust:
        full_name_f = (form.get("full_name") or "").strip()
        mobile_f = (form.get("mobile") or "").strip()
        perm_addr_f = (form.get("perm_address") or "").strip()
        if not full_name_f:
            return jsonify(ok=False, message="full_name required to create profile"), 400
        cust = Customer(user_id=current_user.id, full_name=full_name_f, phone=mobile_f, address=perm_addr_f)
        db.session.add(cust)
        db.session.flush()
    try:
        branch_id = int(form.get("branch_id") or 0)
    except Exception:
        return jsonify(ok=False, message="Invalid branch_id"), 400
    br = Branch.query.get(branch_id)
    if not br:
        return jsonify(ok=False, message="Invalid branch_id"), 400
    product = (form.get("product") or "SAVINGS").upper()
    if product not in ("SAVINGS", "CURRENT", "SALARY", "JOINT"):
        return jsonify(ok=False, message="Invalid product"), 400
    full_name = (form.get("full_name") or "").strip()
    dob_str = (form.get("dob") or "").strip()
    gender = (form.get("gender") or "").strip()
    mobile = (form.get("mobile") or "").strip()
    email = (form.get("email") or "").strip()
    aadhaar_no = (form.get("aadhaar_no") or "").strip()
    pan_no = (form.get("pan_no") or "").strip()
    perm_address = (form.get("perm_address") or "").strip()
    comm_address = (form.get("comm_address") or "").strip()
    occupation_type = (form.get("occupation_type") or "").strip()
    annual_income_range = (form.get("annual_income_range") or "").strip()
    if not (full_name and dob_str and gender and mobile and email and aadhaar_no and pan_no
            and perm_address and occupation_type and annual_income_range):
        return jsonify(ok=False, message="All required fields must be filled"), 400
    if not aadhaar_no.isdigit() or len(aadhaar_no) != 12:
        return jsonify(ok=False, message="Invalid Aadhaar"), 400
    if len(pan_no) != 10:
        return jsonify(ok=False, message="Invalid PAN"), 400
    try:
        dob = datetime.strptime(dob_str, "%Y-%m-%d").date()
    except Exception:
        return jsonify(ok=False, message="Invalid Date of Birth (use YYYY-MM-DD)"), 400
    # Age validation: must be at least 12 years old
    today = date.today()
    try:
        twelfth_birthday = dob.replace(year=dob.year + 12)
    except ValueError:
        # handle Feb 29 -> Feb 28 on non-leap year
        twelfth_birthday = dob.replace(year=dob.year + 12, day=28)
    if twelfth_birthday > today:
        return jsonify(ok=False, message="Minimum age is 12 years to open an account"), 400
    try:
        aadhaar_path = _save_upload(files.get("aadhaar_file"), prefix=f"{cust.id}_aadhaar")
        pan_path = _save_upload(files.get("pan_file"), prefix=f"{cust.id}_pan")
        photo_path = _save_upload(files.get("photo_file"), prefix=f"{cust.id}_photo") if files.get("photo_file") else ""
    except ValueError as ve:
        return jsonify(ok=False, message=str(ve)), 400
    if not aadhaar_path or not pan_path:
        return jsonify(ok=False, message="Aadhaar and PAN files are required"), 400
    cust.full_name = full_name or cust.full_name
    cust.phone = mobile or cust.phone
    cust.address = perm_address or cust.address
    db.session.add(cust)
    db.session.flush()
    ar = AccountRequest(
        customer_id=cust.id,
        branch_id=br.id,
        product=product,
        dob=dob,
        gender=gender,
        aadhaar_no=aadhaar_no,
        pan_no=pan_no,
        perm_address=perm_address,
        comm_address=comm_address or None,
        occupation_type=occupation_type,
        annual_income_range=annual_income_range,
        aadhaar_file_path=aadhaar_path,
        pan_file_path=pan_path,
        photo_file_path=photo_path or None,
        status=RequestStatus.PENDING,
    )
    db.session.add(ar)
    db.session.commit()
    return jsonify(ok=True, request_id=ar.id, status=ar.status.value, message="Account opening request submitted")

# -----------------------
# My accounts
# -----------------------
@api_bp.get("/accounts/my")
@login_required
def accounts_my():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=True, accounts=[])
    rows = (db.session.query(Account).options(joinedload(Account.branch))
            .filter(Account.customer_id == cust.id).order_by(Account.created_at.desc()).all())
    out = []
    for a in rows:
        br = getattr(a, "branch", None)
        out.append({
            "id": a.id,
            "account_no": a.account_no,
            "product": a.product,
            "status": a.status.value if hasattr(a.status, "value") else a.status,
            "branch_id": a.branch_id,
            "branch_code": br.code if br else None,
            "ifsc": br.ifsc if br else None,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })
    return jsonify(ok=True, accounts=out)

# -----------------------
# Balance
# -----------------------
@api_bp.get("/accounts/<int:account_id>/balance")
@login_required
def account_balance(account_id: int):
    cust = _get_customer()
    acc = Account.query.get(account_id)
    if not acc or not cust or acc.customer_id != cust.id:
        return jsonify(ok=False, message="Account not found"), 404
    cr = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == account_id, LedgerEntry.dr_cr == "CR").scalar()
    dr = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == account_id, LedgerEntry.dr_cr == "DR").scalar()
    return jsonify(ok=True, balance=float(Decimal(cr) - Decimal(dr)))

# -----------------------
# Recent Transactions (paginated)
# -----------------------
@api_bp.get("/accounts/<int:account_id>/transactions")
@api_bp.get("/accounts/<int:account_id>/tx")
@login_required
def account_transactions(account_id: int):
    cust = _get_customer()
    acc = Account.query.get(account_id)
    if not acc or not cust or acc.customer_id != cust.id:
        return jsonify(ok=False, message="Account not found"), 404
    before_raw = request.args.get("before", "").strip()
    limit_raw = request.args.get("limit", "").strip()
    try:
        limit = int(limit_raw) if limit_raw else 20
    except Exception:
        limit = 20
    limit = max(1, min(limit, 100))
    before_dt = None
    if before_raw:
        try:
            before_dt = datetime.fromisoformat(before_raw)
        except Exception:
            try:
                before_dt = datetime.strptime(before_raw, "%Y-%m-%d")
            except Exception:
                return jsonify(ok=False, message="Invalid 'before' cursor"), 400
    q = (db.session.query(LedgerEntry, Transaction)
         .join(Transaction, Transaction.id == LedgerEntry.transaction_id)
         .filter(LedgerEntry.account_id == account_id))
    if before_dt is not None:
        q = q.filter(LedgerEntry.posted_at < before_dt)
    q = q.order_by(desc(LedgerEntry.posted_at), desc(LedgerEntry.id)).limit(limit)
    rows = q.all()

    def _format_counterparty(le: LedgerEntry):
        sibs = (db.session.query(LedgerEntry)
                .filter(
                    LedgerEntry.transaction_id == le.transaction_id,
                    or_(
                        and_(LedgerEntry.account_id.isnot(None), LedgerEntry.account_id != le.account_id),
                        and_(LedgerEntry.account_id.is_(None), LedgerEntry.gl_code.isnot(None))
                    )
                ).order_by(LedgerEntry.id.asc()).all())
        if not sibs:
            return False, "N/A", None, None
        s = sibs[0]
        if s.account_id:
            other_acc = Account.query.get(s.account_id)
            if other_acc:
                return True, other_acc.account_no, other_acc.account_no, None
            return True, "Account", None, None
        gl_label = "CASH" if (s.gl_code or "").upper() == GL_CASH_VAULT else f"GL:{s.gl_code}"
        return False, gl_label, None, s.gl_code

    items = []
    next_before = ""
    for le, tx in rows:
        is_acc, cp_label, cp_acc_no, cp_gl = _format_counterparty(le)
        this_acc_no = acc.account_no
        if (le.dr_cr or "").upper() == "CR":
            from_label = cp_label or "N/A"
            to_label = this_acc_no
            from_acc_no = cp_acc_no if is_acc else None
            to_acc_no = this_acc_no
        else:
            from_label = this_acc_no
            to_label = cp_label or "N/A"
            from_acc_no = this_acc_no
            to_acc_no = cp_acc_no if is_acc else None
        dt = le.posted_at or tx.created_at
        date_str = dt.strftime("%d/%m/%Y") if dt else ""
        time_str = dt.strftime("%I:%M %p") if dt else ""
        items.append({
            "posted_at": dt.isoformat() if dt else None,
            "date": date_str,
            "time": time_str,
            "type": tx.type.value if hasattr(tx.type, "value") else (tx.type or ""),
            "from": from_label,
            "to": to_label,
            "from_account_no": from_acc_no,
            "to_account_no": to_acc_no,
            "dr_cr": le.dr_cr,
            "amount": float(le.amount or 0),
        })
    if rows:
        last_dt = rows[-1][0].posted_at or rows[-1][1].created_at
        if last_dt:
            next_before = last_dt.isoformat()
    return jsonify(ok=True, items=items, next_before=next_before)

# -----------------------
# EMPLOYEE: Approve account request
# -----------------------
@api_bp.post("/ops/requests/<int:req_id>/approve")
@login_required
def ops_approve_request(req_id: int):
    if not (_has_role("EMPLOYEE") or _has_role("ADMIN")):
        return jsonify(ok=False, message="EMPLOYEE role required"), 403
    data = _json()
    init_raw = data.get("initial_deposit", 0)
    init_amt = Decimal(0)
    if init_raw not in (None, "", 0, "0"):
        try:
            init_amt = Decimal(str(init_raw))
        except (InvalidOperation, TypeError):
            return jsonify(ok=False, message="invalid initial_deposit"), 400
        if init_amt < 0:
            return jsonify(ok=False, message="initial_deposit must be >= 0"), 400
    ar = AccountRequest.query.get(req_id)
    if not ar:
        return jsonify(ok=False, message="Request not found"), 404
    if ar.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Request already {ar.status.value}"), 400
    br = Branch.query.get(ar.branch_id)
    if not br:
        return jsonify(ok=False, message="Branch not found"), 400
    seq = AccountNumberSeq.query.filter_by(branch_id=br.id).first()
    if not seq:
        seq = AccountNumberSeq(branch_id=br.id, next_serial=1000000001)
        db.session.add(seq)
        db.session.flush()
    serial = int(seq.next_serial)
    seq.next_serial = serial + 1
    account_no = f"{br.code}{serial}"
    acc = Account(
        customer_id=ar.customer_id,
        branch_id=br.id,
        account_no=account_no,
        product=ar.product,
        status=AccountStatus.ACTIVE,
    )
    db.session.add(acc)
    db.session.flush()
    if init_amt > 0:
        tx = Transaction(type=TxType.DEPOSIT, status=TxStatus.POSTED, created_by=current_user.id)
        db.session.add(tx)
        db.session.flush()
        db.session.add(LedgerEntry(transaction_id=tx.id, gl_code=GL_CASH_VAULT, dr_cr="DR", amount=init_amt))
        db.session.add(LedgerEntry(transaction_id=tx.id, account_id=acc.id, dr_cr="CR", amount=init_amt))
    ar.status = RequestStatus.APPROVED
    db.session.commit()
    return jsonify(ok=True, account_id=acc.id, account_no=acc.account_no,
                   request_status=ar.status.value, initial_deposit=float(init_amt))

# -----------------------
# EMPLOYEE: Decline account request
# -----------------------
@api_bp.post("/ops/requests/<int:req_id>/decline")
@login_required
def ops_decline_request(req_id: int):
    if not (_has_role("EMPLOYEE") or _has_role("ADMIN")):
        return jsonify(ok=False, message="EMPLOYEE role required"), 403
    data = _json()
    remark = (data.get("remark") or "").strip()
    if not remark:
        return jsonify(ok=False, message="Remark is required to decline"), 400
    ar = AccountRequest.query.get(req_id)
    if not ar:
        return jsonify(ok=False, message="Request not found"), 404
    if ar.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Request already {ar.status.value}"), 400
    ar.status = RequestStatus.REJECTED
    if hasattr(ar, "remark"):
        ar.remark = remark
    db.session.commit()
    return jsonify(ok=True, status=ar.status.value, message="Request declined with remark")

# -----------------------
# EMPLOYEE: Get one account request
# -----------------------
@api_bp.get("/ops/requests/<int:req_id>")
@login_required
def ops_get_request(req_id: int):
    if not (_has_role("EMPLOYEE") or _has_role("ADMIN")):
        return jsonify(ok=False, message="EMPLOYEE role required"), 403
    ar = (db.session.query(
            AccountRequest,
            Customer.full_name.label("customer_name"),
            Branch.code.label("branch_code"),
        )
        .join(Customer, Customer.id == AccountRequest.customer_id)
        .join(Branch, Branch.id == AccountRequest.branch_id)
        .filter(AccountRequest.id == req_id)
        .first()
    )
    if not ar:
        return jsonify(ok=False, message="Request not found"), 404
    a, cust_name, br_code = ar
    item = {
        "id": a.id,
        "customer_id": a.customer_id,
        "customer_name": cust_name,
        "branch_id": a.branch_id,
        "branch_code": br_code,
        "product": a.product,
        "status": a.status.value if hasattr(a.status, "value") else a.status,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "photo_file_path": a.photo_file_path,
        "aadhaar_file_path": a.aadhaar_file_path,
        "pan_file_path": a.pan_file_path,
        "kyc_photo_path": getattr(a, "kyc_photo_path", None),
        "aadhaar_path": getattr(a, "aadhaar_path", None),
        "pan_path": getattr(a, "pan_path", None),
        "remark": getattr(a, "remark", None),
    }
    return jsonify(ok=True, item=item)

# -----------------------
# EMPLOYEE: Post cash deposit (by account_id)
# -----------------------
@api_bp.post("/ops/deposits/post")
@login_required
def ops_post_deposit():
    if not (_has_role("EMPLOYEE") or _has_role("ADMIN")):
        return jsonify(ok=False, message="EMPLOYEE role required"), 403
    data = _json()
    account_id = data.get("account_id")
    amount_raw = data.get("amount")
    try:
        amount = Decimal(str(amount_raw))
    except (InvalidOperation, TypeError):
        return jsonify(ok=False, message="Invalid amount"), 400
    if amount <= 0:
        return jsonify(ok=False, message="Amount must be > 0"), 400
    acc = Account.query.get(account_id)
    if not acc:
        return jsonify(ok=False, message="Account not found"), 404
    if acc.status != AccountStatus.ACTIVE:
        return jsonify(ok=False, message="Account not active"), 400
    tx = Transaction(type=TxType.DEPOSIT, status=TxStatus.POSTED, created_by=current_user.id)
    db.session.add(tx)
    db.session.flush()
    db.session.add(LedgerEntry(transaction_id=tx.id, gl_code=GL_CASH_VAULT, dr_cr="DR", amount=amount))
    db.session.add(LedgerEntry(transaction_id=tx.id, account_id=acc.id, dr_cr="CR", amount=amount))
    db.session.commit()
    cr = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == acc.id, LedgerEntry.dr_cr == "CR").scalar()
    dr = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == acc.id, LedgerEntry.dr_cr == "DR").scalar()
    new_bal = Decimal(cr) - Decimal(dr)
    receipt_no = f"CD{tx.id:08d}"
    return jsonify(ok=True, transaction_id=tx.id, account_id=acc.id,
                   account_no=acc.account_no, posted_amount=float(amount),
                   new_balance=float(new_bal), receipt_no=receipt_no)

# -----------------------
# EMPLOYEE: Accept cash deposit (by account_no, teller flow)
# -----------------------
@api_bp.post("/ops/deposits/accept")
@login_required
def ops_accept_cash_deposit():
    if not (_has_role("EMPLOYEE") or _has_role("ADMIN")):
        return jsonify(ok=False, message="EMPLOYEE role required"), 403
    data = _json()
    account_no = (data.get("account_no") or "").strip()
    depositor_name = (data.get("depositor_name") or "").strip()
    teller_note = (data.get("teller_note") or "").strip()
    try:
        amount = Decimal(str(data.get("amount", "0")))
    except (InvalidOperation, TypeError):
        return jsonify(ok=False, message="Invalid amount"), 400
    if amount <= 0:
        return jsonify(ok=False, message="Amount must be > 0"), 400
    if not account_no:
        return jsonify(ok=False, message="account_no required"), 400
    acc = Account.query.filter_by(account_no=account_no).first()
    if not acc:
        return jsonify(ok=False, message="Account not found"), 404
    if acc.status != AccountStatus.ACTIVE:
        return jsonify(ok=False, message="Account not active"), 400
    tx = Transaction(type=TxType.DEPOSIT, status=TxStatus.POSTED, created_by=current_user.id)
    db.session.add(tx)
    db.session.flush()
    db.session.add(LedgerEntry(transaction_id=tx.id, gl_code=GL_CASH_VAULT, dr_cr="DR", amount=amount))
    le_kwargs = dict(transaction_id=tx.id, account_id=acc.id, dr_cr="CR", amount=amount)
    if hasattr(LedgerEntry, "memo"):
        le_kwargs["memo"] = teller_note or (f"Cash deposit by {depositor_name}" if depositor_name else "Cash deposit")
    db.session.add(LedgerEntry(**le_kwargs))
    db.session.commit()
    cr = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == acc.id, LedgerEntry.dr_cr == "CR").scalar()
    dr = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == acc.id, LedgerEntry.dr_cr == "DR").scalar()
    new_bal = Decimal(cr) - Decimal(dr)
    receipt_no = f"CD{tx.id:08d}"
    return jsonify(ok=True, transaction_id=tx.id, account_id=acc.id,
                   account_no=acc.account_no, depositor_name=depositor_name or "",
                   note=teller_note or "", posted_amount=float(amount),
                   new_balance=float(new_bal), receipt_no=receipt_no,
                   message="Cash deposit accepted")

# -----------------------
# EMPLOYEE: List account requests
# -----------------------
@api_bp.get("/ops/requests")
@login_required
def ops_list_requests():
    if not (_has_role("EMPLOYEE") or _has_role("ADMIN")):
        return jsonify(ok=False, message="EMPLOYEE role required"), 403
    status_arg = (request.args.get("status") or "PENDING").upper()
    q = (db.session.query(AccountRequest, Customer.full_name.label("customer_name"),
                          Branch.code.label("branch_code"))
         .join(Customer, Customer.id == AccountRequest.customer_id)
         .join(Branch, Branch.id == AccountRequest.branch_id)
         .order_by(AccountRequest.created_at.desc()))
    if status_arg != "ALL":
        try:
            status_enum = RequestStatus[status_arg]
            q = q.filter(AccountRequest.status == status_enum)
        except KeyError:
            return jsonify(ok=False, message="invalid status"), 400
    items = []
    for ar, cust_name, br_code in q.all():
        items.append({
            "id": ar.id,
            "customer_id": ar.customer_id,
            "customer_name": cust_name,
            "branch_id": ar.branch_id,
            "branch_code": br_code,
            "product": ar.product,
            "status": ar.status.value,
            "created_at": ar.created_at.isoformat() if ar.created_at else None,
        })
    return jsonify(ok=True, items=items)

# =========================
# Internet Banking (IB)
# =========================
def _get_owned_account(acc_no: str = "", acc_id=None):
    acc = None
    if acc_no:
        acc = Account.query.filter_by(account_no=str(acc_no).strip()).first()
    elif acc_id:
        try:
            acc = Account.query.get(int(acc_id))
        except Exception:
            acc = None
    if not acc:
        return None, (jsonify(ok=False, message="Account not found"), 404)
    cust = _get_customer()
    if not cust or acc.customer_id != cust.id:
        return None, (jsonify(ok=False, message="Not allowed for this account"), 403)
    return acc, None

@api_bp.get("/ib/status")
@login_required
def ib_status():
    acc_auto, err_auto = _require_any_account(active_only=False)
    if err_auto: return err_auto
    acc_no = (request.args.get("account_no") or "").strip()
    acc_id = request.args.get("account_id")
    acc, err = _get_owned_account(acc_no, acc_id) if (acc_no or acc_id) else (acc_auto, None)
    if err: return err
    ib = InternetBanking.query.filter_by(account_id=acc.id).first()
    return jsonify(ok=True, active=bool(ib), last2=(ib.pin_hint or "") if ib else "")

@api_bp.post("/ib/activate")
@login_required
def ib_activate():
    _, err0 = _require_any_account(active_only=False)
    if err0: return err0
    data = _json()
    acc_no = (data.get("account_no") or "").strip()
    acc_id = data.get("account_id")
    pin = str(data.get("pin") or "").strip()
    if not pin.isdigit() or len(pin) not in (4, 6):
        return jsonify(ok=False, message="PIN must be 4 or 6 digits"), 400
    acc = None
    if acc_no or acc_id:
        acc, err = _get_owned_account(acc_no, acc_id)
        if err: return err
    else:
        acc, err = _require_any_account(active_only=True)
        if err: return err
    if acc.status != AccountStatus.ACTIVE:
        return jsonify(ok=False, message="Account must be ACTIVE to activate IB"), 400
    ib = InternetBanking.query.filter_by(account_id=acc.id).first()
    if ib: return jsonify(ok=False, message="Internet Banking already activated", active=True), 409
    ib = InternetBanking(account_id=acc.id, pin_hash=bcrypt.hash(pin), pin_hint=pin[-2:])
    db.session.add(ib); db.session.commit()
    return jsonify(ok=True, message="Internet banking activated", account_id=acc.id, account_no=acc.account_no)

@api_bp.post("/ib/change_pin")
@login_required
def ib_change_pin():
    _, err0 = _require_any_account(active_only=False)
    if err0: return err0
    data = _json()
    acc_no = (data.get("account_no") or "").strip()
    acc_id = data.get("account_id")
    old_pin = str(data.get("old_pin") or "").strip()
    new_pin = str(data.get("new_pin") or "").strip()
    confirm = str(data.get("confirm_new_pin") or "").strip()
    if not new_pin.isdigit() or len(new_pin) not in (4,6):
        return jsonify(ok=False, message="New PIN must be 4 or 6 digits"), 400
    if new_pin != confirm:
        return jsonify(ok=False, message="New PIN and confirm do not match"), 400
    acc, err = _get_owned_account(acc_no, acc_id) if (acc_no or acc_id) else _require_any_account(active_only=True)
    if err: return err
    ib = InternetBanking.query.filter_by(account_id=acc.id).first()
    if not ib: return jsonify(ok=False, message="Internet Banking not activated"), 400
    if not old_pin.isdigit() or not bcrypt.verify(old_pin, ib.pin_hash):
        return jsonify(ok=False, message="Old PIN is incorrect"), 403
    ib.pin_hash = bcrypt.hash(new_pin); ib.pin_hint = new_pin[-2:]
    db.session.commit()
    return jsonify(ok=True, message="PIN changed successfully")

@api_bp.post("/ib/deactivate")
@login_required
def ib_deactivate():
    _, err0 = _require_any_account(active_only=False)
    if err0: return err0
    data = _json()
    acc_no = (data.get("account_no") or "").strip()
    acc_id = data.get("account_id")
    pin = str(data.get("pin") or "").strip()
    acc, err = _get_owned_account(acc_no, acc_id) if (acc_no or acc_id) else _require_any_account(active_only=True)
    if err: return err
    ib = InternetBanking.query.filter_by(account_id=acc.id).first()
    if not ib: return jsonify(ok=False, message="Internet Banking is not active"), 400
    if not pin.isdigit() or not bcrypt.verify(pin, ib.pin_hash):
        return jsonify(ok=False, message="PIN is incorrect"), 403
    db.session.delete(ib); db.session.commit()
    return jsonify(ok=True, message="Internet Banking deactivated")

# -----------------------
# Send Money (transfer)
# -----------------------
@api_bp.post("/ib/transfer")
@api_bp.post("/ib/transfer/")
@login_required
def ib_transfer():
    _, err0 = _require_any_account(active_only=False)
    if err0: return err0
    data = _json()
    from_acc = None
    if data.get("from_account_no"):
        from_acc = Account.query.filter_by(account_no=str(data["from_account_no"]).strip()).first()
    elif data.get("from_account_id"):
        try: from_acc = Account.query.get(int(data["from_account_id"]))
        except Exception: from_acc = None
    to_acc = None
    if data.get("to_account_no"):
        to_acc = Account.query.filter_by(account_no=str(data["to_account_no"]).strip()).first()
    elif data.get("to_account_id"):
        try: to_acc = Account.query.get(int(data["to_account_id"]))
        except Exception: to_acc = None
    if not from_acc or not to_acc:
        return jsonify(ok=False, message="Invalid source or destination account"), 400
    if from_acc.id == to_acc.id:
        return jsonify(ok=False, message="Cannot transfer to the same account"), 400
    if from_acc.status != AccountStatus.ACTIVE or to_acc.status != AccountStatus.ACTIVE:
        return jsonify(ok=False, message="Both accounts must be ACTIVE"), 400
    cust = _get_customer()
    if not cust or from_acc.customer_id != cust.id:
        return jsonify(ok=False, message="Not allowed for this source account"), 403
    try: amt = Decimal(str(data.get("amount", "0")))
    except (InvalidOperation, TypeError):
        return jsonify(ok=False, message="Invalid amount"), 400
    if amt <= 0:
        return jsonify(ok=False, message="Amount must be > 0"), 400
    pin = str(data.get("pin") or "").strip()
    if not pin.isdigit() or len(pin) not in (4, 6):
        return jsonify(ok=False, message="PIN must be 4 or 6 digits"), 400
    ib = InternetBanking.query.filter_by(account_id=from_acc.id).first()
    if not ib or not bcrypt.verify(pin, ib.pin_hash):
        return jsonify(ok=False, message="Invalid PIN or IB not activated"), 403
    cr = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == from_acc.id, LedgerEntry.dr_cr == "CR").scalar()
    dr = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == from_acc.id, LedgerEntry.dr_cr == "DR").scalar()
    bal = Decimal(cr) - Decimal(dr)
    if bal < amt:
        return jsonify(ok=False, message="Insufficient funds", balance=float(bal)), 400
    tx = Transaction(type=TxType.TRANSFER, status=TxStatus.POSTED, created_by=current_user.id)
    db.session.add(tx); db.session.flush()
    db.session.add(LedgerEntry(transaction_id=tx.id, account_id=from_acc.id, dr_cr="DR", amount=amt))
    db.session.add(LedgerEntry(transaction_id=tx.id, account_id=to_acc.id, dr_cr="CR", amount=amt))
    db.session.commit()
    cr2 = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == from_acc.id, LedgerEntry.dr_cr == "CR").scalar()
    dr2 = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == from_acc.id, LedgerEntry.dr_cr == "DR").scalar()
    new_bal = Decimal(cr2) - Decimal(dr2)
    return jsonify(ok=True, transaction_id=tx.id,
                   from_account_id=from_acc.id, from_account_no=from_acc.account_no,
                   to_account_id=to_acc.id, to_account_no=to_acc.account_no,
                   amount=float(amt), new_balance=float(new_bal), message="Transfer posted")

# =========================
# Loan APIs
# =========================

# -----------------------
# Customer: Apply for Loan
# -----------------------
@api_bp.post("/loans/apply")
@login_required
def loans_apply():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=False, message="Customer profile not found"), 404

    data = _json()
    files = request.files

    amount_raw = data.get("amount")
    product = (data.get("product") or "").upper()
    purpose = (data.get("purpose") or "").strip()

    # New fields stored in LoanApplication
    pan_no = (data.get("pan_no") or "").strip()
    aadhaar_no = (data.get("aadhaar_no") or "").strip()
    occupation = (data.get("occupation") or "").strip()

    # Validate
    if pan_no and len(pan_no) != 10:
        return jsonify(ok=False, message="Invalid PAN"), 400
    if aadhaar_no and (not aadhaar_no.isdigit() or len(aadhaar_no) != 12):
        return jsonify(ok=False, message="Invalid Aadhaar"), 400

    tenure_months = int(data.get("tenure_months") or 12)
    employment_type = (data.get("employment_type") or "").strip() or None
    monthly_income_raw = data.get("monthly_income")

    try:
        amount = Decimal(str(amount_raw))
    except (InvalidOperation, TypeError):
        return jsonify(ok=False, message="Invalid amount"), 400
    if amount <= 0:
        return jsonify(ok=False, message="Amount must be > 0"), 400
    if not product:
        return jsonify(ok=False, message="Product required"), 400

    monthly_income = None
    if monthly_income_raw not in (None, "", "0", 0):
        try:
            monthly_income = Decimal(str(monthly_income_raw))
        except (InvalidOperation, TypeError):
            return jsonify(ok=False, message="Invalid monthly_income"), 400

    # Create LoanApplication (master record)
    loan_app = LoanApplication(
        customer_id=cust.id,
        amount=amount,
        product=product,
        purpose=purpose,
        pan_num=pan_no,
        aadhaar_no=aadhaar_no,
        occupation=occupation,
        status=RequestStatus.PENDING,
    )
    db.session.add(loan_app)
    db.session.flush()

    # LoanApplicationDetail (single row)
    lad = LoanApplicationDetail.query.filter_by(application_id=loan_app.id).first()
    if not lad:
        lad = LoanApplicationDetail(application_id=loan_app.id)
        db.session.add(lad)
    lad.tenure_months = tenure_months
    lad.purpose = purpose or lad.purpose
    lad.monthly_income = monthly_income
    lad.employment_type = employment_type
    lad.stage = "SUBMITTED"

    # Handle uploaded documents
    for field, fileobj in files.items():
        if not fileobj or not fileobj.filename:
            continue
        original = secure_filename(fileobj.filename)
        try:
            saved = _save_upload(fileobj, prefix=f"loan_{cust.id}_{field}", is_loan=True)
        except ValueError as ve:
            return jsonify(ok=False, message=str(ve)), 400
        if saved:
            doc = LoanApplicationDoc(
                application_id=loan_app.id,
                doc_type=field.upper(),
                file_name=original,
                file_path=saved,
            )
            db.session.add(doc)

    # History
    hist = LoanAppHistory(
        application_id=loan_app.id,
        from_stage=None,
        to_stage="SUBMITTED",
        remarks="Application submitted",
        actor_user_id=current_user.id,
    )
    db.session.add(hist)

    db.session.commit()
    return jsonify(ok=True, loan_app_id=loan_app.id, status=loan_app.status.value,
                   message="Loan application submitted")


# -----------------------
# Customer: List My Loan Applications
# -----------------------
@api_bp.get("/loans/my")
@login_required
def loans_my():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=False, message="Customer profile not found"), 404

    apps = (db.session.query(LoanApplication)
            .filter_by(customer_id=cust.id)
            .order_by(LoanApplication.created_at.desc())
            .all())

    items = []
    for a in apps:
        items.append({
            "id": a.id,
            "amount": str(a.amount),
            "product": a.product,
            "purpose": a.purpose,
            "status": a.status.value if a.status else "PENDING",
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })

    return jsonify(ok=True, items=items)


# -----------------------
# Employee: List Loan Applications
# -----------------------
@api_bp.get("/ops/loans")
@api_bp.get("/ops/loans/applications")
@login_required
def ops_loans_list():
    _require_employee_or_admin()
    status_arg = (request.args.get("status") or "PENDING").upper()
    q = (db.session.query(LoanApplication, Customer.full_name.label("customer_name"))
         .join(Customer, Customer.id == LoanApplication.customer_id)
         .order_by(LoanApplication.created_at.desc()))
    if status_arg != "ALL":
        try:
            status_enum = RequestStatus[status_arg]
            q = q.filter(LoanApplication.status == status_enum)
        except KeyError:
            return jsonify(ok=False, message="invalid status"), 400
    items = []
    for app, cust_name in q.all():
        items.append({
            "id": app.id,
            "customer_id": app.customer_id,
            "customer_name": cust_name,
            "amount": float(app.amount),
            "product": app.product,
            "purpose": app.purpose,
            "status": app.status.value,
            "created_at": app.created_at.isoformat() if app.created_at else None,
        })
    return jsonify(ok=True, items=items)


# -----------------------
# Employee: Get Loan Application Details
# -----------------------
@api_bp.get("/ops/loans/applications/<int:loan_app_id>")
@login_required
def ops_loan_application_detail(loan_app_id: int):
    _require_employee_or_admin()
    app = LoanApplication.query.get(loan_app_id)
    if not app:
        return jsonify(ok=False, message="Loan application not found"), 404

    cust = Customer.query.get(app.customer_id)
    lad = LoanApplicationDetail.query.filter_by(application_id=app.id).first()
    docs = LoanApplicationDoc.query.filter_by(application_id=app.id).all()

    return jsonify({
        "ok": True,
        "id": app.id,
        "customer_name": cust.full_name if cust else "",
        "amount": float(app.amount),
        "product": app.product,
        "purpose": app.purpose,
        "status": app.status.value,
        "created_at": app.created_at.isoformat() if app.created_at else None,
        "pan_num": app.pan_num,
        "aadhaar_no": app.aadhaar_no,
        "occupation": app.occupation,
        "tenure_months": lad.tenure_months if lad else None,
        "monthly_income": float(lad.monthly_income) if lad and lad.monthly_income else None,
        "employment_type": lad.employment_type if lad else None,
        "rate_pa": float(lad.rate_pa) if lad and lad.rate_pa else None,
        "documents": [
            {"doc_type": d.doc_type, "file_name": d.file_name, "file_path": d.file_path}
            for d in docs
        ]
    })


# -----------------------
# Employee: Approve Loan Application
# -----------------------
@api_bp.post("/ops/loans/<int:loan_app_id>/approve")
@api_bp.post("/ops/loans/applications/<int:loan_app_id>/approve")
@login_required
def ops_loan_approve(loan_app_id: int):
    _require_employee_or_admin()
    data = _json()
    remark = (data.get("remark") or "").strip()
    rate_pa = Decimal(str(data.get("rate_pa") or "10.0"))
    term_months = int(data.get("term_months") or 12)

    app = LoanApplication.query.get(loan_app_id)
    if not app: return jsonify(ok=False, message="Loan application not found"), 404
    if app.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Already {app.status.value}"), 400

    app.status = RequestStatus.APPROVED

    lad = LoanApplicationDetail.query.filter_by(application_id=app.id).first()
    if not lad:
        lad = LoanApplicationDetail(application_id=app.id)
        db.session.add(lad)
    lad.rate_pa = rate_pa
    lad.tenure_months = term_months
    lad.stage = "APPROVED"

    db.session.add(LoanAppHistory(
        application_id=app.id,
        from_stage="SUBMITTED",
        to_stage="APPROVED",
        remarks=remark or "Approved",
        actor_user_id=current_user.id
    ))

    loan = Loan(customer_id=app.customer_id, principal=app.amount,
                rate_pa=rate_pa, term_months=term_months)
    db.session.add(loan)
    db.session.commit()
    return jsonify(ok=True, loan_app_id=app.id, loan_id=loan.id,
                   message="Loan approved", status=app.status.value)


# -----------------------
# Employee: Decline Loan Application
# -----------------------
@api_bp.post("/ops/loans/<int:loan_app_id>/decline")
@api_bp.post("/ops/loans/applications/<int:loan_app_id>/decline")
@login_required
def ops_loan_decline(loan_app_id: int):
    _require_employee_or_admin()
    data = _json()
    remark = (data.get("remark") or "").strip()
    if not remark:
        return jsonify(ok=False, message="Remark is required"), 400
    app = LoanApplication.query.get(loan_app_id)
    if not app: return jsonify(ok=False, message="Loan application not found"), 404
    if app.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Already {app.status.value}"), 400
    app.status = RequestStatus.REJECTED

    lad = LoanApplicationDetail.query.filter_by(application_id=app.id).first()
    if lad: lad.stage = "REJECTED"

    db.session.add(LoanAppHistory(
        application_id=app.id,
        from_stage="SUBMITTED",
        to_stage="REJECTED",
        remarks=remark,
        actor_user_id=current_user.id
    ))
    db.session.commit()
    return jsonify(ok=True, loan_app_id=app.id, status=app.status.value,
                   message="Loan declined")


# -----------------------
# Employee: Disburse Loan
# -----------------------
@api_bp.post("/ops/loans/<int:loan_app_id>/disburse")
@login_required
def ops_loan_disburse(loan_app_id: int):
    _require_employee_or_admin()
    data = _json()
    account_no = (data.get("account_no") or data.get("to_account_no") or "").strip()
    disburse_amount_raw = data.get("disburse_amount")

    # Safely parse rate
    try:
        rate_pa = Decimal(str(data.get("rate_pa") or "10.0"))
    except (InvalidOperation, TypeError, ValueError):
        return jsonify(ok=False, message="Invalid rate of interest"), 400

    # Safely parse term
    try:
        term_months = int(data.get("term_months") or 12)
    except (TypeError, ValueError):
        return jsonify(ok=False, message="Invalid term (months)"), 400

    # Validate application
    app = LoanApplication.query.get(loan_app_id)
    if not app:
        return jsonify(ok=False, message="Loan application not found"), 404
    if app.status != RequestStatus.APPROVED:
        return jsonify(ok=False, message="Loan not approved"), 400

    # Validate account
    acc = Account.query.filter_by(account_no=account_no).first()
    if not acc:
        return jsonify(ok=False, message="Account not found"), 404
    if acc.status != AccountStatus.ACTIVE:
        return jsonify(ok=False, message="Account not active"), 400

    # Amount
    try:
        disburse_amount = Decimal(str(disburse_amount_raw or app.amount))
    except (InvalidOperation, TypeError):
        return jsonify(ok=False, message="Invalid disburse amount"), 400
    if disburse_amount <= 0:
        return jsonify(ok=False, message="Disburse amount must be > 0"), 400

    # Transaction
    tx = Transaction(type=TxType.LOAN_DISBURSAL, status=TxStatus.POSTED, created_by=current_user.id)
    db.session.add(tx); db.session.flush()

    db.session.add(LedgerEntry(transaction_id=tx.id, gl_code=GL_BANK_LOAN, dr_cr="DR", amount=disburse_amount))
    db.session.add(LedgerEntry(transaction_id=tx.id, account_id=acc.id, dr_cr="CR", amount=disburse_amount))
    # 👆 removed "memo" argument

    # Update loan detail
    lad = LoanApplicationDetail.query.filter_by(application_id=app.id).first()
    if lad:
        lad.rate_pa = rate_pa
        lad.tenure_months = term_months
        lad.stage = "DISBURSED"

    db.session.add(LoanAppHistory(
        application_id=app.id,
        from_stage="APPROVED",
        to_stage="DISBURSED",
        remarks=f"Loan disbursed to {account_no}",
        actor_user_id=current_user.id
    ))

    db.session.commit()
    return jsonify(ok=True, loan_app_id=app.id, account_id=acc.id,
                   account_no=acc.account_no, disbursed_amount=float(disburse_amount),
                   message="Loan amount disbursed successfully")



# -----------------------
# Customer: Loan Application Status
# -----------------------
@api_bp.get("/loans/<int:loan_app_id>/status")
@login_required
def loan_status(loan_app_id: int):
    cust = _get_customer()
    app = LoanApplication.query.get(loan_app_id)
    if not app or not cust or app.customer_id != cust.id:
        return jsonify(ok=False, message="Loan application not found"), 404
    return jsonify(ok=True, loan_app_id=app.id, status=app.status.value)


# -----------------------
# Employee: View Loan Documents
# -----------------------
@api_bp.get("/ops/loans/<int:loan_app_id>/docs")
@api_bp.get("/ops/loans/applications/<int:loan_app_id>/docs")
@login_required
def ops_loan_docs(loan_app_id: int):
    _require_employee_or_admin()
    docs = LoanApplicationDoc.query.filter_by(application_id=loan_app_id).all()
    out = []
    for d in docs:
        out.append({"id": d.id, "doc_type": d.doc_type, "file_path": d.file_path, "file_name": d.file_name})
    return jsonify(ok=True, docs=out)


@api_bp.get("/employee/file/loan/<path:filename>")
@login_required
def employee_file_loan(filename: str):
    _require_employee_or_admin()
    safe_name = secure_filename(os.path.basename(filename))
    if not safe_name:
        return abort(404)
    loan_root = _ensure_loans_root()
    abs_path = os.path.abspath(os.path.join(loan_root, safe_name))
    if not abs_path.startswith(os.path.abspath(loan_root)):
        return abort(403)
    if not os.path.exists(abs_path):
        return abort(404)
    directory, fname = os.path.split(abs_path)
    return send_from_directory(directory, fname)


# =========================
# Credit Card APIs
# =========================

# -----------------------
# Customer: Apply for Credit Card
# -----------------------
# -----------------------
# Customer: Apply for Credit Card
# -----------------------
@api_bp.post("/credit_cards/apply")
@api_bp.post("/ops/credit_cards")   # for frontend calls
@login_required
def credit_cards_apply():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=False, message="Customer profile not found"), 404

    form = request.form
    files = request.files

    try:
        monthly_income = Decimal(str(form.get("monthly_income") or 0))
        preferred_limit = Decimal(str(form.get("preferred_limit") or 0))
    except Exception:
        return jsonify(ok=False, message="Invalid income/limit"), 400

    try:
        pan_path = _save_upload(files.get("pan_file"), prefix=f"cc_{cust.id}_pan")
        aadhaar_path = _save_upload(files.get("aadhaar_file"), prefix=f"cc_{cust.id}_aadhaar")
    except ValueError as ve:
        return jsonify(ok=False, message=str(ve)), 400

    app = CreditCardApplication(
        customer_id=cust.id,
        account_no=(form.get("account_no") or "").strip(),
        card_type=(form.get("card_type") or "").strip(),
        delivery_address=(form.get("delivery_address") or "").strip(),
        monthly_income=monthly_income,
        employment_type=(form.get("employment_type") or "").strip(),
        preferred_limit=preferred_limit,
        requested_limit=preferred_limit,   # ✅ required field
        pincode=(form.get("pincode") or "").strip(),
        pan_file_path=pan_path,
        aadhaar_file_path=aadhaar_path,
        status=RequestStatus.PENDING,
    )

    db.session.add(app)
    db.session.commit()

    return jsonify(
        ok=True,
        credit_card_app_id=app.id,
        status=app.status.value,
        message="Credit Card application submitted"
    ), 201


# -----------------------
# Customer: List My Credit Card Applications
# -----------------------
@api_bp.get("/credit_cards/my")
@login_required
def credit_cards_my():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=False, message="Customer profile not found"), 404

    apps = (db.session.query(CreditCardApplication)
            .filter_by(customer_id=cust.id)
            .order_by(CreditCardApplication.created_at.desc())
            .all())

    items = []
    for a in apps:
        items.append({
            "id": a.id,
            "account_no": a.account_no,
            "card_type": a.card_type,
            "preferred_limit": str(a.preferred_limit),
            "status": a.status.value if a.status else "PENDING",
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })

    return jsonify(ok=True, items=items)


# -----------------------
# Employee: List Credit Card Applications
# -----------------------
@api_bp.get("/ops/credit_cards")
@login_required
def ops_credit_cards_list():
    _require_employee_or_admin()
    status_arg = (request.args.get("status") or "PENDING").upper()

    q = (db.session.query(CreditCardApplication, Customer.full_name.label("customer_name"))
         .join(Customer, Customer.id == CreditCardApplication.customer_id)
         .order_by(CreditCardApplication.created_at.desc()))

    if status_arg != "ALL":
        try:
            status_enum = RequestStatus[status_arg]
            q = q.filter(CreditCardApplication.status == status_enum)
        except KeyError:
            return jsonify(ok=False, message="invalid status"), 400

    items = []
    for app, cust_name in q.all():
        items.append({
            "id": app.id,
            "customer_id": app.customer_id,
            "customer_name": cust_name,
            "account_no": app.account_no,
            "card_type": app.card_type,
            "preferred_limit": str(app.preferred_limit),
            "status": app.status.value,
            "created_at": app.created_at.isoformat() if app.created_at else None,
            # include KYC/document file paths so employee UI can preview
            "pan_file_path": getattr(app, "pan_file_path", None),
            "aadhaar_file_path": getattr(app, "aadhaar_file_path", None),
        })

    return jsonify(ok=True, items=items)


# -----------------------
# Employee: Approve Credit Card Application
# -----------------------
@api_bp.post("/ops/credit_cards/<int:cc_app_id>/approve")
@login_required
def ops_credit_card_approve(cc_app_id: int):
    _require_employee_or_admin()
    app = CreditCardApplication.query.get(cc_app_id)
    if not app:
        return jsonify(ok=False, message="Application not found"), 404
    if app.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Already {app.status.value}"), 400

    app.status = RequestStatus.APPROVED
    db.session.commit()
    return jsonify(ok=True, credit_card_app_id=app.id, status=app.status.value, message="Credit Card approved")


# -----------------------
# Employee: Decline Credit Card Application
# -----------------------
@api_bp.post("/ops/credit_cards/<int:cc_app_id>/decline")
@login_required
def ops_credit_card_decline(cc_app_id: int):
    _require_employee_or_admin()
    data = _json()
    remark = (data.get("remark") or "").strip()
    if not remark:
        return jsonify(ok=False, message="Remark required"), 400
    app = CreditCardApplication.query.get(cc_app_id)
    if not app:
        return jsonify(ok=False, message="Application not found"), 404
    if app.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Already {app.status.value}"), 400

    app.status = RequestStatus.REJECTED
    db.session.commit()
    return jsonify(ok=True, credit_card_app_id=app.id, status=app.status.value, message="Credit Card declined")


# =========================
# Debit Card APIs
# =========================

# -----------------------
# Customer: Apply for Debit Card
# -----------------------
@api_bp.post("/debit_cards/apply")
@api_bp.post("/ops/debit_cards")   # for frontend calls
@login_required
def debit_cards_apply():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=False, message="Customer profile not found"), 404

    form = request.form
    files = request.files

    try:
        monthly_income = Decimal(str(form.get("monthly_income") or 0))
        preferred_limit = Decimal(str(form.get("preferred_limit") or 0))
    except Exception:
        return jsonify(ok=False, message="Invalid income/limit"), 400

    try:
        pan_path = _save_upload(files.get("pan_file"), prefix=f"dc_{cust.id}_pan")
        aadhaar_path = _save_upload(files.get("aadhaar_file"), prefix=f"dc_{cust.id}_aadhaar")
    except ValueError as ve:
        return jsonify(ok=False, message=str(ve)), 400

    app = DebitCardApplication(
    customer_id=cust.id,
    account_no=(form.get("account_no") or "").strip(),
    card_type=(form.get("card_type") or "").strip(),
    card_network=(form.get("card_network") or "VISA").strip(),   # <-- ADD THIS LINE
    delivery_address=(form.get("delivery_address") or "").strip(),
    monthly_income=monthly_income,
    employment_type=(form.get("employment_type") or "").strip(),
    preferred_limit=preferred_limit,
    requested_limit=preferred_limit,
    pincode=(form.get("pincode") or "").strip(),
    pan_file_path=pan_path,
    aadhaar_file_path=aadhaar_path,
    status=RequestStatus.PENDING,
)


    db.session.add(app)
    db.session.commit()

    return jsonify(
        ok=True,
        debit_card_app_id=app.id,
        status=app.status.value,
        message="Debit Card application submitted"
    ), 201


# -----------------------
# Customer: List My Debit Card Applications
# -----------------------
@api_bp.get("/debit_cards/my")
@login_required
def debit_cards_my():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=False, message="Customer profile not found"), 404

    apps = (db.session.query(DebitCardApplication)
            .filter_by(customer_id=cust.id)
            .order_by(DebitCardApplication.created_at.desc())
            .all())

    items = []
    for a in apps:
        items.append({
            "id": a.id,
            "account_no": a.account_no,
            "card_type": a.card_type,
            "preferred_limit": str(a.preferred_limit),
            "status": a.status.value if a.status else "PENDING",
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })

    return jsonify(ok=True, items=items)


# -----------------------
# Employee: List Debit Card Applications
# -----------------------
@api_bp.get("/ops/debit_cards")
@login_required
def ops_debit_cards_list():
    _require_employee_or_admin()
    status_arg = (request.args.get("status") or "PENDING").upper()

    q = (db.session.query(DebitCardApplication, Customer.full_name.label("customer_name"))
         .join(Customer, Customer.id == DebitCardApplication.customer_id)
         .order_by(DebitCardApplication.created_at.desc()))

    if status_arg != "ALL":
        try:
            status_enum = RequestStatus[status_arg]
            q = q.filter(DebitCardApplication.status == status_enum)
        except KeyError:
            return jsonify(ok=False, message="invalid status"), 400

    items = []
    for app, cust_name in q.all():
        items.append({
            "id": app.id,
            "customer_id": app.customer_id,
            "customer_name": cust_name,
            "account_no": app.account_no,
            "card_type": app.card_type,
            "preferred_limit": str(app.preferred_limit),
            "status": app.status.value,
            "created_at": app.created_at.isoformat() if app.created_at else None,
            "pan_file_path": getattr(app, "pan_file_path", None),
            "aadhaar_file_path": getattr(app, "aadhaar_file_path", None),
        })

    return jsonify(ok=True, items=items)


# -----------------------
# Employee: Approve Debit Card Application
# -----------------------
@api_bp.post("/ops/debit_cards/<int:dc_app_id>/approve")
@login_required
def ops_debit_card_approve(dc_app_id: int):
    _require_employee_or_admin()
    app = DebitCardApplication.query.get(dc_app_id)
    if not app:
        return jsonify(ok=False, message="Application not found"), 404
    if app.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Already {app.status.value}"), 400

    app.status = RequestStatus.APPROVED
    db.session.commit()
    return jsonify(ok=True, debit_card_app_id=app.id, status=app.status.value, message="Debit Card approved")


# -----------------------
# Employee: Decline Debit Card Application
# -----------------------
@api_bp.post("/ops/debit_cards/<int:dc_app_id>/decline")
@login_required
def ops_debit_card_decline(dc_app_id: int):
    _require_employee_or_admin()
    data = _json()
    remark = (data.get("remark") or "").strip()
    if not remark:
        return jsonify(ok=False, message="Remark required"), 400
    app = DebitCardApplication.query.get(dc_app_id)
    if not app:
        return jsonify(ok=False, message="Application not found"), 404
    if app.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Already {app.status.value}"), 400

    app.status = RequestStatus.REJECTED
    db.session.commit()
    return jsonify(ok=True, debit_card_app_id=app.id, status=app.status.value, message="Debit Card declined")


# =========================
# SIP (Systematic Investment Plan) APIs
# =========================

# -----------------------
# Customer: Apply for SIP
# -----------------------
@api_bp.post("/sip/apply")
@login_required
def sip_apply():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=False, message="Customer profile not found"), 404

    # Get first active account
    acc, err = _require_any_account(active_only=True)
    if err: return err

    data = _json()
    files = request.files

    fund_name = (data.get("fund_name") or "").strip()
    fund_type = (data.get("fund_type") or "").strip().upper()
    monthly_amount_raw = data.get("monthly_amount")
    tenure_months = int(data.get("tenure_months") or 12)
    start_date_str = (data.get("start_date") or "").strip()

    # Validate inputs
    if not fund_name or not fund_type or not monthly_amount_raw:
        return jsonify(ok=False, message="Fund name, type, and monthly amount are required"), 400

    if fund_type not in ("EQUITY", "DEBT", "HYBRID"):
        return jsonify(ok=False, message="Invalid fund type"), 400

    try:
        monthly_amount = Decimal(str(monthly_amount_raw))
        if monthly_amount <= 0:
            return jsonify(ok=False, message="Monthly amount must be > 0"), 400
    except (InvalidOperation, TypeError):
        return jsonify(ok=False, message="Invalid monthly amount"), 400

    if tenure_months < 6 or tenure_months > 360:  # 6 months to 30 years
        return jsonify(ok=False, message="Tenure must be between 6 and 360 months"), 400

    try:
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
    except Exception:
        return jsonify(ok=False, message="Invalid start date (use YYYY-MM-DD)"), 400

    # Set expected returns based on fund type
    expected_returns = {
        "EQUITY": Decimal("12.0"),
        "DEBT": Decimal("8.0"), 
        "HYBRID": Decimal("10.0")
    }

    # Handle KYC document upload
    kyc_path = ""
    if files.get("kyc_file"):
        try:
            kyc_path = _save_upload(files.get("kyc_file"), prefix=f"sip_{cust.id}_kyc")
        except ValueError as ve:
            return jsonify(ok=False, message=str(ve)), 400

    # Create SIP Application
    sip_app = SIPApplication(
        customer_id=cust.id,
        account_id=acc.id,
        fund_name=fund_name,
        fund_type=fund_type,
        monthly_amount=monthly_amount,
        tenure_months=tenure_months,
        start_date=start_date,
        expected_return_pa=expected_returns[fund_type],
        status=RequestStatus.PENDING,
        kyc_file_path=kyc_path or None,
    )

    db.session.add(sip_app)
    db.session.commit()

    return jsonify(
        ok=True,
        sip_app_id=sip_app.id,
        status=sip_app.status.value,
        message="SIP application submitted"
    ), 201


# -----------------------
# Customer: List My SIP Applications
# -----------------------
@api_bp.get("/sip/my")
@login_required
def sip_my():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=False, message="Customer profile not found"), 404

    apps = (db.session.query(SIPApplication)
            .filter_by(customer_id=cust.id)
            .order_by(SIPApplication.created_at.desc())
            .all())

    items = []
    for a in apps:
        items.append({
            "id": a.id,
            "fund_name": a.fund_name,
            "fund_type": a.fund_type,
            "monthly_amount": str(a.monthly_amount),
            "tenure_months": a.tenure_months,
            "expected_return_pa": str(a.expected_return_pa),
            "status": a.status.value if a.status else "PENDING",
            "is_active": a.is_active,
            "current_value": str(a.current_value),
            "total_invested": str(a.total_invested),
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })

    return jsonify(ok=True, items=items)


# -----------------------
# Employee: List SIP Applications
# -----------------------
@api_bp.get("/ops/sip")
@login_required
def ops_sip_list():
    _require_employee_or_admin()
    status_arg = (request.args.get("status") or "PENDING").upper()

    q = (db.session.query(SIPApplication, Customer.full_name.label("customer_name"))
         .join(Customer, Customer.id == SIPApplication.customer_id)
         .order_by(SIPApplication.created_at.desc()))

    if status_arg != "ALL":
        try:
            status_enum = RequestStatus[status_arg]
            q = q.filter(SIPApplication.status == status_enum)
        except KeyError:
            return jsonify(ok=False, message="invalid status"), 400

    items = []
    for app, cust_name in q.all():
        items.append({
            "id": app.id,
            "customer_id": app.customer_id,
            "customer_name": cust_name,
            "fund_name": app.fund_name,
            "fund_type": app.fund_type,
            "monthly_amount": str(app.monthly_amount),
            "tenure_months": app.tenure_months,
            "expected_return_pa": str(app.expected_return_pa),
            "status": app.status.value,
            "is_active": app.is_active,
            "created_at": app.created_at.isoformat() if app.created_at else None,
            "kyc_file_path": app.kyc_file_path,
        })

    return jsonify(ok=True, items=items)


# -----------------------
# Employee: Approve SIP Application
# -----------------------
@api_bp.post("/ops/sip/<int:sip_app_id>/approve")
@login_required
def ops_sip_approve(sip_app_id: int):
    _require_employee_or_admin()
    app = SIPApplication.query.get(sip_app_id)
    if not app:
        return jsonify(ok=False, message="SIP application not found"), 404
    if app.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Already {app.status.value}"), 400

    app.status = RequestStatus.APPROVED
    app.is_active = True
    db.session.commit()

    return jsonify(ok=True, sip_app_id=app.id, status=app.status.value, message="SIP approved")


# -----------------------
# Employee: Decline SIP Application
# -----------------------
@api_bp.post("/ops/sip/<int:sip_app_id>/decline")
@login_required
def ops_sip_decline(sip_app_id: int):
    _require_employee_or_admin()
    data = _json()
    remark = (data.get("remark") or "").strip()
    if not remark:
        return jsonify(ok=False, message="Remark required"), 400

    app = SIPApplication.query.get(sip_app_id)
    if not app:
        return jsonify(ok=False, message="SIP application not found"), 404
    if app.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Already {app.status.value}"), 400

    app.status = RequestStatus.REJECTED
    db.session.commit()

    return jsonify(ok=True, sip_app_id=app.id, status=app.status.value, message="SIP declined")


# -----------------------
# Employee: Get Single SIP Application
# -----------------------
@api_bp.get("/ops/sip/<int:sip_app_id>")
@login_required
def ops_sip_get(sip_app_id: int):
    _require_employee_or_admin()
    app = SIPApplication.query.get(sip_app_id)
    if not app:
        return jsonify(ok=False, message="SIP application not found"), 404

    customer = Customer.query.get(app.customer_id)
    account = Account.query.get(app.account_id)

    return jsonify(ok=True, sip_app={
        "id": app.id,
        "customer_name": customer.full_name if customer else "Unknown",
        "account_no": account.account_no if account else "Unknown",
        "fund_name": app.fund_name,
        "fund_type": app.fund_type,
        "monthly_amount": float(app.monthly_amount),
        "tenure_months": app.tenure_months,
        "start_date": app.start_date.isoformat() if app.start_date else None,
        "expected_return_pa": float(app.expected_return_pa),
        "status": app.status.value,
        "is_active": app.is_active,
        "current_value": float(app.current_value or 0),
        "total_invested": float(app.total_invested or 0),
        "kyc_file_path": app.kyc_file_path,
        "created_at": app.created_at.isoformat() if app.created_at else None,
        "updated_at": app.updated_at.isoformat() if app.updated_at else None
    })


# -----------------------
# Employee: View SIP Documents
# -----------------------
@api_bp.get("/ops/sip/<int:sip_app_id>/docs")
@login_required
def ops_sip_docs(sip_app_id: int):
    _require_employee_or_admin()
    app = SIPApplication.query.get(sip_app_id)
    if not app:
        return jsonify(ok=False, message="SIP application not found"), 404

    docs = []
    if app.kyc_file_path:
        docs.append({
            "type": "KYC",
            "file_path": app.kyc_file_path,
            "file_name": app.kyc_file_path.split("/")[-1] if "/" in app.kyc_file_path else app.kyc_file_path
        })

    return jsonify(ok=True, docs=docs)


# -----------------------
# Employee: Process SIP Investment (Monthly)
# -----------------------
@api_bp.post("/ops/sip/<int:sip_app_id>/process")
@login_required
def ops_sip_process(sip_app_id: int):
    _require_employee_or_admin()
    data = _json()
    
    app = SIPApplication.query.get(sip_app_id)
    if not app:
        return jsonify(ok=False, message="SIP application not found"), 404
    if not app.is_active:
        return jsonify(ok=False, message="SIP is not active"), 400

    acc = Account.query.get(app.account_id)
    if not acc or acc.status != AccountStatus.ACTIVE:
        return jsonify(ok=False, message="Account not active"), 400

    # Check account balance
    cr = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == acc.id, LedgerEntry.dr_cr == "CR").scalar()
    dr = db.session.query(func.coalesce(func.sum(LedgerEntry.amount), 0))\
        .filter(LedgerEntry.account_id == acc.id, LedgerEntry.dr_cr == "DR").scalar()
    balance = Decimal(cr) - Decimal(dr)

    if balance < app.monthly_amount:
        return jsonify(ok=False, message="Insufficient balance for SIP"), 400

    # Simulate NAV and units (for demo)
    import random
    nav = Decimal(random.uniform(50.0, 200.0))  # Random NAV between 50-200
    units = app.monthly_amount / nav

    # Create SIP transaction record
    sip_tx = SIPTransaction(
        sip_id=app.id,
        account_id=acc.id,
        amount=app.monthly_amount,
        transaction_date=date.today(),
        status=TxStatus.POSTED,
        nav_at_purchase=nav,
        units_purchased=units,
    )
    db.session.add(sip_tx)

    # Create bank transaction
    tx = Transaction(type=TxType.TRANSFER, status=TxStatus.POSTED, created_by=current_user.id)
    db.session.add(tx)
    db.session.flush()

    # Debit customer account
    db.session.add(LedgerEntry(transaction_id=tx.id, account_id=acc.id, dr_cr="DR", amount=app.monthly_amount))
    # Credit investment GL (for demo)
    db.session.add(LedgerEntry(transaction_id=tx.id, gl_code="INVESTMENT_GL", dr_cr="CR", amount=app.monthly_amount))

    # Update SIP totals
    app.total_invested = (app.total_invested or 0) + app.monthly_amount
    # Simulate growth
    growth_factor = Decimal("1.02")  # 2% monthly growth
    app.current_value = (app.current_value or 0) * growth_factor + app.monthly_amount

    db.session.commit()

    return jsonify(
        ok=True,
        sip_app_id=app.id,
        transaction_id=sip_tx.id,
        amount=float(app.monthly_amount),
        nav=float(nav),
        units=float(units),
        message="SIP investment processed"
    )


# ==============================
# SOVEREIGN GOLD BONDS (SGB) API
# ==============================

# -----------------------
# Customer: Apply for SGB
# -----------------------
@api_bp.post("/sgb/apply")
@login_required
def sgb_apply():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=False, message="Customer profile not found"), 404

    acc = _first_account_for_user(active_only=True)
    if not acc:
        return jsonify(ok=False, message="No active account found"), 404

    # Handle both JSON and FormData
    if request.is_json:
        data = _json()
    else:
        data = request.form.to_dict()
    
    series = (data.get("series") or "").strip()
    investment_amount = data.get("investment_amount")
    pan_number = (data.get("pan_number") or "").strip().upper()
    
    # Convert investment_amount to float if it's a string
    if investment_amount:
        try:
            investment_amount = float(investment_amount)
        except (ValueError, TypeError):
            investment_amount = None

    if not series:
        return jsonify(ok=False, message="Series is required"), 400
    if not investment_amount or investment_amount <= 0:
        return jsonify(ok=False, message="Valid investment amount required"), 400
    if not pan_number or len(pan_number) != 10:
        return jsonify(ok=False, message="Valid PAN number required"), 400

    # Calculate units based on current gold price (simulated)
    current_gold_price = 6500  # ₹ per gram (simulated)
    units = Decimal(str(investment_amount)) / Decimal(str(current_gold_price))

    # Save KYC file if provided
    kyc_path = None
    files = request.files
    if files.get("kyc_file"):
        try:
            kyc_path = _save_upload(files.get("kyc_file"), prefix=f"sgb_{cust.id}_kyc")
        except ValueError as ve:
            return jsonify(ok=False, message=str(ve)), 400

    # Create SGB Application
    sgb_app = SGBApplication(
        customer_id=cust.id,
        account_id=acc.id,
        series=series,
        investment_amount=investment_amount,
        units=units,
        pan_number=pan_number,
        kyc_file_path=kyc_path,
        current_value=investment_amount  # Initially same as investment
    )

    try:
        db.session.add(sgb_app)
        db.session.commit()
        return jsonify(ok=True, message="SGB application submitted successfully", sgb_id=sgb_app.id)
    except Exception as e:
        db.session.rollback()
        return jsonify(ok=False, message="Failed to submit SGB application"), 500


# -----------------------
# Customer: Get my SGB investments
# -----------------------
@api_bp.get("/sgb/my")
@login_required
def sgb_my():
    cust = _get_customer()
    if not cust:
        return jsonify(ok=False, message="Customer profile not found"), 404

    apps = (db.session.query(SGBApplication)
            .filter_by(customer_id=cust.id)
            .order_by(SGBApplication.created_at.desc())
            .all())

    items = []
    for a in apps:
        items.append({
            "id": a.id,
            "series": a.series,
            "investment_amount": float(a.investment_amount),
            "units": float(a.units),
            "current_value": float(a.current_value or 0),
            "interest_earned": float(a.interest_earned or 0),
            "status": a.status.value,
            "created_at": a.created_at.isoformat() if a.created_at else None
        })

    return jsonify(ok=True, items=items)


# -----------------------
# Employee: List SGB applications
# -----------------------
@api_bp.get("/ops/sgb")
@login_required
def ops_sgb_list():
    _require_employee_or_admin()
    status_arg = (request.args.get("status") or "PENDING").upper()

    q = (db.session.query(SGBApplication, Customer.full_name.label("customer_name"))
         .join(Customer, Customer.id == SGBApplication.customer_id)
         .order_by(SGBApplication.created_at.desc()))

    if status_arg != "ALL":
        try:
            status_enum = RequestStatus[status_arg]
            q = q.filter(SGBApplication.status == status_enum)
        except KeyError:
            return jsonify(ok=False, message="invalid status"), 400

    items = []
    for app, cust_name in q.all():
        items.append({
            "id": app.id,
            "customer_name": cust_name,
            "series": app.series,
            "investment_amount": float(app.investment_amount),
            "units": float(app.units),
            "status": app.status.value,
            "created_at": app.created_at.isoformat() if app.created_at else None
        })

    return jsonify(ok=True, items=items)


# -----------------------
# Employee: Approve SGB application
# -----------------------
@api_bp.post("/ops/sgb/<int:sgb_app_id>/approve")
@login_required
def ops_sgb_approve(sgb_app_id: int):
    _require_employee_or_admin()
    app = SGBApplication.query.get(sgb_app_id)
    if not app:
        return jsonify(ok=False, message="SGB application not found"), 404
    if app.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Already {app.status.value}"), 400

    app.status = RequestStatus.APPROVED
    try:
        db.session.commit()
        return jsonify(ok=True, message="SGB application approved")
    except Exception as e:
        db.session.rollback()
        return jsonify(ok=False, message="Failed to approve SGB application"), 500


# -----------------------
# Employee: Decline SGB application
# -----------------------
@api_bp.post("/ops/sgb/<int:sgb_app_id>/decline")
@login_required
def ops_sgb_decline(sgb_app_id: int):
    _require_employee_or_admin()
    data = _json()
    remark = (data.get("remark") or "").strip()
    if not remark:
        return jsonify(ok=False, message="Remark required"), 400

    app = SGBApplication.query.get(sgb_app_id)
    if not app:
        return jsonify(ok=False, message="SGB application not found"), 404
    if app.status != RequestStatus.PENDING:
        return jsonify(ok=False, message=f"Already {app.status.value}"), 400

    app.status = RequestStatus.REJECTED
    try:
        db.session.commit()
        return jsonify(ok=True, message="SGB application declined")
    except Exception as e:
        db.session.rollback()
        return jsonify(ok=False, message="Failed to decline SGB application"), 500


# -----------------------
# Employee: Get Single SGB Application
# -----------------------
@api_bp.get("/ops/sgb/<int:sgb_app_id>")
@login_required
def ops_sgb_get(sgb_app_id: int):
    _require_employee_or_admin()
    app = SGBApplication.query.get(sgb_app_id)
    if not app:
        return jsonify(ok=False, message="SGB application not found"), 404

    customer = Customer.query.get(app.customer_id)
    account = Account.query.get(app.account_id)

    return jsonify(ok=True, sgb_app={
        "id": app.id,
        "customer_name": customer.full_name if customer else "Unknown",
        "account_no": account.account_no if account else "Unknown",
        "series": app.series,
        "investment_amount": float(app.investment_amount),
        "units": float(app.units),
        "pan_number": app.pan_number,
        "current_value": float(app.current_value or 0),
        "interest_earned": float(app.interest_earned or 0),
        "status": app.status.value,
        "kyc_file_path": app.kyc_file_path,
        "created_at": app.created_at.isoformat() if app.created_at else None,
        "updated_at": app.updated_at.isoformat() if app.updated_at else None
    })
