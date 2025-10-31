# seed_basic.py
from backend import create_app
from database.models import db, Role, User, UserRole, Branch, AccountNumberSeq

app = create_app()

def ensure_role(name: str) -> Role:
    r = Role.query.filter_by(name=name).first()
    if not r:
        r = Role(name=name)
        db.session.add(r)
        db.session.commit()
    return r

def ensure_branch(code: str, name: str, ifsc: str, address: str) -> Branch:
    b = Branch.query.filter_by(code=code).first()
    if not b:
        b = Branch(code=code, name=name, ifsc=ifsc, address=address)
        db.session.add(b)
        db.session.commit()
    if not AccountNumberSeq.query.filter_by(branch_id=b.id).first():
        db.session.add(AccountNumberSeq(branch_id=b.id, next_serial=1000000001))
        db.session.commit()
    return b

def ensure_employee(email: str, first: str, last: str, password: str) -> User:
    u = User.query.filter_by(email=email).first()
    if not u:
        u = User(first_name=first, last_name=last, email=email)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
    emp_role = ensure_role("EMPLOYEE")
    if not UserRole.query.filter_by(user_id=u.id, role_id=emp_role.id).first():
        db.session.add(UserRole(user_id=u.id, role_id=emp_role.id))
        db.session.commit()
    return u

if __name__ == "__main__":
    with app.app_context():
        # Roles
        for r in ["CUSTOMER", "EMPLOYEE", "ADMIN"]:
            ensure_role(r)

        # Branches + number sequences
        ensure_branch("B001", "Main Branch", "YBKL0001", "Head Office")
        ensure_branch("B002", "City Branch", "YBKL0002", "City Center")

        # One default EMPLOYEE user
        ensure_employee("employee@yourbank.local", "Bank", "Employee", "1234")

        print("✅ Seeding done: roles, branches, account_number_seq, employee user.")
