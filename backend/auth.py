# backend/auth.py
from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user, login_required
from database.models import db, User, Role, UserRole

auth_bp = Blueprint("auth", __name__)

def _json():
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form.to_dict()

@auth_bp.post("/register")
def register():
    data = _json()
    first = (data.get("first_name") or "").strip()
    last  = (data.get("last_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    pwd   = (data.get("password") or "").strip()

    if not all([first, last, email, pwd]):
        return jsonify(ok=False, message="All fields are required."), 400

    if User.query.filter_by(email=email).first():
        return jsonify(ok=False, message="Email already registered."), 409

    user = User(first_name=first, last_name=last, email=email)
    user.set_password(pwd)
    db.session.add(user)
    db.session.flush()  # get user.id before role link

    # Attach CUSTOMER role if it exists
    customer_role = Role.query.filter_by(name="CUSTOMER").first()
    if customer_role:
        db.session.add(UserRole(user_id=user.id, role_id=customer_role.id))

    db.session.commit()
    return jsonify(ok=True, message="Registration successful. Please log in."), 201

@auth_bp.post("/login")
def login():
    data = _json()
    email = (data.get("email") or "").strip().lower()
    pwd   = (data.get("password") or "").strip()

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(pwd):
        return jsonify(ok=False, message="Invalid email or password."), 401

    login_user(user)
    return jsonify(
        ok=True,
        message="Logged in.",
        user={"id": user.id, "first_name": user.first_name, "last_name": user.last_name, "email": user.email},
    )

@auth_bp.post("/logout")
@login_required
def logout():
    logout_user()
    return jsonify(ok=True, message="Logged out.")
