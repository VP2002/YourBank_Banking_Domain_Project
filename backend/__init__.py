from flask import Flask, render_template, abort
from flask_login import LoginManager, current_user
from functools import wraps
import os
from flask_migrate import Migrate

from .api import api_bp
from .auth import auth_bp

from database import init_db, db
from database.models import User, Role, UserRole

# ✅ Create migrate object (don’t bind yet)
migrate = Migrate()


def create_app():
    app = Flask(
        __name__,
        template_folder="../frontend/templates",
        static_folder="../frontend/static",
    )

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL",
        "mysql+pymysql://root:Parth%40123@localhost/banking_portal?charset=utf8mb4",
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # --- Uploads ---
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

    UPLOADS_ROOT = os.path.join(PROJECT_ROOT, "uploads")
    KYC_ROOT = os.path.join(UPLOADS_ROOT, "kyc")
    LOANS_ROOT = os.path.join(UPLOADS_ROOT, "loans")

    os.makedirs(KYC_ROOT, exist_ok=True)
    os.makedirs(LOANS_ROOT, exist_ok=True)

    app.config["UPLOADS_ROOT"] = UPLOADS_ROOT
    app.config["KYC_ROOT"] = KYC_ROOT
    app.config["LOANS_ROOT"] = LOANS_ROOT
    app.config["UPLOAD_FOLDER"] = KYC_ROOT
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

    # --- Init DB & Migrate ---
    init_db(app)              # bind db
    migrate.init_app(app, db) # ✅ bind migrate here

    # --- Login ---
    login_manager = LoginManager()
    login_manager.login_view = "home"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str):
        try:
            return db.session.get(User, int(user_id))
        except Exception:
            return None

    # --- Role guard ---
    def role_required(role_name: str):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if not current_user.is_authenticated:
                    return abort(401)
                role = Role.query.filter_by(name=role_name).first()
                if not role:
                    return abort(403)
                link = UserRole.query.filter_by(
                    user_id=current_user.id, role_id=role.id
                ).first()
                if not link:
                    return abort(403)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    # --- Pages ---
    @app.route("/")
    def home():
        return render_template("index.html")

    @app.route("/careers")
    def careers():
        return render_template("careers.html")

    @app.route("/services")
    def services():
        return render_template("services.html")

    @app.route("/security")
    def security():
        return render_template("security.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/employee")
    @role_required("EMPLOYEE")
    def employee():
        return render_template("employee.html")

    # --- Blueprints ---
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(api_bp, url_prefix="/api")

    # --- Helpers for templates ---
    @app.context_processor
    def inject_helpers():
        def has_role(name: str) -> bool:
            if not current_user.is_authenticated:
                return False
            role = Role.query.filter_by(name=name).first()
            if not role:
                return False
            return UserRole.query.filter_by(
                user_id=current_user.id, role_id=role.id
            ).first() is not None
        return dict(has_role=has_role)

    # --- Auto create tables (dev only) ---
    with app.app_context():
        from database import models  # noqa
        db.create_all()

    app.role_required = role_required
    return app
