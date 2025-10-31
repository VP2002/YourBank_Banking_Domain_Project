from flask_sqlalchemy import SQLAlchemy

# One shared SQLAlchemy instance for the whole app
db = SQLAlchemy()

def init_db(app):
    """
    Bind SQLAlchemy to the Flask app.
    Call this once from backend/__init__.py after app.config is set.
    """
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    db.init_app(app)
