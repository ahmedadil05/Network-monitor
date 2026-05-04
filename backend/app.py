"""
app.py
Flask application factory.
Stack: Python + Flask + PostgreSQL + Isolation Forest (scikit-learn).
Architecture: Three-Tier (Section 4.2). No external APIs (Section 3.4.7).
Deployment: Local/Railway (Section 3.4.6).
"""
import logging
import os
from flask import Flask, g, session

from backend.config import Config
from backend.database.db import get_db, close_db, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)


def create_app(config_object=None):
    """Flask application factory."""
    app = Flask(
        __name__,
        template_folder=os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "frontend", "templates"
        ),
        static_folder=os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "frontend", "static"
        ),
    )

    # ── Configuration ─────────────────────────────────────────────
    cfg = config_object or Config
    app.config.from_object(cfg)

    # ── Database ──────────────────────────────────────────────────
    app.teardown_appcontext(close_db)
    init_db(app)

    # ── Make session user available in templates ──────────────────
    @app.context_processor
    def inject_user():
        from backend.auth.session_manager import get_current_user, is_authenticated
        return {
            "current_user": get_current_user(),
            "is_authenticated": is_authenticated(),
        }

    # ── Blueprints ────────────────────────────────────────────────
    from backend.auth.routes import auth_bp
    from backend.dashboard.routes import dashboard_bp
    from backend.reports.routes import reports_bp
    from backend.admin.routes import admin_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)

    # ── Default admin on first run ────────────────────────────────
    _create_default_admin(app)

    return app


def _create_default_admin(app):
    """Create default admin account if no users exist."""
    with app.app_context():
        from backend.database.db import query_db
        existing = query_db("SELECT user_id FROM users LIMIT 1", one=True)
        if existing is None:
            try:
                from backend.models.user import User
                User.create(username="admin", password="admin123", role="administrator")
                app.logger.info("Default admin created: admin / admin123")
            except Exception as e:
                app.logger.warning("Could not create default admin: %s", e)


if __name__ == "__main__":
    application = create_app()
    application.run(host="0.0.0.0", port=5000, debug=True)
