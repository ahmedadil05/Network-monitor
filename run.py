"""
run.py
Application entry point for local development.
Section 3.4.6 — 'deployed in a local or controlled academic environment.'
Usage: python run.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from backend.app import create_app

if __name__ == "__main__":
    app = create_app()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    public_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
    base_url = f"https://{public_domain}" if public_domain else f"http://{host}:{port}"

    print("\n" + "="*60)
    print("  Network Monitor — AI Log Anomaly Detection System")
    print("  Üsküdar University | Ahmed Adil Badawi Mohammed")
    print("="*60)
    print(f"  URL:      {base_url}")
    print(f"  Login:    admin / admin123")
    print("="*60 + "\n")
    app.run(host=host, port=port, debug=(not bool(public_domain)))
