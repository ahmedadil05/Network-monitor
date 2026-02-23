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
    print("\n" + "="*60)
    print("  Network Monitor — AI Log Anomaly Detection System")
    print("  Üsküdar University | Ahmed Adil Badawi Mohammed")
    print("="*60)
    print(f"  URL:      http://127.0.0.1:5000")
    print(f"  Login:    admin / admin123")
    print("="*60 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
