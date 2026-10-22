"""
CyberPulse Master Launcher (IBM Bootcamp Project)
Convenient 1-click launcher to run the Cyber Command Center or Streamlit Dashboard.

Usage:
    python run.py                 # Launches the Flask Cyber Command Center (http://127.0.0.1:5000)
    python run.py --streamlit     # Launches the Streamlit Analytics Dashboard (http://localhost:8501)
    python run.py --test          # Runs all 187 automated unit tests
"""
import sys
import os
import subprocess

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
CYBERPULSE_DIR = os.path.join(ROOT_DIR, "CyberPulse")


def main():
    if "--streamlit" in sys.argv:
        print(">> Launching CyberPulse Streamlit Analytics Dashboard...")
        app_path = os.path.join(CYBERPULSE_DIR, "app.py")
        subprocess.run([sys.executable, "-m", "streamlit", "run", app_path], cwd=CYBERPULSE_DIR)
    elif "--test" in sys.argv:
        print(">> Running CyberPulse Comprehensive Unit Test Suite (187 Tests)...")
        test_runner = os.path.join(CYBERPULSE_DIR, "tests", "run_tests.py")
        subprocess.run([sys.executable, test_runner], cwd=CYBERPULSE_DIR)
    else:
        print("==================================================================")
        print("   CYBERPULSE — Automated Threat Intelligence & IOC Analyzer    ")
        print("   IBM Bootcamp Capstone Project Portfolio                       ")
        print("==================================================================")
        print(">> Starting Cyber Command Center Server on http://127.0.0.1:5000 ...")
        print(">> Press Ctrl+C to stop the server.")
        server_path = os.path.join(CYBERPULSE_DIR, "server.py")
        subprocess.run([sys.executable, server_path], cwd=CYBERPULSE_DIR)


if __name__ == "__main__":
    main()
