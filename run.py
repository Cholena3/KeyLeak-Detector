"""Root-level runner for Render deployment."""
import subprocess, sys, os
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))
sys.exit(subprocess.call([sys.executable, "app.py"]))
