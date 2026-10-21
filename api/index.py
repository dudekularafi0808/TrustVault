import os
import sys

# Ensure root directory is in sys.path so modules like app and database can be imported
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Set VERCEL environment variable for runtime
os.environ["VERCEL"] = "1"

from app import app

# Vercel WSGI entry point
# Exports the Flask WSGI callable 'app'
