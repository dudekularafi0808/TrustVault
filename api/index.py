import os
import sys

# Ensure root directory is in sys.path so modules like app and database can be imported
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Set VERCEL environment variable for runtime
os.environ["VERCEL"] = "1"

# Cloud fallbacks when .env is gitignored
if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "postgresql://postgres.lduepqknvpsfjycarevm:Ece%400460___@aws-0-ap-northeast-1.pooler.supabase.com:5432/postgres?sslmode=require"
if not os.environ.get("HOST_EMAIL"):
    os.environ["HOST_EMAIL"] = "23jr1a0460@gmail.com"
if not os.environ.get("SMTP_SERVER"):
    os.environ["SMTP_SERVER"] = "smtp.gmail.com"
if not os.environ.get("SMTP_PORT"):
    os.environ["SMTP_PORT"] = "465"
if not os.environ.get("SMTP_USERNAME"):
    os.environ["SMTP_USERNAME"] = "23jr1a0460@gmail.com"
if not os.environ.get("SMTP_PASSWORD"):
    os.environ["SMTP_PASSWORD"] = "dadgojkawkgvfyqk"
if not os.environ.get("SMTP_SENDER"):
    os.environ["SMTP_SENDER"] = "TrustVault Security <23jr1a0460@gmail.com>"
if not os.environ.get("SMTP_USE_TLS"):
    os.environ["SMTP_USE_TLS"] = "false"

from app import app

# Vercel WSGI entry point
# Exports the Flask WSGI callable 'app'
