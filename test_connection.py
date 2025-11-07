import psycopg2
from psycopg2 import OperationalError

# Replace with your actual DATABASE_URL from Railway
DATABASE_URL = "postgresql://postgres:faxWXpYkZtpFzFssEFRvzVUKacQGFxaC@switchback.proxy.rlwy.net:46241/railway"

try:
    conn = psycopg2.connect(DATABASE_URL)
    print("✅ Connection successful!")
    conn.close()
except OperationalError as e:
    print("❌ Connection failed:")
    print(e)
