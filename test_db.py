import mysql.connector

DB_CONFIG = {
    "host": "localhost",
    "user": "capstone_user",
    "password": "Capstone123!",
    "database": "cloud_security_posture_db",
}

conn = mysql.connector.connect(**DB_CONFIG)
cursor = conn.cursor()

cursor.execute("SELECT COUNT(*) FROM findings")
count = cursor.fetchone()[0]
print("Total findings stored:", count)

cursor.execute("""
SELECT finding_code, title, severity
FROM findings
ORDER BY detected_at DESC
LIMIT 3
""")

for row in cursor.fetchall():
    print(row)

cursor.close()
conn.close()