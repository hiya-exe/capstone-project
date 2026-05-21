# import sqlite3

# conn = sqlite3.connect("capstone.db")
# cursor = conn.cursor()

# print("\n--- SCANS ---")
# cursor.execute("SELECT * FROM scans")
# for row in cursor.fetchall():
#     print(row)

# print("\n--- RESOURCES ---")
# cursor.execute("SELECT * FROM resources")
# for row in cursor.fetchall():
#     print(row)

# print("\n--- FINDINGS ---")
# cursor.execute("SELECT * FROM findings")
# for row in cursor.fetchall():
#     print(row)

# print("\n--- CIS MAPPINGS ---")
# cursor.execute("SELECT * FROM finding_cis_mappings")
# for row in cursor.fetchall():
#     print(row)

# conn.close()

import sqlite3

conn = sqlite3.connect("capstone.db")
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

conn.close()