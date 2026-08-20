import sqlite3

DATABASE_PATH = "database/logs.db"

connection = sqlite3.connect(DATABASE_PATH)
cursor = connection.cursor()

columns = [
    ("last_login", "TEXT"),
    ("failed_login_attempts", "INTEGER NOT NULL DEFAULT 0"),
    ("locked_until", "TEXT"),
    ("is_active", "INTEGER NOT NULL DEFAULT 1"),
]

existing_columns = [
    row[1]
    for row in cursor.execute("PRAGMA table_info(users)").fetchall()
]

for column_name, column_definition in columns:

    if column_name in existing_columns:
        print(f"{column_name} already exists - skipped")
        continue

    cursor.execute(
        f"ALTER TABLE users ADD COLUMN {column_name} {column_definition}"
    )

    print(f"{column_name} added")

connection.commit()
connection.close()

print()
print("Database migration completed.")