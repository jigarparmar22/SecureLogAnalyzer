import sqlite3
import os

DATABASE_PATH = "database/logs.db"


def get_connection():
    return sqlite3.connect(DATABASE_PATH)


def create_database():

    os.makedirs("database", exist_ok=True)

    connection = get_connection()

    cursor = connection.cursor()

    # Events table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        event_id TEXT,
        level TEXT,
        time TEXT,
        provider TEXT,
        computer TEXT,
        message TEXT

    )
    """)

    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT UNIQUE NOT NULL,

        password_hash TEXT NOT NULL

    )
    """)

    connection.commit()
    connection.close()


def insert_event(event):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
    INSERT INTO events
    (
        event_id,
        level,
        time,
        provider,
        computer,
        message
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """,
    (
        event["event_id"],
        event["level"],
        event["time"],
        event["provider"],
        event["computer"],
        event["message"]
    ))

    connection.commit()
    connection.close()
def insert_events(events):

    connection = get_connection()

    cursor = connection.cursor()

    data = []

    for event in events:

        data.append((
            event["event_id"],
            event["level"],
            event["time"],
            event["provider"],
            event["computer"],
            event["message"]
        ))

    cursor.executemany("""
        INSERT INTO events
        (
            event_id,
            level,
            time,
            provider,
            computer,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, data)

    connection.commit()

    connection.close()


def get_all_events():

    connection = get_connection()

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            event_id,
            level,
            time,
            provider,
            computer,
            message
        FROM events
        ORDER BY id ASC
    """)

    rows = cursor.fetchall()

    connection.close()

    return rows

def search_by_event_id(event_id):

    connection = get_connection()

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            event_id,
            level,
            time,
            provider,
            computer,
            message
        FROM events
        WHERE event_id = ?
        ORDER BY id ASC
    """, (event_id,))

    rows = cursor.fetchall()

    connection.close()

    return rows

def search_by_level(level):

    connection = get_connection()

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            event_id,
            level,
            time,
            provider,
            computer,
            message
        FROM events
        WHERE level = ?
        ORDER BY id ASC
    """, (level,))

    rows = cursor.fetchall()

    connection.close()

    return rows

def search_by_provider(provider):

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            event_id,
            level,
            time,
            provider,
            computer,
            message
        FROM events
        WHERE provider LIKE ?
        ORDER BY id ASC
    """, (f"%{provider}%",))

    rows = cursor.fetchall()

    connection.close()

    return rows

def clear_events():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("DELETE FROM events")

    connection.commit()

    connection.close()

def search_by_datetime(start_time, end_time):

    connection = get_connection()

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            event_id,
            level,
            time,
            provider,
            computer,
            message
        FROM events
        WHERE time >= ?
        AND time <= ?
        ORDER BY id ASC
    """, (start_time, end_time))

    rows = cursor.fetchall()

    connection.close()

    return rows

def create_user(username, password_hash):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO users (username, password_hash)
        VALUES (?, ?)
    """, (username, password_hash))

    connection.commit()
    connection.close()

def get_user(username):

    connection = get_connection()

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, username, password_hash
        FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()

    connection.close()

    return user