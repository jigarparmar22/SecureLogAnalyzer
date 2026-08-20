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
    
        password_hash TEXT NOT NULL,
    
        role TEXT NOT NULL DEFAULT 'user',
    
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
        last_login TEXT,
    
        failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    
        locked_until TEXT,
    
        is_active INTEGER NOT NULL DEFAULT 1
    
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

def search_events(event_id=None, level=None, provider=None, start_time=None, end_time=None):
    """
    Combined event search that safely combines any provided filters.
    All filters are optional and are AND-ed together.
    """

    connection = get_connection()

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    query = """
        SELECT
            event_id,
            level,
            time,
            provider,
            computer,
            message
        FROM events
        WHERE 1=1
    """

    params = []

    if event_id:
        query += " AND event_id = ?"
        params.append(event_id)

    if level:
        query += " AND level = ?"
        params.append(level)

    if provider:
        query += " AND provider LIKE ?"
        params.append(f"%{provider}%")

    if start_time:
        query += " AND substr(time, 1, 16) >= ?"
        params.append(start_time)

    if end_time:
        query += " AND substr(time, 1, 16) <= ?"
        params.append(end_time)

    query += " ORDER BY id ASC"

    cursor.execute(query, params)

    rows = cursor.fetchall()

    connection.close()

    return rows

def create_user(username, password_hash, role="user"):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO users
        (
            username,
            password_hash,
            role
        )
        VALUES (?, ?, ?)
    """, (
        username,
        password_hash,
        role
    ))

    connection.commit()
    connection.close()

def get_user(username):

    connection = get_connection()

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            password_hash,
            role,
            created_at,
            last_login,
            failed_login_attempts,
            locked_until,
            is_active
        FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()

    connection.close()

    return user

def get_user_by_id(user_id):

    connection = get_connection()

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            password_hash,
            role,
            created_at,
            last_login,
            failed_login_attempts,
            locked_until,
            is_active
        FROM users
        WHERE id = ?
    """, (user_id,))

    user = cursor.fetchone()

    connection.close()

    return user

def record_failed_login(username, max_attempts=5):
    """
    Increase failed login attempts.
    Lock the account for 15 minutes when the limit is reached.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1
        WHERE username = ?
    """, (username,))

    cursor.execute("""
        SELECT failed_login_attempts
        FROM users
        WHERE username = ?
    """, (username,))

    result = cursor.fetchone()

    if result:
        attempts = result[0]

        if attempts >= max_attempts:

            cursor.execute("""
                UPDATE users
                SET locked_until = datetime('now', '+15 minutes')
                WHERE username = ?
            """, (username,))

    connection.commit()
    connection.close()


def reset_failed_login(username):
    """
    Reset failed login attempts after a successful login.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE users
        SET
            failed_login_attempts = 0,
            locked_until = NULL,
            last_login = datetime('now')
        WHERE username = ?
    """, (username,))

    connection.commit()
    connection.close()


def is_account_locked(username):
    """
    Return True if the account is currently locked.
    Automatically clears an expired lock.
    """

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT locked_until
        FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()

    if not user:
        connection.close()
        return False

    locked_until = user["locked_until"]

    if not locked_until:
        connection.close()
        return False

    cursor.execute("""
        SELECT datetime('now') < ?
    """, (locked_until,))

    locked = cursor.fetchone()[0]

    if locked:
        connection.close()
        return True

    # Lock has expired.
    cursor.execute("""
        UPDATE users
        SET
            locked_until = NULL,
            failed_login_attempts = 0
        WHERE username = ?
    """, (username,))

    connection.commit()
    connection.close()

    return False


def deactivate_user(user_id):
    """
    Disable a user account without deleting it.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE users
        SET is_active = 0
        WHERE id = ?
    """, (user_id,))

    connection.commit()
    connection.close()

def get_all_users():

    connection = get_connection()

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            role,
            created_at,
            last_login,
            failed_login_attempts,
            locked_until,
            is_active
        FROM users
        ORDER BY id ASC
    """)

    users = cursor.fetchall()

    connection.close()

    return users

def username_exists(username):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()

    connection.close()

    return user is not None

def update_user_password(user_id, password_hash):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
    """, (password_hash, user_id))

    connection.commit()
    connection.close()

def activate_user(user_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE users
        SET is_active = 1
        WHERE id = ?
    """, (user_id,))

    connection.commit()
    connection.close()


def delete_user(user_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM users
        WHERE id = ?
    """, (user_id,))

    connection.commit()
    connection.close()