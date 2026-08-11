from werkzeug.security import generate_password_hash

from database.database import create_database, create_user


# Make sure the database and users table exist
create_database()

username = input("Enter username: ")
password = input("Enter password: ")

password_hash = generate_password_hash(password)

try:

    create_user(username, password_hash)

    print()
    print("User created successfully!")
    print("Username:", username)

except Exception as error:

    print()
    print("Could not create user.")
    print("Error:", error)