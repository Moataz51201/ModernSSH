import bcrypt
import json

def create_user(username, password, role='user'):
    if role not in ['admin', 'user']:
        print(" Invalid role! Role must be 'admin' or 'user'.")
        return

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    users = {}
    try:
        with open("users.json", "r") as file:
            users = json.load(file)
    except FileNotFoundError:
        pass

    users[username] = {
        "password": hashed_password,
        "role": role
    }

    with open("users.json", "w") as file:
        json.dump(users, file, indent=4)

    print(f" User '{username}' with role '{role}' added successfully!")

# Example usage:
create_user("normaluser", "user123", "user")  # Change username, password, role as needed
create_user("root","kali","admin")
