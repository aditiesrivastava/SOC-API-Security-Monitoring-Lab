from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)


def log_event(status_code, username=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = request.remote_addr
    method = request.method
    endpoint = request.path

    log_entry = (
        f"{timestamp} | "
        f"IP={ip} | "
        f"METHOD={method} | "
        f"ENDPOINT={endpoint} | "
        f"USER={username} | "
        f"STATUS={status_code}\n"
    )

    with open("security.log", "a") as log_file:
        log_file.write(log_entry)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if username == "admin" and password == "Password123":
        log_event(200, username)

        return jsonify({
            "message": "Login successful",
            "user": username
        }), 200

    log_event(401, username)

    return jsonify({
        "message": "Invalid username or password"
    }), 401


@app.route("/admin", methods=["GET"])
def admin():
    log_event(403)

    return jsonify({
        "message": "Access denied"
    }), 403


@app.route("/users", methods=["GET"])
def users():
    log_event(200)

    return jsonify({
        "users": [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"}
        ]
    }), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)