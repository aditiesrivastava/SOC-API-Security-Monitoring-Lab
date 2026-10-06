from collections import defaultdict
from datetime import datetime, timedelta

LOG_FILE = "security.log"
ALERT_FILE = "alerts.log"

failed_logins = defaultdict(list)
forbidden_access = defaultdict(list)


def write_alert(severity, alert_type, ip, endpoint, count):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = (
        f"{timestamp} | "
        f"SEVERITY={severity} | "
        f"TYPE={alert_type} | "
        f"IP={ip} | "
        f"ENDPOINT={endpoint} | "
        f"COUNT={count}\n"
    )

    with open(ALERT_FILE, "a") as file:
        file.write(alert)

    print(alert.strip())


# -----------------------------
# READ SECURITY LOG
# -----------------------------

with open(LOG_FILE, "r") as file:

    for line in file:

        parts = line.strip().split(" | ")

        if len(parts) < 6:
            continue

        timestamp = datetime.strptime(
            parts[0],
            "%Y-%m-%d %H:%M:%S"
        )

        ip = parts[1].replace("IP=", "")
        endpoint = parts[3].replace("ENDPOINT=", "")
        status = parts[5].replace("STATUS=", "")

        if status == "401":
            failed_logins[ip].append(timestamp)

        if status == "403":
            forbidden_access[ip].append(timestamp)


# -----------------------------
# DETECTION 1: BRUTE FORCE
# -----------------------------

for ip, timestamps in failed_logins.items():

    timestamps.sort()

    for i in range(len(timestamps)):

        window_start = timestamps[i]
        window_end = window_start + timedelta(seconds=60)

        attempts = [
            t for t in timestamps
            if window_start <= t <= window_end
        ]

        if len(attempts) >= 5:

            write_alert(
                "HIGH",
                "BRUTE_FORCE",
                ip,
                "/login",
                len(attempts)
            )

            break


# -----------------------------
# DETECTION 2: ADMIN PROBING
# -----------------------------

for ip, timestamps in forbidden_access.items():

    timestamps.sort()

    for i in range(len(timestamps)):

        window_start = timestamps[i]
        window_end = window_start + timedelta(seconds=60)

        attempts = [
            t for t in timestamps
            if window_start <= t <= window_end
        ]

        if len(attempts) >= 3:

            write_alert(
                "MEDIUM",
                "ADMIN_PROBING",
                ip,
                "/admin",
                len(attempts)
            )

            break