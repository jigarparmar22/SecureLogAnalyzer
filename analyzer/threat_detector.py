from datetime import datetime
# Windows Security Threat Rules


THREAT_RULES = {
    "4624": ("Successful Login", "Low"),
    "4625": ("Failed Login Attempt", "High"),
    "1102": ("Security Log Cleared", "Critical"),
    "4672": ("Special Privileges Assigned", "Medium"),
    "4720": ("New User Account Created", "Medium"),
    "4726": ("User Account Deleted", "High"),
    "4728": ("User Added to Privileged Group", "High"),
    "4732": ("Member Added to Local Group", "Medium")
}


# Number of failed login attempts required
# before triggering the brute-force rule.

FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 10

def parse_event_time(time_value):

    if not time_value:
        return None

    time_value = str(time_value).strip()

    # Windows Event Log format:
    # 2026-07-16T11:09:11.9240531Z

    try:
        # Remove the UTC Z
        if time_value.endswith("Z"):
            time_value = time_value[:-1]

        # Python supports up to 6 microsecond digits.
        # Windows may provide 7 digits, so trim to 6.
        if "." in time_value:

            date_part, fraction = time_value.split(".", 1)

            fraction = fraction[:6]

            time_value = f"{date_part}.{fraction}"

            return datetime.strptime(
                time_value,
                "%Y-%m-%dT%H:%M:%S.%f"
            )

        return datetime.strptime(
            time_value,
            "%Y-%m-%dT%H:%M:%S"
        )

    except ValueError:

        return None

def detect_threats(events):

    detected_threats = []

    # Sort events using their actual timestamps
    events = sorted(
        events,
        key=lambda event: parse_event_time(event["time"])
        or datetime.min
    )
    # -------------------------------------------------
    # RULE 1: Individual Event ID Detection
    # -------------------------------------------------

    for event in events:

        event_id = str(event["event_id"])

        if event_id in THREAT_RULES:

            threat_name, severity = THREAT_RULES[event_id]

            detected_threats.append({
                "event_id": event_id,
                "threat": threat_name,
                "severity": severity,
                "level": event["level"],
                "time": event["time"],
                "computer": event["computer"],
                "provider": event["provider"],
            })


        # -------------------------------------------------
    # RULE 2: Time-Based Failed Login Detection
    # Possible Brute Force Attack
    # -------------------------------------------------

    failed_logins = []

    for event in events:

        if str(event["event_id"]) == "4625":

            event_time = parse_event_time(event["time"])

            if event_time:

                failed_logins.append(
                    (event_time, event)
                )


    # Sort failed login events chronologically

    failed_logins.sort(key=lambda item: item[0])


    # Check whether enough failed logins
    # occurred inside the configured time window

    if len(failed_logins) >= FAILED_LOGIN_THRESHOLD:

        for index in range(
            len(failed_logins) - FAILED_LOGIN_THRESHOLD + 1
        ):

            first_time = failed_logins[index][0]

            last_time = failed_logins[
                index + FAILED_LOGIN_THRESHOLD - 1
            ][0]

            time_difference = (
                last_time - first_time
            ).total_seconds() / 60


            if time_difference <= FAILED_LOGIN_WINDOW_MINUTES:

                latest_event = failed_logins[
                    index + FAILED_LOGIN_THRESHOLD - 1
                ][1]


                detected_threats.append({
                    "event_id": "4625",
                    "threat": "Possible Brute Force Attack",
                    "severity": "Critical",
                    "level": latest_event["level"],
                    "time": latest_event["time"],
                    "computer": latest_event["computer"],
                    "provider": latest_event["provider"],
                })

                break


    # -------------------------------------------------
    # RULE 3: Time-Based Failed Login Followed
    # by Successful Login
    # Possible Account Compromise
    # -------------------------------------------------

    failed_login_sequence = []

    for event in events:

        event_id = str(event["event_id"])

        event_time = parse_event_time(event["time"])

        if event_time is None:
            continue

        # Store failed login attempts
        if event_id == "4625":

            failed_login_sequence.append(
                (event_time, event)
            )

        # Check successful login
        elif event_id == "4624":

            # Need at least 5 failed attempts
            if len(failed_login_sequence) >= FAILED_LOGIN_THRESHOLD:

                latest_failed_time = failed_login_sequence[-1][0]

                time_difference = (
                    event_time - latest_failed_time
                ).total_seconds() / 60

                # Successful login happened within
                # the configured time window
                if (
                    0 <= time_difference
                    <= FAILED_LOGIN_WINDOW_MINUTES
                ):

                    detected_threats.append({
                        "event_id": "4624",
                        "threat": "Possible Account Compromise",
                        "severity": "Critical",
                        "level": event["level"],
                        "time": event["time"],
                        "computer": event["computer"],
                        "provider": event["provider"],
                    })

                    # Prevent the same sequence
                    # from being detected repeatedly.
                    failed_login_sequence = []
    # -------------------------------------------------
    # RULE 4: Suspicious Account and Privilege Activity
    # -------------------------------------------------

    new_account_detected = False

    for event in events:

        event_id = str(event["event_id"])

        # New user account created
        if event_id == "4720":

            new_account_detected = True

        # New account followed by special privileges
        elif event_id == "4672" and new_account_detected:

            detected_threats.append({
                "event_id": "4672",
                "threat": "Possible Privilege Escalation After Account Creation",
                "severity": "Critical",
                "level": event["level"],
                "time": event["time"],
                "computer": event["computer"],
                "provider": event["provider"],
            })

            new_account_detected = False

        # New account followed by privileged group membership
        elif event_id == "4728" and new_account_detected:

            detected_threats.append({
                "event_id": "4728",
                "threat": "New Account Added to Privileged Group",
                "severity": "Critical",
                "level": event["level"],
                "time": event["time"],
                "computer": event["computer"],
                "provider": event["provider"],
            })

            new_account_detected = False

        # New account followed by local group membership
        elif event_id == "4732" and new_account_detected:

            detected_threats.append({
                "event_id": "4732",
                "threat": "New Account Added to Local Group",
                "severity": "High",
                "level": event["level"],
                "time": event["time"],
                "computer": event["computer"],
                "provider": event["provider"],
            })

            new_account_detected = False

    # -------------------------------------------------
    # RULE 5: Security Log Tampering Detection
    # -------------------------------------------------

    suspicious_before_log_clear = False

    for event in events:

        event_id = str(event["event_id"])

        # Suspicious activity before the log is cleared
        if event_id in ["4625", "4672", "4720", "4728", "4732"]:

            suspicious_before_log_clear = True

        # Security log cleared after suspicious activity
        elif event_id == "1102" and suspicious_before_log_clear:

            detected_threats.append({
                "event_id": "1102",
                "threat": "Possible Security Log Tampering",
                "severity": "Critical",
                "level": event["level"],
                "time": event["time"],
                "computer": event["computer"],
                "provider": event["provider"],
            })

            suspicious_before_log_clear = False
    return detected_threats