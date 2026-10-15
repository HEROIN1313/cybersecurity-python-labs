USERS = {
    "ciso_office": {
        "role": "ciso",
        "clearance": 4,
        "department": "Executive",
        "active": True,
    },
    "threat_hunter": {
        "role": "threat_analyst",
        "clearance": 3,
        "department": "Threat Intel",
        "active": True,
    },
    "junior_dev": {
        "role": "junior_developer",
        "clearance": 2,
        "department": "Development",
        "active": True,
    },
    "visitor_acc": {
        "role": "visitor",
        "clearance": 1,
        "department": "Guest",
        "active": True,
    },
    "legacy_sys": {
        "role": "legacy",
        "clearance": 2,
        "department": "Legacy",
        "active": False,
    },
}
RESOURCES = [
    ("threat_intelligence", 4),
    ("malware_samples", 3),
    ("coding_guidelines", 2),
    ("visitor_wifi", 1),
    ("strategic_plans", 4),
    ("demo_environment", 1),
    ("risk_assessments", 3),
    ("crypto_keys", 4),
    ("api_documentation", 2),
    ("guest_portal", 1),
]
SECURITY_LEVELS = ("Guest", "Employee", "Privileged", "Executive")
BLOCKED_USERS = {"legacy_sys", "malicious_user", "expired_guest"}


def check_access(username: str, resource_level: int) -> tuple[bool, str]:
    """Перевірка прав доступу користувача до ресурсу."""
    user = USERS.get(username)
    if user is None:
        return False, "User not found"
    if username in BLOCKED_USERS:
        return False, "User is blocked"
    if not user["active"]:
        return False, "Account inactive"
    if int(user["clearance"]) >= resource_level:
        return True, ""
    return False, "Insufficient clearance"


def run_access_control_checks() -> None:
    """Вивід списку ресурсів та перевірка доступу."""
    print("\nРесурси системи")
    for resource, level in RESOURCES:
        print(f"{resource}: {SECURITY_LEVELS[level - 1]}")

    print("\nПеревірка доступу")
    usernames = [*USERS, "malicious_user", "unknown_user"]
    for username in usernames:
        for resource, level in RESOURCES:
            allowed, reason = check_access(username, level)
            outcome = "ALLOW" if allowed else f"DENY ({reason})"
            print(f"user={username} resource={resource} -> {outcome}")


if __name__ == "__main__":
    run_access_control_checks()
