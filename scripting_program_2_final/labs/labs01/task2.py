"""Завдання 2: Багаторівнева система контролю доступу (Варіант 1)."""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import (
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

USERS = {
    "admin001": {
        "role": "administrator",
        "clearance": 4,
        "department": "IT",
        "active": True,
    },
    "user123": {
        "role": "analyst",
        "clearance": 2,
        "department": "Security",
        "active": True,
    },
    "guest789": {
        "role": "guest",
        "clearance": 1,
        "department": "External",
        "active": True,
    },
    "manager456": {
        "role": "manager",
        "clearance": 3,
        "department": "Operations",
        "active": True,
    },
    "contractor99": {
        "role": "contractor",
        "clearance": 1,
        "department": "External",
        "active": False,
    },
}

RESOURCES = [
    ("database_backup", 4),
    ("user_logs", 2),
    ("public_docs", 1),
    ("financial_reports", 3),
    ("system_config", 4),
    ("training_materials", 1),
    ("security_policies", 3),
    ("audit_logs", 4),
    ("employee_data", 3),
    ("temp_files", 1),
]

SECURITY_LEVELS = ("Public", "Internal", "Confidential", "Secret")
BLOCKED_USERS = {"contractor99", "temp_user", "suspended_acc"}

# Логіни для перевірки: база + неіснуючий і заблокований користувачі
USERS_TO_CHECK = list(USERS) + ["temp_user", "unknown_user"]


def check_access(username, resource_level):
    """Повертає (дозвіл, причина відмови) для пари користувач-ресурс."""
    if username not in USERS:
        return False, "User not found"

    if username in BLOCKED_USERS:
        return False, "User is blocked"

    user_data = USERS[username]
    if not user_data.get("active", False):
        return False, "Account inactive"

    if user_data["clearance"] >= resource_level:
        return True, ""

    return False, "Insufficient clearance"


def print_resources():
    """Виводить ресурси з текстовою назвою рівня безпеки."""
    print("Список ресурсів системи:")
    for res_name, level_num in RESOURCES:
        level_name = SECURITY_LEVELS[level_num - 1]
        print(f" - {res_name:<20} | Рівень безпеки: {level_name}")


def print_access_matrix():
    """Виводить результат перевірки доступу для всіх пар."""
    print("\nРезультати перевірки доступу:")
    print("-" * 65)
    for username in USERS_TO_CHECK:
        for res_name, res_level in RESOURCES:
            allowed, reason = check_access(username, res_level)
            status = "ALLOW" if allowed else f"DENY ({reason})"
            print(f"user={username:<14} resource={res_name:<20} -> {status}")


def run_task2():
    """Головна точка входу завдання 2."""
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

    print_resources()
    print_access_matrix()


if __name__ == "__main__":
    run_task2()
