"""Завдання 1: Комплексний аналізатор надійності паролів (Варіант 1)."""

import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import (
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

PASSWORDS = [
    "password123",
    "Qwerty!2023",
    "admin",
    "MyP@ssw0rd",
    "123456",
    "SecurePass!",
    "test",
    "P@ssw0rd123",
    "welcome",
    "StrongP@ss1",
]

CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "password",
    "123456",
    "admin",
    "test",
    "welcome",
    "qwerty",
}


def evaluate_password(pwd, rules, forbidden, all_passwords):
    """Повертає текстову оцінку надійності одного пароля."""
    min_len = rules["min_length"]

    if pwd in forbidden or len(pwd) < min_len:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in pwd)
    has_upper = any(char.isupper() for char in pwd)
    has_lower = any(char.islower() for char in pwd)
    has_special = any(not char.isalnum() for char in pwd)

    meets_all = (
        (has_digit or not rules["require_digits"])
        and (has_upper or not rules["require_upper"])
        and (has_special or not rules["require_special"])
    )

    if meets_all:
        is_unique = all_passwords.count(pwd) == 1
        if len(pwd) >= min_len + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"

    groups_met = sum([has_digit, has_upper, has_lower, has_special])
    if groups_met >= 2:
        return "Середній"

    return "Слабкий"


def build_password_list(source):
    """Додає 3 випадкові дублікати в кінець списку паролів."""
    extended = source.copy()
    for index in random.sample(range(len(source)), 3):
        extended.append(source[index])
    return extended


def print_report(results):
    """Виводить результати аналізу у табличному вигляді."""
    print(f"{'ПАРОЛЬ':<20} | {'СТАТУС':<15}")
    print("-" * 38)
    for pwd, status in results:
        print(f"{pwd:<20} | {status:<15}")


def run_task1():
    """Головна точка входу завдання 1."""
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n")

    random.seed(42)
    all_passwords = build_password_list(PASSWORDS)

    results = [
        (
            pwd,
            evaluate_password(pwd, CRITERIA, FORBIDDEN_PASSWORDS, all_passwords),
        )
        for pwd in all_passwords
    ]

    print_report(results)


if __name__ == "__main__":
    run_task1()
