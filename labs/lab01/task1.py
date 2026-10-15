"""Password-strength analysis for laboratory work 1."""

import os
import random
import sys
from collections.abc import Iterable

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "Security@2023",
    "pass",
    "MyStrong#Key",
    "root",
    "Advanc3d@Pass",
    "user",
    "Protec7! Pass",
    "1234",
    "Elite@Security",
    "admin123",
]
CRITERIA = {
    "min_length": 7,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
FORBIDDEN_PASSWORDS = {"pass", "root", "user", "1234", "admin123", "password"}


def add_random_duplicates(passwords: list[str]) -> list[str]:
    """Append duplicates of passwords selected at three random indexes."""
    selected_indexes = random.sample(range(len(passwords)), k=3)
    passwords.extend(passwords[index] for index in selected_indexes)
    return passwords


def has_special_character(password: str) -> bool:
    """Return whether a password contains a non-alphanumeric character."""
    return any(not character.isalnum() for character in password)


def assess_password(
    password: str,
    passwords: Iterable[str],
    criteria: dict[str, int | bool],
    forbidden_passwords: set[str],
) -> str:
    """Classify a password using the specified security criteria."""
    min_length = int(criteria["min_length"])
    has_digit = any(character.isdigit() for character in password)
    has_upper = any(character.isupper() for character in password)
    has_special = has_special_character(password)
    has_lower = any(character.islower() for character in password)
    meets_all = (
        len(password) >= min_length and has_digit and has_upper and has_special
    )
    password_list = list(passwords)

    if password in forbidden_passwords or len(password) < min_length:
        return "Заборонений"
    if (
        meets_all
        and len(password) >= min_length + 4
        and password_list.count(password) == 1
    ):
        return "Дуже сильний"
    if meets_all:
        return "Сильний"
    if (
        len(password) >= min_length
        and sum((has_digit, has_upper, has_special, has_lower)) > 0
    ):
        return "Середній"
    if has_digit or has_upper or has_special or has_lower:
        return "Слабкий"
    return "Слабкий"


def run_password_analysis() -> None:
    """Print student details and a table of password-strength results."""
    passwords = add_random_duplicates(PASSWORDS.copy())
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print("\nАналіз надійності паролів")
    print(f"{'№':<3} {'Пароль':<20} Результат")
    print("-" * 48)
    for index, password in enumerate(passwords, start=1):
        result = assess_password(
            password, passwords, CRITERIA, FORBIDDEN_PASSWORDS
        )
        print(f"{index:<3} {password:<20} {result}")


if __name__ == "__main__":
    run_password_analysis()
