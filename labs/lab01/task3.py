import csv
import hashlib
import json
import os
import sys
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import ParamSpec, TypeVar

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 14
DATA_DIRECTORY = Path(__file__).parent / "data"
USERS_FILE = DATA_DIRECTORY / "users.csv"
LOG_FILE = DATA_DIRECTORY / "log.json"
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)
P = ParamSpec("P")
T = TypeVar("T")
users_db: list[tuple[str, str]] = []


class ValidationError(Exception):
    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерація sha512 хешу для пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль має містити щонайменше {MIN_PASSWORD_LENGTH} символів."
        )
    return hashlib.sha512(f"{password}{salt}".encode()).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створення запису користувача з хешем пароля."""
    if not username:
        raise ValueError("Логін не може бути порожнім.")
    return username, generate_hash(password, PERSONAL_SALT)


def create_users(
    users_list: tuple[tuple[str, str], ...],
) -> list[tuple[str, str]]:
    """Запис валідних користувачів у CSV-файл."""
    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    created_users: list[tuple[str, str]] = []
    with USERS_FILE.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        for username, password in users_list:
            try:
                record = create_user(username, password)
            except (ValidationError, ValueError) as error:
                print(f"Не вдалося створити {username}: {error}")
                continue
            writer.writerow(record)
            created_users.append(record)
    return created_users


def read_users() -> list[tuple[str, str]]:
    """Зчитування користувачів з файлу users.csv."""
    with USERS_FILE.open("r", newline="", encoding="utf-8") as csv_file:
        return [
            (row[0], row[1]) for row in csv.reader(csv_file) if len(row) == 2
        ]


def _read_log_events() -> list[dict[str, object]]:
    if not LOG_FILE.exists():
        return []
    with LOG_FILE.open("r", encoding="utf-8") as log_file:
        content = log_file.read().strip()
    return json.loads(content) if content else []


def log_event(function: Callable[P, bool]) -> Callable[P, bool]:
    """Декоратор для запису спроб входу у log.json."""

    @wraps(function)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> bool:
        username = str(args[0]) if args else str(kwargs.get("username", ""))
        result = "failure"
        try:
            successful = function(*args, **kwargs)
            result = "success" if successful else "failure"
            return successful
        finally:
            DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
            event = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [],
                "kwargs": {},
            }
            events = _read_log_events()
            events.append(event)
            with LOG_FILE.open("w", encoding="utf-8") as log_file:
                json.dump(events, log_file, ensure_ascii=False, indent=2)

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевірка логіна та пароля."""
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми.")
    password_hash = generate_hash(password, PERSONAL_SALT)
    return (username, password_hash) in users_db


def run_user_storage_and_login_demo() -> None:
    """Створення бази, читання та перевірка входу."""
    global users_db
    users_to_register = (
        ("analyst_01", "SecurePassword@01"),
        ("analyst_02", "SecurePassword@02"),
        ("developer_01", "Developer#Password1"),
        ("developer_02", "Developer#Password2"),
        ("auditor_01", "AuditPassword$001"),
        ("operator_01", "OperatorPassword!1"),
        ("manager_01", "ManagerPassword@1"),
        ("intern_01", "InternPassword#001"),
        ("admin_01", "AdminPassword$001"),
        ("invalid_user", "short"),
    )
    try:
        create_users(users_to_register)
        users_db = read_users()
        print("\nКористувачі з users.csv")
        print(f"{'Логін':<16} Хеш пароля")
        print("-" * 79)
        for username, password_hash in users_db:
            print(f"{username:<16} {password_hash}")

        print("\nСпроби входу")
        print(f"analyst_01: {login('analyst_01', 'SecurePassword@01')}")
        print(f"analyst_01: {login('analyst_01', 'incorrect-password')}")
    except (
        FileNotFoundError,
        PermissionError,
        OSError,
        ValidationError,
        ValueError,
    ) as error:
        print(f"Помилка роботи з даними: {error}")


if __name__ == "__main__":
    run_user_storage_and_login_demo()
