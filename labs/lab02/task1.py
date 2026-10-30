from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PBKDF2_ITERATIONS = 310_000
SESSION_TIMEOUT_SEC = 900
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


class User:
    """Модель облікового запису користувача."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
        password: str | None = None,
    ) -> None:
        if not username.strip():
            raise ValueError("Ім'я користувача не може бути порожнім.")
        if not role.strip():
            raise ValueError("Роль не може бути порожньою.")
        self.username = username
        self._email = ""
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""
        if password is not None:
            self.set_password(password)

    @property
    def email(self) -> str:
        """Повертає перевірену адресу електронної пошти."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if (
            not isinstance(value, str)
            or EMAIL_PATTERN.fullmatch(value) is None
        ):
            raise ValueError("Некоректний формат email.")
        self._email = value

    def set_password(self, password: str) -> None:
        """Хешування пароля через PBKDF2-HMAC із сіллю."""
        if len(password) < 8:
            raise ValueError("Пароль має містити щонайменше 8 символів.")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Перевірка пароля із захистом від атак за часом."""
        if not self.__password_hash:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        """Деактивація користувача."""
        self.active = False

    def __str__(self) -> str:
        status = "active" if self.active else "inactive"
        return (
            f"User(username={self.username!r}, email={self.email!r}, "
            f"role={self.role!r}, {status})"
        )


class Admin(User):
    """Обліковий запис адміністратора з розширеними правами."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str | None = None,
        active: bool = True,
        permissions: set[str] | None = None,
    ) -> None:
        super().__init__(username, email, "admin", active, password)
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        """Надання дозволу адміністратору."""
        if not permission.strip():
            raise ValueError("Дозвіл не може бути порожнім.")
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Вилучення дозволу адміністратора."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевірка наявності дозволу."""
        return permission in self.permissions

    def __str__(self) -> str:
        base = super().__str__()
        return f"{base}, permissions={sorted(self.permissions)!r}"


class Session:
    """Сесія користувача з фіксацією активності в UTC."""

    def __init__(self, ip: str) -> None:
        if not ip.strip():
            raise ValueError("IP-адреса не може бути порожньою.")
        now = datetime.now(timezone.utc)
        self.ip = ip
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        """Оновлення часу останньої активності."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевірка тривалості сесії."""
        if timeout_sec <= 0:
            raise ValueError("Таймаут має бути додатним числом.")
        elapsed = datetime.now(timezone.utc) - self.last_activity
        return elapsed <= timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditRecord:
    """Запис події аудиту."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал обліку дій користувачів."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        """Додавання запису події в журнал."""
        ts = datetime.now(timezone.utc)
        self._records.append(AuditRecord(ts, username, action))

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        """Повертає копію списку записів."""
        return tuple(self._records)

    def show_all(self) -> None:
        """Вивід усіх записів журналу аудиту."""
        for rec in self._records:
            print(
                f"{rec.timestamp.isoformat()} | {rec.username} | {rec.action}"
            )


_ALLOWED_KEYS = {"user", "session", "audit_log", "authenticated"}

_WRITABLE_TYPES = {
    "user": User,
    "session": Session,
    "audit_log": AuditLog,
}


class UserAccount:
    """Агрегатор даних користувача, сесії та аудиту."""

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Автентифікація та відкриття сесії."""
        if username != self.user.username or not self.user.active:
            self.audit_log.add_log(username, "login_failure")
            return False
        if not self.user.check_password(password):
            self.audit_log.add_log(username, "login_failure")
            return False
        self.session = Session(ip)
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        """Перевірка дійсності поточної сесії."""
        if self.session is None:
            return False
        if not self.session.is_active(SESSION_TIMEOUT_SEC):
            self.session = None
            return False
        return self.user.active

    def logout(self) -> None:
        """Завершення поточної сесії."""
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> User | Session | AuditLog | bool:
        if key not in _ALLOWED_KEYS:
            raise KeyError(f"Невідомий або захищений ключ: {key}")
        if key == "authenticated":
            return self.is_authenticated()
        return getattr(self, key)

    def __setitem__(
        self, key: str, value: User | Session | AuditLog | None
    ) -> None:
        expected = _WRITABLE_TYPES.get(key)
        if expected is None:
            raise KeyError(f"Невідомий або захищений ключ: {key}")
        if value is None and key == "session":
            self.session = None
            return
        if not isinstance(value, expected):
            raise TypeError(
                f"Значення для {key!r} має бути {expected.__name__}."
            )
        setattr(self, key, value)


def run_demo() -> None:
    """Демонстрація функціоналу класів ООП."""
    admin = Admin("security_admin", "admin_1@example.org", "SecurePass123!")
    admin.grant_permission("view_audit")
    account = UserAccount(admin)

    print(
        "Успішний вхід:",
        account.login("security_admin", "SecurePass123!", "192.0.2.10"),
    )
    print(
        "Невдалий вхід:",
        account.login("security_admin", "wrong-password", "192.0.2.10"),
    )

    try:
        admin.email = "invalid-email"
    except ValueError as err:
        print("Перевірка валідації email:", err)

    admin.email = "admin_2@example.org"
    print("Оновлений email:", admin.email)
    print("Права адміністратора:", admin.permissions)

    if account.session is not None:
        account.session.last_activity -= timedelta(
            seconds=SESSION_TIMEOUT_SEC + 1
        )
    print("Сесія активна після таймауту:", account.is_authenticated())

    account.login("security_admin", "SecurePass123!", "192.0.2.10")
    account.logout()
    print("\nЖурнал аудиту:")
    account.audit_log.show_all()
