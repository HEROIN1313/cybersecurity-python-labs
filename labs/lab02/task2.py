from __future__ import annotations

import json
import logging
import re
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

LOGGER = logging.getLogger(__name__)
AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?sshd(?:\[\d+\])?: "
    r"(?P<status>Failed|Accepted) password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+)\b"
)


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """Подія автентифікації SSH."""

    timestamp: datetime
    status: str
    username: str
    ip_address: str


@dataclass(frozen=True, slots=True)
class BruteForceAlert:
    """Виявлена атака підбору паролів."""

    ip_address: str
    attempts: int
    target_users: tuple[str, ...]
    window_start: datetime
    window_end: datetime


def parse_auth_log(path: Path, year: int | None = None) -> list[AuthEvent]:
    """Парсинг подій автентифікації SSH з файлу auth.log."""
    if not path.is_file():
        raise FileNotFoundError(f"Файл логу не знайдено: {path}")

    log_year = year if year is not None else datetime.now().year
    events: list[AuthEvent] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line_number, line in enumerate(lines, start=1):
        match = AUTH_PATTERN.search(line)
        if match is None:
            continue
        try:
            timestamp = datetime.strptime(
                f"{log_year} {match['timestamp']}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=None)
        except ValueError:
            LOGGER.warning("Пропуск рядка %d: некоректний час", line_number)
            continue
        events.append(
            AuthEvent(timestamp, match["status"], match["user"], match["ip"])
        )

    events.sort(key=lambda event: event.timestamp)
    LOGGER.info(
        "Оброблено %d рядків, виявлено %d подій SSH", len(lines), len(events)
    )
    return events


def detect_bruteforce(
    events: list[AuthEvent], threshold: int, window_min: int
) -> list[BruteForceAlert]:
    """Виявлення атак перебору паролів за ковзним вікном часу."""
    if threshold < 0:
        raise ValueError("Поріг не може бути від'ємним.")
    if window_min <= 0:
        raise ValueError("Розмір вікна має бути більшим за нуль.")

    window = timedelta(minutes=window_min)
    failures: defaultdict[str, deque[AuthEvent]] = defaultdict(deque)
    alerts: list[BruteForceAlert] = []
    alerted_ips: set[str] = set()
    for event in events:
        if event.status != "Failed":
            continue
        attempts = failures[event.ip_address]
        attempts.append(event)
        while attempts and event.timestamp - attempts[0].timestamp > window:
            attempts.popleft()
        if len(attempts) > threshold and event.ip_address not in alerted_ips:
            alert = BruteForceAlert(
                ip_address=event.ip_address,
                attempts=len(attempts),
                target_users=tuple(
                    sorted({item.username for item in attempts})
                ),
                window_start=attempts[0].timestamp,
                window_end=event.timestamp,
            )
            alerts.append(alert)
            alerted_ips.add(event.ip_address)
            LOGGER.error(
                "Виявлено брутфорс з %s: %d спроб (користувачі: %s)",
                alert.ip_address,
                alert.attempts,
                ", ".join(alert.target_users),
            )
    return alerts


def export_blocked_ips(
    alerts: list[BruteForceAlert], output_path: Path
) -> None:
    """Експорт списку заблокованих IP та деталей атаки у JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = []
    for alert in alerts:
        item = asdict(alert)
        item["target_users"] = list(alert.target_users)
        item["window_start"] = alert.window_start.isoformat(sep=" ")
        item["window_end"] = alert.window_end.isoformat(sep=" ")
        payload.append(item)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    LOGGER.info("Звіт збережено у %s", output_path)


def run_analysis(
    auth_log: Path,
    threshold: int = 5,
    window_min: int = 5,
    output_json: Path | None = None,
) -> list[BruteForceAlert]:
    """Аналіз логу, вивід виявлених IP та експорт звіту."""
    LOGGER.info("Аналіз подій автентифікації у %s", auth_log)
    events = parse_auth_log(auth_log)
    alerts = detect_bruteforce(events, threshold, window_min)
    print("=== SSH Bruteforce Detection Results ===")
    print(
        f"Failed Attempts Threshold: >{threshold} attempts in "
        f"{window_min} minutes"
    )
    for alert in alerts:
        users = ", ".join(alert.target_users)
        print(
            f"[ALERT] Bruteforce Detected! IP: {alert.ip_address} | "
            f"Total Failures: {alert.attempts} | Target Users: {users}"
        )
    print("=== Recommended Blocklist (IPs) ===")
    for alert in alerts:
        print(alert.ip_address)
    if output_json is not None:
        export_blocked_ips(alerts, output_json)
    return alerts
