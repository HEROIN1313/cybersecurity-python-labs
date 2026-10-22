from __future__ import annotations

import argparse
import logging
from pathlib import Path

from .task1 import run_demo
from .task2 import run_analysis


def build_parser() -> argparse.ArgumentParser:
    """Побудова парсера аргументів командного рядка."""
    parser = argparse.ArgumentParser(description="Лабораторна робота №2")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="Запуск демонстрації моделей ООП")

    analyze = subparsers.add_parser(
        "analyze", help="Аналіз файлу логів SSH auth.log"
    )
    analyze.add_argument(
        "--auth-log", type=Path, required=True, help="Шлях до файлу auth.log"
    )
    analyze.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Поріг невдалих спроб (за замовчуванням: 5)",
    )
    analyze.add_argument(
        "--window-min",
        type=int,
        default=5,
        help="Розмір часового вікна у хвилинах (за замовчуванням: 5)",
    )
    analyze.add_argument(
        "--output-json",
        type=Path,
        help="Шлях для збереження JSON-звіту",
    )
    return parser


def main() -> None:
    """Головна точка входу для запуску CLI."""
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s: %(message)s"
    )
    args = build_parser().parse_args()
    if args.command == "demo":
        run_demo()
    else:
        run_analysis(
            args.auth_log,
            args.threshold,
            args.window_min,
            args.output_json,
        )


if __name__ == "__main__":
    main()
