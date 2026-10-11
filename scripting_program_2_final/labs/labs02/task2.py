"""Завдання 2, варіант 1: аналізатор журналів веб-сервера (Nginx/Apache access.log).

Утиліта розбирає рядки журналу регулярними виразами ``re``, фільтрує запити
за часовим інтервалом (``datetime``), рахує топ-N IP-адрес з відповідями-
помилками (``collections.Counter``), шукає сигнатури базових атак (SQLi,
Directory Traversal, XSS), друкує підсумок і зберігає звіт у JSON або CSV.
Хід роботи фіксується через ``logging``.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote_plus

logger = logging.getLogger("lab02.access_log")

# --- Константи ---------------------------------------------------------------
DEFAULT_LOG_FILE = Path(__file__).resolve().parent / "data" / "data_v01" / "access.log"
DEFAULT_MIN_STATUS = 400
DEFAULT_TOP = 5
MIN_HTTP_STATUS = 100
MAX_HTTP_STATUS = 599
MAX_DECODE_ROUNDS = 3  # захист від подвійного кодування (%252e%252e)
PRINT_REQUEST_LIMIT = 100  # довжина запиту в консольному виводі
REPORT_REQUEST_LIMIT = 500  # довжина запиту у звіті
REPORT_FORMATS = ("json", "csv")

EXIT_OK = 0
EXIT_ERROR = 1

MONTH_NAMES = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec"
MONTHS = {name: number for number, name in enumerate(MONTH_NAMES.split(), start=1)}

# Common/Combined Log Format. Назву місяця розбираємо вручну (MONTHS), бо
# strptime("%b") залежить від локалі ОС. URI може містити пробіли й лапки
# (неекрановані атаки), тому береться нежадібно до протоколу "HTTP/x.y".
LOG_LINE_RE = re.compile(
    r"(?P<ip>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4})"
    r":(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"\s+(?P<tz_sign>[+-])(?P<tz_hours>\d{2})(?P<tz_minutes>\d{2})\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<uri>.*?)\s+(?P<protocol>HTTP/\d(?:\.\d)?)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
    r'(?:\s+"[^"]*"\s+"[^"]*")?\s*'  # необов'язкові Referer та User-Agent
)

CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# Сигнатури застосовуються до URI (сирого та декодованого). Кожна атака —
# набір шаблонів; достатньо збігу будь-якого з них.
ATTACK_SIGNATURES: dict[str, tuple[re.Pattern[str], ...]] = {
    "SQLi": tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"\bunion\b[\s/*+]+(?:all\b[\s/*+]+)?select\b",  # UNION SELECT
            r"['\"`]\s*(?:or|and)\b\s*['\"`]?\w+['\"`]?\s*(?:=|like\b)",  # ' OR '1'='1
            r"\b(?:or|and)\s+\d+\s*=\s*\d+",  # OR 1=1
            r"['\"]\s*(?:--|#|/\*)",  # закриття рядка + SQL-коментар
            r"\bselect[\s/*]+.+?[\s/*]+from\b|\binsert\s+into\b|\bdelete\s+from\b",
            r"\bdrop\s+(?:table|database)\b|\binformation_schema\b",
            r"\b(?:sleep|benchmark)\s*\(",  # time-based SQLi
        )
    ),
    "Directory Traversal": tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"\.\.[/\\]",  # ../ або ..\
            r"[/\\]\.\.$",  # /.. наприкінці
            r"/etc/(?:passwd|shadow|hosts)\b",
            r"\b(?:boot|win)\.ini\b",
            r"\bc:[/\\]windows\b",
        )
    ),
    "XSS": tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"<\s*/?\s*script\b",
            r"\bjavascript\s*:",
            r"<[^>]*\bon\w+\s*=",  # <img src=x onerror=...>
            r"[\s\"'/]on(?:error|load|click|mouseover|mouseenter|focus)\s*=",
            r"<\s*(?:iframe|svg|object|embed)\b",
        )
    ),
}


# --- Моделі даних ------------------------------------------------------------
@dataclass(frozen=True)
class LogEntry:
    """Один розібраний рядок access.log."""

    line_no: int
    ip: str
    timestamp: datetime  # з часовим поясом із журналу
    method: str
    uri: str
    protocol: str
    status: int
    size: int | None  # None, якщо у журналі "-"

    @property
    def request(self) -> str:
        return f"{self.method} {self.uri}"


@dataclass(frozen=True)
class AttackAlert:
    """Підозрілий запит, у якому знайдено сигнатуру атаки."""

    attack_type: str
    ip: str
    timestamp: datetime
    request: str
    status: int


@dataclass(frozen=True)
class IpErrorStat:
    """Статистика відповідей-помилок для однієї IP-адреси."""

    ip: str
    errors: int
    statuses: dict[int, int]

    def breakdown(self) -> str:
        """Рядок виду ``404: 120, 500: 22`` (від частіших кодів до рідших)."""
        ordered = sorted(self.statuses.items(), key=lambda item: (-item[1], item[0]))
        return ", ".join(f"{code}: {count}" for code, count in ordered)


@dataclass
class ParseStats:
    """Лічильники читання файлу (заповнюються генератором ``read_entries``)."""

    total_lines: int = 0
    malformed_lines: int = 0


@dataclass
class AnalysisReport:
    """Результат аналізу, з якого формується консольний вивід і файл звіту."""

    source_file: str
    min_status: int
    top: int
    since: datetime | None
    until: datetime | None
    total_lines: int = 0
    malformed_lines: int = 0
    processed_entries: int = 0
    error_responses: int = 0
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    top_error_ips: list[IpErrorStat] = field(default_factory=list)
    alerts: list[AttackAlert] = field(default_factory=list)

    def attack_counts(self) -> dict[str, int]:
        counts = Counter(alert.attack_type for alert in self.alerts)
        return {name: counts.get(name, 0) for name in ATTACK_SIGNATURES}

    def to_dict(self) -> dict[str, object]:
        """Структура для JSON-звіту (дати — у форматі ISO 8601)."""
        return {
            "source_file": self.source_file,
            "parameters": {
                "min_status": self.min_status,
                "top": self.top,
                "since": _iso(self.since),
                "until": _iso(self.until),
            },
            "summary": {
                "total_lines": self.total_lines,
                "malformed_lines": self.malformed_lines,
                "processed_entries": self.processed_entries,
                "error_responses": self.error_responses,
                "first_timestamp": _iso(self.first_timestamp),
                "last_timestamp": _iso(self.last_timestamp),
            },
            "top_error_ips": [
                {
                    "ip": stat.ip,
                    "errors": stat.errors,
                    "statuses": {str(c): n for c, n in sorted(stat.statuses.items())},
                }
                for stat in self.top_error_ips
            ],
            "attack_counts": self.attack_counts(),
            "attacks": [
                {
                    "type": alert.attack_type,
                    "ip": alert.ip,
                    "timestamp": alert.timestamp.isoformat(),
                    "status": alert.status,
                    "request": alert.request,
                }
                for alert in self.alerts
            ],
        }


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment is not None else None


def clean_text(text: str, limit: int) -> str:
    """Прибирає керівні символи (log injection) та обрізає занадто довгий рядок."""
    text = CONTROL_CHARS_RE.sub("?", text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# --- Розбір журналу ----------------------------------------------------------
def parse_line(line: str, line_no: int = 0) -> LogEntry | None:
    """Розбирає один рядок журналу; повертає ``None``, якщо формат некоректний."""
    match = LOG_LINE_RE.fullmatch(line.rstrip("\r\n"))
    if match is None:
        return None
    month = MONTHS.get(match["month"].capitalize())
    if month is None:
        return None
    try:
        offset = timedelta(
            hours=int(match["tz_hours"]), minutes=int(match["tz_minutes"])
        )
        if match["tz_sign"] == "-":
            offset = -offset
        timestamp = datetime(
            int(match["year"]),
            month,
            int(match["day"]),
            int(match["hour"]),
            int(match["minute"]),
            int(match["second"]),
            tzinfo=timezone(offset),
        )
    except ValueError:  # неіснуюча дата/час або некоректний пояс
        return None
    size = match["size"]
    return LogEntry(
        line_no=line_no,
        ip=match["ip"],
        timestamp=timestamp,
        method=match["method"],
        uri=match["uri"],
        protocol=match["protocol"],
        status=int(match["status"]),
        size=None if size == "-" else int(size),
    )


def read_entries(path: Path, stats: ParseStats) -> Iterator[LogEntry]:
    """Генератор: читає файл порядково (економить пам'ять на великих журналах)."""
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            stats.total_lines += 1
            entry = parse_line(line, line_no)
            if entry is None:
                stats.malformed_lines += 1
                logger.debug("Skipping malformed line %d: %.80r", line_no, line)
                continue
            yield entry


# --- Фільтрація за часом -----------------------------------------------------
def _comparable(moment: datetime, bound: datetime) -> datetime:
    """Якщо межа задана без часового поясу, порівнюємо з «настінним» часом журналу."""
    return moment.replace(tzinfo=None) if bound.tzinfo is None else moment


def in_time_range(
    moment: datetime, since: datetime | None, until: datetime | None
) -> bool:
    """Перевіряє, що ``since <= moment <= until`` (відсутня межа не обмежує)."""
    if since is not None and _comparable(moment, since) < since:
        return False
    return not (until is not None and _comparable(moment, until) > until)


# --- Сигнатури атак ----------------------------------------------------------
def decode_uri(uri: str) -> str:
    """Декодує %XX та '+' (до кількох раундів — проти подвійного кодування)."""
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote_plus(uri)
        if decoded == uri:
            break
        uri = decoded
    return uri


def detect_attacks(entry: LogEntry) -> list[str]:
    """Повертає назви атак, сигнатури яких знайдено в URI запиту."""
    candidates = {entry.uri, decode_uri(entry.uri)}
    return [
        name
        for name, patterns in ATTACK_SIGNATURES.items()
        if any(p.search(text) for p in patterns for text in candidates)
    ]


# --- Аналіз ------------------------------------------------------------------
def analyze_entries(
    entries: Iterable[LogEntry],
    *,
    source_file: str = "",
    min_status: int = DEFAULT_MIN_STATUS,
    top: int = DEFAULT_TOP,
    since: datetime | None = None,
    until: datetime | None = None,
) -> AnalysisReport:
    """Один прохід по записах: фільтр за часом, помилки за IP, пошук атак."""
    report = AnalysisReport(source_file, min_status, top, since, until)
    errors_by_ip: Counter[str] = Counter()
    statuses_by_ip: defaultdict[str, Counter[int]] = defaultdict(Counter)

    for entry in entries:
        if not in_time_range(entry.timestamp, since, until):
            continue
        report.processed_entries += 1
        stamp = entry.timestamp
        if report.first_timestamp is None or stamp < report.first_timestamp:
            report.first_timestamp = stamp
        if report.last_timestamp is None or stamp > report.last_timestamp:
            report.last_timestamp = stamp

        if min_status <= entry.status <= MAX_HTTP_STATUS:
            report.error_responses += 1
            errors_by_ip[entry.ip] += 1
            statuses_by_ip[entry.ip][entry.status] += 1

        for attack_name in detect_attacks(entry):
            report.alerts.append(
                AttackAlert(
                    attack_type=attack_name,
                    ip=entry.ip,
                    timestamp=entry.timestamp,
                    request=clean_text(entry.request, REPORT_REQUEST_LIMIT),
                    status=entry.status,
                )
            )

    report.top_error_ips = [
        IpErrorStat(ip, count, dict(statuses_by_ip[ip]))
        for ip, count in errors_by_ip.most_common(top)
    ]
    return report


# --- Консольний вивід --------------------------------------------------------
def _format_moment(moment: datetime | None) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment is not None else "-"


def print_report(report: AnalysisReport) -> None:
    """Друкує підсумок у форматі, наведеному в завданні."""
    if report.min_status == DEFAULT_MIN_STATUS:
        label = "4xx/5xx"
    else:
        label = f"status >= {report.min_status}"
    print(f"\n=== Top-{report.top} IP Addresses with Error Statuses ({label}) ===")
    if not report.top_error_ips:
        print("(no error responses found)")
    for stat in report.top_error_ips:
        noun = "error" if stat.errors == 1 else "errors"
        print(f"{stat.ip} - {stat.errors} {noun} ({stat.breakdown()})")

    print("\n=== Detected Attack Signatures ===")
    if not report.alerts:
        print("(no attack signatures detected)")
    for alert in report.alerts:
        request = clean_text(alert.request, PRINT_REQUEST_LIMIT)
        print(f'[ALERT] Potential {alert.attack_type} from {alert.ip}: "{request}"')
    if report.alerts:
        totals = ", ".join(f"{n}: {c}" for n, c in report.attack_counts().items())
        print(f"Total alerts: {len(report.alerts)} ({totals})")


# --- Збереження звіту --------------------------------------------------------
CSV_COLUMNS = (
    "section",
    "rank",
    "ip",
    "errors",
    "status_breakdown",
    "timestamp",
    "attack_type",
    "status",
    "request",
)


def _csv_safe(value: str) -> str:
    """Захист від CSV/formula injection при відкритті звіту в Excel."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def write_report(report: AnalysisReport, path: Path, report_format: str) -> None:
    """Записує звіт у JSON або CSV (створює відсутні каталоги)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if report_format == "json":
        with path.open("w", encoding="utf-8") as handle:
            json.dump(report.to_dict(), handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        return

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for rank, stat in enumerate(report.top_error_ips, start=1):
            writer.writerow(
                {
                    "section": "top_error_ip",
                    "rank": rank,
                    "ip": stat.ip,
                    "errors": stat.errors,
                    "status_breakdown": stat.breakdown(),
                }
            )
        for alert in report.alerts:
            writer.writerow(
                {
                    "section": "attack",
                    "ip": alert.ip,
                    "timestamp": alert.timestamp.isoformat(),
                    "attack_type": alert.attack_type,
                    "status": alert.status,
                    "request": _csv_safe(alert.request),
                }
            )


# --- CLI ---------------------------------------------------------------------
def status_code(value: str) -> int:
    """Тип argparse: HTTP-код у діапазоні 100-599."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}") from None
    if not MIN_HTTP_STATUS <= number <= MAX_HTTP_STATUS:
        raise argparse.ArgumentTypeError(
            f"status must be between {MIN_HTTP_STATUS} and {MAX_HTTP_STATUS}"
        )
    return number


def positive_int(value: str) -> int:
    """Тип argparse: ціле число більше нуля."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}") from None
    if number < 1:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return number


def datetime_arg(value: str) -> datetime:
    """Тип argparse: ``YYYY-MM-DD[ HH:MM[:SS]]``, за потреби з поясом ``+03:00``."""
    try:
        return datetime.fromisoformat(value.strip())
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid date/time {value!r}; expected YYYY-MM-DD[ HH:MM[:SS]]"
        ) from None


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Додає параметри команди ``analyze`` (викликається з main.py)."""
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help="шлях до access.log (типово: labs/lab02/data/data_v01/access.log)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="шлях до звіту (типово: web_analysis_report.<format> поруч із журналом)",
    )
    parser.add_argument(
        "--min-status",
        type=status_code,
        default=DEFAULT_MIN_STATUS,
        help=f"мін. код відповіді-помилки (типово: {DEFAULT_MIN_STATUS})",
    )
    parser.add_argument(
        "--top",
        type=positive_int,
        default=DEFAULT_TOP,
        help=f"скільки IP-адрес показати у топі (типово: {DEFAULT_TOP})",
    )
    parser.add_argument(
        "--format",
        dest="report_format",
        choices=REPORT_FORMATS,
        default=None,
        help="формат звіту (типово: за розширенням --output, інакше json)",
    )
    parser.add_argument(
        "--since",
        type=datetime_arg,
        default=None,
        help="лише запити не раніше цього часу, напр. '2026-09-27 08:00:00'",
    )
    parser.add_argument(
        "--until",
        type=datetime_arg,
        default=None,
        help="лише запити не пізніше цього часу (включно)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="детальне логування (DEBUG), зокрема про пропущені рядки",
    )


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
        stream=sys.stderr,
        force=True,
    )


def resolve_format(output: Path | None, requested: str | None) -> str:
    if requested is not None:
        return requested
    if output is not None and output.suffix.lower() == ".csv":
        return "csv"
    return "json"


def _ranges_conflict(since: datetime | None, until: datetime | None) -> bool:
    if since is None or until is None:
        return False
    if (since.tzinfo is None) != (until.tzinfo is None):
        return False  # різні типи (naive/aware) порівнювати не можна
    return since > until


def run(args: argparse.Namespace) -> int:
    """Виконує аналіз журналу; повертає код завершення процесу."""
    configure_logging(args.verbose)
    log_file: Path = args.log_file

    if _ranges_conflict(args.since, args.until):
        logger.error("--since must not be later than --until")
        return EXIT_ERROR
    if not log_file.is_file():
        logger.error("Log file not found: %s", log_file)
        return EXIT_ERROR

    report_format = resolve_format(args.output, args.report_format)
    output = args.output or log_file.parent / f"web_analysis_report.{report_format}"

    logger.info("Loading access log from %s...", log_file)
    stats = ParseStats()
    try:
        report = analyze_entries(
            read_entries(log_file, stats),
            source_file=str(log_file),
            min_status=args.min_status,
            top=args.top,
            since=args.since,
            until=args.until,
        )
    except OSError as exc:
        logger.error("Cannot read %s: %s", log_file, exc)
        return EXIT_ERROR

    report.total_lines = stats.total_lines
    report.malformed_lines = stats.malformed_lines
    if stats.malformed_lines:
        logger.warning(
            "Skipped %d malformed line(s) out of %d (use --verbose for details)",
            stats.malformed_lines,
            stats.total_lines,
        )
    if report.processed_entries == 0:
        logger.warning("No log entries to analyze (empty file or filter too strict)")
    else:
        logger.info(
            "Processed %d log entries from %s to %s.",
            report.processed_entries,
            _format_moment(report.first_timestamp),
            _format_moment(report.last_timestamp),
        )

    print_report(report)

    try:
        write_report(report, output, report_format)
    except OSError as exc:
        logger.error("Cannot write report to %s: %s", output, exc)
        return EXIT_ERROR
    logger.info("Analysis report saved to %s", output)
    return EXIT_OK
