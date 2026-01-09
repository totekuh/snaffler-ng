"""
Logging utilities for Snaffler Linux
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class DataOnlyFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return getattr(record, "is_data", False)


# Color codes for console output
class Colors:
    BLACK = '\033[90m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    GRAY = '\033[37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def _logger_has_file_handler(logger: logging.Logger) -> bool:
    return any(isinstance(h, logging.FileHandler) for h in logger.handlers)


class SnafflerFormatter(logging.Formatter):
    """Custom formatter for Snaffler output"""

    LEVEL_COLORS = {
        'DEBUG': Colors.GRAY,
        'INFO': Colors.GREEN,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.RED + Colors.BOLD,
    }

    def __init__(self, logger: logging.Logger):
        super().__init__()
        self.logger = logger

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created).strftime(
            '%Y-%m-%d %H:%M:%S'
        )
        level = record.levelname
        message = record.getMessage()

        use_colors = (
                sys.stdout.isatty()
                and not _logger_has_file_handler(self.logger)
        )

        if use_colors:
            color = self.LEVEL_COLORS.get(level, '')
            return (
                f"{Colors.GRAY}[{timestamp}]{Colors.RESET} "
                f"{color}[{level}]{Colors.RESET} {message}"
            )
        else:
            return f"[{timestamp}] [{level}] {message}"



class SnafflerJSONFormatter(logging.Formatter):
    """JSON formatter for file output"""

    def format(self, record):
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
        }

        if hasattr(record, 'file_path'):
            log_data['file_path'] = record.file_path
        if hasattr(record, 'triage'):
            log_data['triage'] = record.triage
        if hasattr(record, 'rule_name'):
            log_data['rule_name'] = record.rule_name
        if hasattr(record, 'match_context'):
            log_data['match_context'] = record.match_context

        return json.dumps(log_data)


def setup_logging(
        log_level: str = "info",
        log_to_file: bool = False,
        log_file_path: Optional[str] = None,
        log_to_console: bool = True,
        log_type: str = "plain",
) -> logging.Logger:

    level_map = {
        'trace': logging.DEBUG,
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'data': logging.WARNING,
    }

    level = level_map.get(log_level.lower(), logging.INFO)

    logger = logging.getLogger('snaffler')
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # ---------- console ----------
    if log_to_console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(level)
        ch.setFormatter(SnafflerFormatter(logger))
        logger.addHandler(ch)

    # ---------- file ----------
    if log_to_file and log_file_path:
        log_path = Path(log_file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        fh = logging.FileHandler(log_file_path, mode='a')

        if log_level == "data":
            fh.setLevel(logging.DEBUG)
            fh.addFilter(DataOnlyFilter())
        else:
            fh.setLevel(level)

        if log_type == "json":
            fh.setFormatter(SnafflerJSONFormatter())
        else:
            fh.setFormatter(SnafflerFormatter(logger))

        logger.addHandler(fh)

    return logger


def log_file_result(
        logger: logging.Logger,
        file_path: str,
        triage: str,
        rule_name: str,
        match: str = None,
        context: str = None,
        size: int = None,
        modified: str = None,
):
    triage_colors = {
        'Black': Colors.BLACK + Colors.BOLD,
        'Red': Colors.RED + Colors.BOLD,
        'Yellow': Colors.YELLOW + Colors.BOLD,
        'Green': Colors.GREEN,
        'Gray': Colors.GRAY,
    }

    use_colors = (
            sys.stdout.isatty()
            and not _logger_has_file_handler(logger)
    )

    color = triage_colors.get(triage, '') if use_colors else ''
    reset = Colors.RESET if use_colors else ''
    bold = Colors.BOLD if use_colors else ''

    parts = [f"{color}[{triage}]{reset}", f"[{rule_name}]"]

    if size:
        parts.append(f"[{format_size(size)}]")
    if modified:
        parts.append(f"[mtime:{modified}]")

    parts.append(f"{bold}{file_path}{reset}")

    if match:
        parts.append(f"Match: {match}")
    if context:
        parts.append(f"Context: {context[:200]}...")

    is_json = any(
        isinstance(h.formatter, SnafflerJSONFormatter)
        for h in logger.handlers
    )

    message = "file_match" if is_json else " ".join(parts)


    extra = {
        'file_path': file_path,
        'triage': triage,
        'rule_name': rule_name,
        'is_data': True,
    }

    if match:
        extra['match'] = match
    if context:
        extra['match_context'] = context

    logger.warning(message, extra=extra)


def print_completion_stats(start_time):
    if not start_time:
        return

    logger = logging.getLogger('snaffler')
    end_time = datetime.now()
    duration = end_time - start_time

    total_seconds = int(duration.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    logger.info("-" * 60)
    logger.info(f"Started:  {start_time:%Y-%m-%d %H:%M:%S}")
    logger.info(f"Finished: {end_time:%Y-%m-%d %H:%M:%S}")

    if hours > 0:
        logger.info(f"Duration: {hours}h {minutes}m {seconds}s")
    elif minutes > 0:
        logger.info(f"Duration: {minutes}m {seconds}s")
    else:
        logger.info(f"Duration: {seconds}s")

    logger.info("-" * 60)


def format_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f}PB"
