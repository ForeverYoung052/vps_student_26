import re
import socket
import hashlib
from typing import Optional

def extract_ip(log_line: str) -> Optional[str]:
   # Ищет IP-адрес в строке лога, сигнализирующей о неудачной попытке входа по SSH.
    if "Failed password" in log_line:
        match = re.search(
            r"from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            log_line
        )

        if match:
            return match.group(1)

    return None

def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    # Подсчитывает число неудачных попыток входа для каждого IP.
    attacks: dict[str, int] = {}

    for line in log_lines:
        ip = extract_ip(line)

        if ip:
            attacks[ip] = attacks.get(ip, 0) + 1

    return attacks

def detect_brute_force(ip_counts: dict[str, int], threshold: int = 5) -> list[str]:
    # Выявляет IP-адреса с количеством попыток больше или равно threshold.
    alerts: list[str] = []

    for ip, count in ip_counts.items():
        if count >= threshold:
            alerts.append(ip)

    return alerts

def detect_suspicious_paths(log_line: str) -> bool:
    # Проверяет строку лога на известные сигнатуры веб-атак.
    signatures = [
        "/etc/passwd",
        ".env",
        "wp-admin",
        "select+union",
        "union+select",
        "shell.php"
    ]

    log_line = log_line.lower()

    for signature in signatures:
        if signature in log_line:
            return True

    return False

def calculate_risk_score(brute_force_alerts: int, web_alerts: int) -> str:
    # Вычисляет общий уровень риска.
    risk_score = brute_force_alerts * 3 + web_alerts

    if risk_score == 0:
        return "LOW"

    if risk_score < 5:
        return "MEDIUM"

    return "HIGH"

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    #  Проверяет доступность TCP-порта.
    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(timeout)

        result = sock.connect_ex((ip, port))

        sock.close()

        return result == 0

    except (socket.timeout, socket.error, OSError):
        return False

def get_file_hash(filepath: str) -> str:
   # Вычисляет SHA-256 хеш файла.
    sha256_hash = hashlib.sha256()

    try:
        with open(filepath, "rb") as file:
            while True:
                block = file.read(4096)

                if not block:
                    break

                sha256_hash.update(block)

        return sha256_hash.hexdigest()

    except FileNotFoundError:
        return "FILE_NOT_FOUND"