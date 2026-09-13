import unittest
import sys
import os

# Добавляем текущую директорию в пути импорта Python
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import vps_soc_analyzer as analyzer

class TestVPSSOCAnalyzer(unittest.TestCase):
    
    def test_extract_ip_valid_failed_password(self):
        """Тест успешного извлечения IP из строки неудачной аутентификации SSH"""
        line = "Sep 02 12:00:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.55 port 43210 ssh2"
        ip = analyzer.extract_ip(line)
        self.assertEqual(ip, "192.168.1.55")

    def test_extract_ip_accepted_password(self):
        """Тест: IP не должен извлекаться, если вход успешный"""
        line = "Sep 02 12:01:00 server sshd[1234]: Accepted password for admin from 192.168.1.55 port 43210 ssh2"
        ip = analyzer.extract_ip(line)
        self.assertIsNone(ip)

    def test_group_by_ip_aggregation(self):
        """Тест корректности подсчета попыток входов по каждому IP"""
        logs = [
            "Failed password for user root from 1.1.1.1 port 22",
            "Failed password for user admin from 1.1.1.1 port 22",
            "Failed password for user guest from 2.2.2.2 port 22",
            "Accepted password for root from 1.1.1.1 port 22" # Успешный вход, должен игнорироваться
        ]
        counts = analyzer.group_by_ip(logs)
        expected = {"1.1.1.1": 2, "2.2.2.2": 1}
        self.assertEqual(counts, expected)

    def test_detect_brute_force_below_threshold(self):
        """Тест: брутфорс не должен детектироваться, если попыток меньше лимита"""
        counts = {"1.1.1.1": 4, "2.2.2.2": 2}
        alerts = analyzer.detect_brute_force(counts, threshold=5)
        self.assertEqual(alerts, [])

    def test_detect_brute_force_above_threshold(self):
        """Тест: брутфорс должен детектироваться при превышении лимита"""
        counts = {"1.1.1.1": 6, "2.2.2.2": 2}
        alerts = analyzer.detect_brute_force(counts, threshold=5)
        self.assertEqual(alerts, ["1.1.1.1"])

    def test_detect_suspicious_paths_positive(self):
        """Тест обнаружения опасных путей в веб-запросах"""
        line1 = '1.1.1.1 - - [02/Sep/2026:12:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 150'
        line2 = '1.1.1.1 - - [02/Sep/2026:12:01:00 +0000] "GET /.env HTTP/1.1" 404 150'
        self.assertTrue(analyzer.detect_suspicious_paths(line1))
        self.assertTrue(analyzer.detect_suspicious_paths(line2))

    def test_detect_suspicious_paths_negative(self):
        """Тест: обычные пути веб-запросов не должны детектироваться как опасные"""
        line = '1.1.1.1 - - [02/Sep/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 4500'
        self.assertFalse(analyzer.detect_suspicious_paths(line))

    def test_calculate_risk_score_low(self):
        """Тест: нулевая активность -> низкий риск"""
        self.assertEqual(analyzer.calculate_risk_score(0, 0), "LOW")

    def test_calculate_risk_score_medium(self):
        """Тест: единичные угрозы -> средний риск"""
        self.assertEqual(analyzer.calculate_risk_score(1, 1), "MEDIUM") # 1*3 + 1 = 4 < 5

    def test_calculate_risk_score_high(self):
        """Тест: критическая нагрузка -> высокий риск"""
        self.assertEqual(analyzer.calculate_risk_score(2, 0), "HIGH") # 2*3 = 6 >= 5

if __name__ == "__main__":
    unittest.main()
