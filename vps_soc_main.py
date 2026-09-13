import os
import sys

# Добавляем текущую директорию в пути импорта Python
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Импортируем симулятор генерации логов
try:
    from vps_log_generator import generate_mock_ssh_logs, generate_mock_nginx_logs
except ImportError:
    print("[!] Не найден файл vps_log_generator.py. Убедитесь, что он лежит в той же папке!")
    sys.exit(1)

# Импортируем студенческий модуль аналитики
try:
    import vps_soc_analyzer as analyzer
except ImportError:
    print("[!] Не найден файл vps_soc_analyzer.py. Переименуйте шаблон или создайте его!")
    sys.exit(1)

def run_pipeline():
    print("=" * 60)
    print("ЗАПУСК КОНВЕЙЕРА (PIPELINE) МИНИ-SOC НА VPS (СТУДЕНЧЕСКИЙ ШАБЛОН)")
    print("=" * 60)

    # Шаг 1: Симуляция/Генерация данных на сервере (Уже реализовано)
    print("[1] Симуляция: Создаем искусственные логи на сервере...")
    mock_ssh_lines = generate_mock_ssh_logs(num_lines=100)
    mock_nginx_lines = generate_mock_nginx_logs(num_lines=50)
    
    ssh_log_path = "mock_auth.log"
    nginx_log_path = "mock_nginx_access.log"
    
    with open(ssh_log_path, "w") as f:
        f.writelines([line + "\n" for line in mock_ssh_lines])
    with open(nginx_log_path, "w") as f:
        f.writelines([line + "\n" for line in mock_nginx_lines])
        
    print(f"    - Сгенерировано строк SSH: {len(mock_ssh_lines)} (сохранено в {ssh_log_path})")
    print(f"    - Сгенерировано строк Nginx: {len(mock_nginx_lines)} (сохранено в {nginx_log_path})")
    print("-" * 60)

    # Шаг 2: Анализ логов SSH (Брутфорс)
    print("[2] Анализ SSH логов:")
    with open(ssh_log_path, "r") as f:
        ssh_logs = f.readlines()
        
    # TODO: Вызовите функцию группировки по IP из модуля analyzer
    # ip_attempts = ...
    ip_attempts = {} # Заглушка
    
    print(f"    - Всего уникальных IP, совершивших неудачный вход: {len(ip_attempts)}")
    for ip, count in sorted(ip_attempts.items(), key=lambda x: x[1], reverse=True)[:3]:
        print(f"      * IP: {ip} - {count} неудачных попыток")
        
    # TODO: Вызовите функцию детектора брутфорса
    # bf_alerts = ...
    bf_alerts = [] # Заглушка
    
    print(f"    - ОБНАРУЖЕНО БРУТФОРС-АТАК (>= 5 попыток): {len(bf_alerts)}")
    for ip in bf_alerts:
        print(f"      [ALERT] IP {ip} превысил порог и заблокирован в SOC!")
    print("-" * 60)

    # Шаг 3: Анализ веб-логов (Nginx)
    print("[3] Анализ веб-логов (Nginx):")
    with open(nginx_log_path, "r") as f:
        nginx_logs = f.readlines()
        
    web_alerts_count = 0
    print("    - Подозрительные веб-запросы:")
    for line in nginx_logs:
        # TODO: Проверьте строку на наличие веб-атак с помощью функции из analyzer
        # is_suspicious = ...
        is_suspicious = False # Заглушка
        
        if is_suspicious:
            web_alerts_count += 1
            parts = line.split('"')
            request = parts[1] if len(parts) > 1 else line.strip()
            ip = line.split()[0]
            print(f"      [ALERT] {ip} запросил опасный путь: '{request}'")
            
    print(f"    - Всего зафиксировано подозрительных веб-запросов: {web_alerts_count}")
    print("-" * 60)

    # Шаг 4: Расчет риска для VPS
    print("[4] Оценка уровня угрозы VPS (Risk Scoring):")
    # TODO: Рассчитайте уровень риска с помощью функции из analyzer
    # risk = ...
    risk = "NOT_IMPLEMENTED" # Заглушка
    
    print(f"    - УРОВЕНЬ РИСКА ДЛЯ VPS: **{risk}**")
    print("-" * 60)

    # Шаг 5: Проверка целостности файлов на VPS
    print("[5] Контроль целостности файлов на VPS:")
    dummy_config = "vps_secure_config.conf"
    
    with open(dummy_config, "w") as f:
        f.write("PermitRootLogin no\nPasswordAuthentication no\n")
    
    # TODO: Рассчитайте хеш-сумму исходного файла с помощью функции из analyzer
    # hash_original = ...
    hash_original = "None" # Заглушка
    print(f"    - Хеш-сумма файла {dummy_config} (SHA-256): {hash_original}")
    
    # Симулируем несанкционированное изменение (взлом)
    with open(dummy_config, "a") as f:
        f.write("PermitRootLogin yes # ХАКЕР ИЗМЕНИЛ НАСТРОЙКУ!\n")
        
    # TODO: Рассчитайте хеш-сумму измененного файла
    # hash_modified = ...
    hash_modified = "None" # Заглушка
    print(f"    - Хеш-сумма после изменения: {hash_modified}")
    
    if hash_original != hash_modified:
        print("    - [!] ВНИМАНИЕ: Целостность конфигурационного файла НАРУШЕНА!")
    else:
        print("    - [OK] Файл конфигурации не изменен.")
    print("-" * 60)

    # Шаг 6: Проверка доступности портов на VPS (Тестируем локально)
    print("[6] Сетевая разведка (Тестовый сканер портов):")
    ports_to_scan = [22, 80, 443, 8080]
    print(f"    - Сканируем порты на localhost (127.0.0.1): {ports_to_scan}")
    for port in ports_to_scan:
        # TODO: Проверьте статус порта с помощью функции из analyzer
        # is_open = ...
        is_open = False # Заглушка
        
        status = "ОТКРЫТ" if is_open else "ЗАКРЫТ"
        print(f"      * Порт {port}: {status}")
    print("-" * 60)

    # Очистка временных файлов (Уже реализовано)
    for file in [ssh_log_path, nginx_log_path, dummy_config]:
        if os.path.exists(file):
            os.remove(file)
            
    print("КОНВЕЙЕР ЗАВЕРШИЛ РАБОТУ.")
    print("=" * 60)

if __name__ == "__main__":
    run_pipeline()
