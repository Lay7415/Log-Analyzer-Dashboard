import random
import time
from datetime import datetime, timezone, timedelta
from faker import Faker

fake = Faker()

# --- Пути к файлам ---
ACCESS_LOG_FILE_PATH = "./nginx/logs/access.log"
ERROR_LOG_FILE_PATH = "./nginx/logs/error.log"
NUM_LOG_LINES = 10000
NUM_ERROR_LINES = 150

print("Подготовка пулов реалистичных данных для access.log...")

IP_POOL = [fake.ipv4() for _ in range(200)]
ip_weights = ([0.04] * 10) + ([0.00315] * 190)

pages = [
    "/", "/products/123", "/api/v1/users", "/cart", "/login",
    "/products/456", "/checkout", "/blog/article-1", "/contact-us", "/api/v2/items",
    "/admin/panel", "/static/style.css", "/images/logo.png", "/uploads/document.pdf"
]
page_weights = [0.25, 0.15, 0.10, 0.10, 0.08, 0.08, 0.05, 0.04, 0.04, 0.03, 0.01, 0.01, 0.01, 0.01]

USER_AGENT_POOL = [fake.user_agent() for _ in range(100)]
http_statuses = [200, 301, 404, 500, 403]
status_weights = [0.8, 0.05, 0.08, 0.02, 0.05]

print("Настройка временного диапазона для логов...")
end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(hours=3)
peak_time_start = end_time - timedelta(hours=2)
peak_time_end = end_time - timedelta(hours=1)

def get_random_timestamp():
    """Возвращает случайную временную метку, с большей вероятностью в 'часы пик'."""
    if random.random() < 0.7:
        ts = random.uniform(peak_time_start.timestamp(), peak_time_end.timestamp())
    else:
        ts = random.uniform(start_time.timestamp(), end_time.timestamp())
    return datetime.fromtimestamp(ts, tz=timezone.utc)

print(f"Генерация {NUM_LOG_LINES} строк логов в файл {ACCESS_LOG_FILE_PATH}...")
print(f"Временной диапазон: от {start_time.strftime('%H:%M:%S')} до {end_time.strftime('%H:%M:%S')}")

with open(ACCESS_LOG_FILE_PATH, "w") as f:
    log_entries = []
    for _ in range(NUM_LOG_LINES):
        log_time = get_random_timestamp()
        timestamp_str = log_time.strftime('%d/%b/%Y:%H:%M:%S %z')
        
        ip = random.choices(IP_POOL, weights=ip_weights, k=1)[0]
        page = random.choices(pages, weights=page_weights, k=1)[0]
        user_agent = random.choice(USER_AGENT_POOL)
        method = random.choice(["GET", "POST"])
        protocol = "HTTP/1.1"
        request = f"{method} {page} {protocol}"
        status = random.choices(http_statuses, weights=status_weights, k=1)[0]
        bytes_sent = random.randint(100, 15000)
        referrer = fake.uri()

        log_line = f'{ip} - - [{timestamp_str}] "{request}" {status} {bytes_sent} "{referrer}" "{user_agent}"\n'
        log_entries.append((log_time, log_line))
    
    log_entries.sort(key=lambda x: x[0])
    
    for _, log_line in log_entries:
        f.write(log_line)

    print("Генерация аномальной активности (DDoS-симуляция)...")
    anomaly_ip = "1.2.3.4"
    for i in range(200):
        attack_time = end_time - timedelta(seconds=random.randint(1, 60))
        timestamp_str = attack_time.strftime('%d/%b/%Y:%H:%M:%S %z')
        request = "GET /login HTTP/1.1" # Атакуем страницу логина
        log_line = f'{anomaly_ip} - - [{timestamp_str}] "{request}" 403 150 "{fake.uri()}" "{random.choice(USER_AGENT_POOL)}"\n'
        f.write(log_line)

print(f"Генерация {NUM_ERROR_LINES} строк логов в файл {ERROR_LOG_FILE_PATH}...")
error_levels = ["error", "warn"]
error_messages = [
    'open() "/usr/share/nginx/html/favicon.ico" failed (2: No such file or directory)',
    'directory index of "/usr/share/nginx/html/images/" is forbidden',
    'access forbidden by rule',
    'client sent invalid method while reading client request line'
]

with open(ERROR_LOG_FILE_PATH, "w") as f:
    error_entries = []
    for _ in range(NUM_ERROR_LINES):
        log_time = get_random_timestamp()
        timestamp_str = log_time.strftime('%Y/%m/%d %H:%M:%S')
        level = random.choice(error_levels)
        message = random.choice(error_messages)
        ip = random.choice(IP_POOL)
        
        log_line = f'{timestamp_str} [{level}] 12345#12345: *6789 client: {ip}, server: localhost, request: "GET /some/problematic/path HTTP/1.1", {message}, host: "localhost:8080"\n'
        error_entries.append((log_time, log_line))

    error_entries.sort(key=lambda x: x[0])
    for _, log_line in error_entries:
        f.write(log_line)
print("Генерация error.log завершена.")