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
start_time = end_time - timedelta(hours=6)
peak_time_start = end_time - timedelta(hours=3)
peak_time_end = end_time - timedelta(hours=1)

def get_random_timestamp():
    if random.random() < 0.7:
        ts = random.uniform(peak_time_start.timestamp(), peak_time_end.timestamp())
    else:
        ts = random.uniform(start_time.timestamp(), end_time.timestamp())
    return datetime.fromtimestamp(ts, tz=timezone.utc)

print(f"Генерация {NUM_LOG_LINES} строк логов в файл {ACCESS_LOG_FILE_PATH}...")

with open(ACCESS_LOG_FILE_PATH, "w") as f:
    log_entries = []
    for _ in range(NUM_LOG_LINES):
        log_time = get_random_timestamp()
        timestamp_str = log_time.strftime('%d/%b/%Y:%H:%M:%S %z')
        ip = random.choices(IP_POOL, weights=ip_weights, k=1)[0]
        page = random.choices(pages, weights=page_weights, k=1)[0]
        user_agent = random.choice(USER_AGENT_POOL)
        method = random.choice(["GET", "POST"])
        request = f"{method} {page} HTTP/1.1"
        status = random.choices(http_statuses, weights=status_weights, k=1)[0]
        bytes_sent = random.randint(100, 15000)
        referrer = fake.uri()
        log_line = f'{ip} - - [{timestamp_str}] "{request}" {status} {bytes_sent} "{referrer}" "{user_agent}"\n'
        log_entries.append((log_time, log_line))
    
    log_entries.sort(key=lambda x: x[0])
    for _, log_line in log_entries:
        f.write(log_line)

    # --- БЛОК ГЕНЕРАЦИИ АНОМАЛИЙ ---
    
    # Определение словаря payloads с различными типами атак
    payloads = {
        "1.2.3.4": ["/some/path", "/admin", "/login", "/api/v1/users"],  # Request Rate Anomaly paths
        "5.6.7.8": ["' OR '1'='1", "admin' --", "' UNION SELECT * FROM users --"],  # SQL Injection attempts
        "9.10.11.12": ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"]  # XSS attempts
    }
    
    def generate_attack(ip, request_template, count, status_code, message):
        print(message)
        for _ in range(count):
            attack_time = end_time - timedelta(seconds=random.randint(1, 180))
            timestamp_str = attack_time.strftime('%d/%b/%Y:%H:%M:%S %z')
            page = request_template.format(payload=random.choice(payloads.get(ip, [""])))
            request = f"GET {page} HTTP/1.1"
            f.write(f'{ip} - - [{timestamp_str}] "{request}" {status_code} {random.randint(200, 1500)} "{fake.uri()}" "{random.choice(USER_AGENT_POOL)}"\n')

    # 1. Request Rate Anomaly
    generate_attack("1.2.3.4", "/some/path", 200, 403, "Генерация аномальной активности (Request Rate Anomaly)...")

    # 2. Login Attack (Brute-force)
    print("Генерация аномальной активности (Login Attack)...")
    login_attack_ip = "10.20.30.40"
    for _ in range(50):
        attack_time = end_time - timedelta(seconds=random.randint(1, 120))
        timestamp_str = attack_time.strftime('%d/%b/%Y:%H:%M:%S %z')
        f.write(f'{login_attack_ip} - - [{timestamp_str}] "POST /login HTTP/1.1" 401 500 "{fake.uri()}" "{random.choice(USER_AGENT_POOL)}"\n')

    # 3. Scanning Activity (поиск уникальных страниц)
    print("Генерация аномальной активности (Scanning Activity)...")
    scanner_ip = "50.60.70.80"
    for page in {fake.uri_path() for _ in range(30)}:
        attack_time = end_time - timedelta(seconds=random.randint(1, 180))
        timestamp_str = attack_time.strftime('%d/%b/%Y:%H:%M:%S %z')
        f.write(f'{scanner_ip} - - [{timestamp_str}] "GET {page} HTTP/1.1" 404 350 "{fake.uri()}" "{random.choice(USER_AGENT_POOL)}"\n')
        
    # 4. НОВИНКА: SQL Injection
    sqli_ip = "11.22.33.44"
    sql_payloads = ["' OR 1=1--", " UNION SELECT user, password FROM users--", " 1' AND '1'='1"]
    payloads = {sqli_ip: sql_payloads}
    generate_attack(sqli_ip, "/products?id={payload}", 20, 500, "Генерация аномальной активности (SQL Injection)...")

    # 5. НОВИНКА: Path Traversal
    path_ip = "55.66.77.88"
    path_payloads = ["../../../../etc/passwd", "../../../../../windows/system.ini"]
    payloads[path_ip] = path_payloads
    generate_attack(path_ip, "/static/{payload}", 15, 403, "Генерация аномальной активности (Path Traversal)...")

    # 6. НОВИНКА: Vulnerability Scanning (поиск известных уязвимостей)
    vuln_scanner_ip = "99.88.77.66"
    vuln_paths = ["/wp-admin/", "/phpmyadmin/", "/.git/config", "/solr/admin/"]
    payloads[vuln_scanner_ip] = vuln_paths
    generate_attack(vuln_scanner_ip, "{payload}", len(vuln_paths) * 2, 404, "Генерация аномальной активности (Vulnerability Scanning)...")

    # 7. НОВИНКА: Bad User-Agent
    print("Генерация аномальной активности (Bad User-Agent)...")
    bad_bot_ip = "44.55.66.77"
    bad_user_agents = ["sqlmap", "Nikto", "Nmap Scripts", "masscan"]
    for agent in bad_user_agents:
        attack_time = end_time - timedelta(seconds=random.randint(1, 180))
        timestamp_str = attack_time.strftime('%d/%b/%Y:%H:%M:%S %z')
        f.write(f'{bad_bot_ip} - - [{timestamp_str}] "GET / HTTP/1.1" 200 1200 "{fake.uri()}" "{agent}"\n')


print(f"Генерация {NUM_ERROR_LINES} строк логов в файл {ERROR_LOG_FILE_PATH}...")
with open(ERROR_LOG_FILE_PATH, "w") as f:
    error_entries = []
    for _ in range(NUM_ERROR_LINES):
        log_time = get_random_timestamp()
        timestamp_str = log_time.strftime('%Y/%m/%d %H:%M:%S')
        level = random.choice(["error", "warn"])
        message = random.choice([
            'open() "/usr/share/nginx/html/favicon.ico" failed (2: No such file or directory)',
            'directory index of "/usr/share/nginx/html/images/" is forbidden',
            'access forbidden by rule',
            'client sent invalid method while reading client request line'
        ])
        ip = random.choice(IP_POOL)
        log_line = f'{timestamp_str} [{level}] 12345#12345: *6789 client: {ip}, server: localhost, request: "GET /some/problematic/path HTTP/1.1", {message}, host: "localhost:8080"\n'
        error_entries.append((log_time, log_line))
    error_entries.sort(key=lambda x: x[0])
    for _, log_line in error_entries:
        f.write(log_line)
print("Генерация error.log завершена.")