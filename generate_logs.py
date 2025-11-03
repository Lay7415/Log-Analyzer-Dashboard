import random
import time
from datetime import datetime, timezone, timedelta
from faker import Faker
import os

fake = Faker()

ACCESS_LOG_FILE_PATH = "/var/log/nginx/access.log" 
ERROR_LOG_FILE_PATH = "/var/log/nginx/error.log"
LOG_INTERVAL = 1 

LOG_DIR = os.path.dirname(ACCESS_LOG_FILE_PATH)
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)
    print(f"Директория {LOG_DIR} создана.")

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

current_time = datetime.now(timezone.utc)
end_time = current_time
start_time = end_time - timedelta(hours=6)
peak_time_start = end_time - timedelta(hours=3)
peak_time_end = end_time - timedelta(hours=1)

payloads = {
    "1.2.3.4": ["/some/path", "/admin", "/login", "/api/v1/users"],
    "5.6.7.8": ["' OR '1'='1", "admin' --", "' UNION SELECT * FROM users --"],
    "9.10.11.12": ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"],
    "11.22.33.44": ["' OR 1=1--", " UNION SELECT user, password FROM users--", " 1' AND '1'='1"],
    "55.66.77.88": ["../../../../etc/passwd", "../../../../../windows/system.ini"],
    "99.88.77.66": ["/wp-admin/", "/phpmyadmin/", "/.git/config", "/solr/admin/"],
}

def generate_attack_log(ip, request_template, status_code, is_anomaly=1, anomaly_type=""):
    log_time = datetime.now(timezone.utc) - timedelta(seconds=random.randint(1, 10)) # Генерируем немного в прошлом
    timestamp_str = log_time.strftime('%d/%b/%Y:%H:%M:%S %z')
    
    if ip in payloads and anomaly_type in ["SQL Injection", "Path Traversal", "Vulnerability Scanning"]:
        payload = random.choice(payloads.get(ip, [""]))
        page = request_template.format(payload=payload)
    else:
        page = request_template 
    
    method = random.choice(["GET", "POST"]) if not anomaly_type else ("GET" if "Scanning" in anomaly_type or "Traversal" in anomaly_type else "POST")
    request = f"{method} {page} HTTP/1.1"
    bytes_sent = random.randint(200, 15000)
    referrer = fake.uri()
    user_agent = random.choice(USER_AGENT_POOL)
    
    if anomaly_type == "Login Attack":
        request = "POST /login HTTP/1.1"
        status_code = 401
        bytes_sent = 500

    log_line = f'{ip} - - [{timestamp_str}] "{request}" {status_code} {bytes_sent} "{referrer}" "{user_agent}"\n'
    
    with open(ACCESS_LOG_FILE_PATH, "a") as f:
        f.write(log_line)

print(f"Генерация логов в {ACCESS_LOG_FILE_PATH} с интервалом {LOG_INTERVAL} сек...")

try:
    with open(ACCESS_LOG_FILE_PATH, "w") as f:
        f.write("") 
    with open(ERROR_LOG_FILE_PATH, "w") as f:
        f.write("") 
except Exception as e:
    print(f"Ошибка при инициализации файлов логов: {e}")


next_attack_time = time.time() + random.randint(5, 20)
next_login_time = time.time() + random.randint(10, 30)
next_scan_time = time.time() + random.randint(15, 40)
next_error_time = time.time() + random.uniform(0.5, 1.5)

while True:
    start_loop_time = time.time()
    current_ts = time.time()
    
    log_time = datetime.now(timezone.utc)
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
    
    with open(ACCESS_LOG_FILE_PATH, "a") as f: 
        f.write(log_line)
        
    if current_ts > next_attack_time:
        print("Injecting: Request Rate Anomaly")
        for _ in range(random.randint(5, 10)): 
             generate_attack_log("1.2.3.4", "/some/path", 403, 1, "Request Rate Anomaly")
        next_attack_time = current_ts + random.randint(10, 30)
        
    if current_ts > next_login_time:
        print("Injecting: Login Attack")
        for _ in range(20):
             generate_attack_log("10.20.30.40", "/login", 401, 1, "Login Attack")
        next_login_time = current_ts + random.randint(30, 60)
        
    if current_ts > next_scan_time:
        print("Injecting: Scanning Activity")
        for page in {fake.uri_path() for _ in range(random.randint(10, 20))}:
            generate_attack_log(f"50.60.70.{random.randint(1, 254)}", f"{page}", 404, 1, "Scanning Activity")
        next_scan_time = current_ts + random.randint(40, 90)

    if random.random() < 0.05: 
        generate_attack_log("11.22.33.44", "/products?id={payload}", 500, 1, "SQL Injection")
        
    if random.random() < 0.03: 
        generate_attack_log("55.66.77.88", "/static/{payload}", 403, 1, "Path Traversal")

    if random.random() < 0.02: 
        generate_attack_log("99.88.77.66", "{payload}", 404, 1, "Vulnerability Scanning")
        
    if random.random() < 0.01: 
        user_agent = random.choice(["sqlmap", "Nikto", "Nmap Scripts"])
        log_time_ua = datetime.now(timezone.utc) - timedelta(seconds=random.randint(1, 5))
        timestamp_str_ua = log_time_ua.strftime('%d/%b/%Y:%H:%M:%S %z')
        with open(ACCESS_LOG_FILE_PATH, "a") as f:
            f.write(f'44.55.66.77 - - [{timestamp_str_ua}] "GET / HTTP/1.1" 200 1200 "{fake.uri()}" "{user_agent}"\n')


    if current_ts > next_error_time:
        log_time_err = datetime.now(timezone.utc) - timedelta(seconds=random.randint(1, 3))
        timestamp_str_err = log_time_err.strftime('%Y/%m/%d %H:%M:%S')
        level = random.choice(["error", "warn"])
        message = random.choice([
            'open() "/usr/share/nginx/html/favicon.ico" failed (2: No such file or directory)',
            'directory index of "/usr/share/nginx/html/images/" is forbidden',
            'access forbidden by rule',
            'client sent invalid method while reading client request line'
        ])
        ip = random.choice(IP_POOL)
        log_line = f'{timestamp_str_err} [{level}] 12345#12345: *6789 client: {ip}, server: localhost, request: "GET /some/problematic/path HTTP/1.1", {message}, host: "localhost:8080"\n'
        with open(ERROR_LOG_FILE_PATH, "a") as f:
            f.write(log_line)
        next_error_time = current_ts + random.uniform(0.5, 1.5)
        
    
    elapsed = time.time() - start_loop_time
    sleep_time = LOG_INTERVAL - elapsed
    if sleep_time > 0:
        time.sleep(sleep_time)