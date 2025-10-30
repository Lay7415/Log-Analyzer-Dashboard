import random
import time
from datetime import datetime, timezone
from faker import Faker

fake = Faker()

LOG_FILE_PATH = "./nginx/logs/access.log"
NUM_LOG_LINES = 10000

print("Подготовка пулов реалистичных данных...")

IP_POOL = [fake.ipv4() for _ in range(200)]
ip_weights = ([0.04] * 10) + ([0.00315] * 190)


pages = [
    "/",                            # Главная страница (самая популярная)
    "/products/123",                # Популярный товар
    "/api/v1/users",                # Частый API-запрос
    "/cart",                        # Корзина
    "/login",                       # Страница входа
    "/products/456",                # Другой товар
    "/checkout",                    # Оформление заказа
    "/blog/article-1",              # Непопулярная статья в блоге
    "/contact-us",                  # Контакты
    "/api/v2/items"                 # Другой API-запрос
]
page_weights = [0.30, 0.15, 0.10, 0.10, 0.08, 0.08, 0.07, 0.04, 0.04, 0.04]

USER_AGENT_POOL = [fake.user_agent() for _ in range(100)]


http_statuses = [200, 301, 404, 500, 403]
status_weights = [0.8, 0.05, 0.08, 0.02, 0.05] # Сделаем 200 еще более частым


print(f"Генерация {NUM_LOG_LINES} строк логов в файл {LOG_FILE_PATH}...")

with open(LOG_FILE_PATH, "w") as f:
    for _ in range(NUM_LOG_LINES):
        ip = random.choices(IP_POOL, weights=ip_weights, k=1)[0]
        page = random.choices(pages, weights=page_weights, k=1)[0]
        
        user_agent = random.choice(USER_AGENT_POOL)
        
        now_aware = datetime.now().replace(tzinfo=timezone.utc)
        timestamp = now_aware.strftime('%d/%b/%Y:%H:%M:%S %z')
        
        method = random.choice(["GET", "POST"]) 
        protocol = "HTTP/1.1"
        request = f"{method} {page} {protocol}"
        
        status = random.choices(http_statuses, weights=status_weights, k=1)[0]
        bytes_sent = random.randint(100, 15000)
        referrer = fake.uri()

        log_line = f'{ip} - - [{timestamp}] "{request}" {status} {bytes_sent} "{referrer}" "{user_agent}"\n'
        f.write(log_line)

print("Генерация завершена.")