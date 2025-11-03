### docker-compose.yml

```
services:
  zookeeper:
    image: confluentinc/cp-zookeeper:7.4.0
    container_name: zookeeper
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
    ports:
      - "2181:2181"

  kafka:
    image: confluentinc/cp-kafka:7.4.0
    container_name: kafka
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    ports:
      - "9092:9092"
    depends_on:
      - zookeeper

  nginx:
    image: nginx:latest
    container_name: nginx
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/site1:/usr/share/nginx/html
      - ./nginx/logs:/var/log/nginx
    ports:
      - "8080:80"

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.10.2
    container_name: filebeat
    user: root
    command: ["--strict.perms=false"]
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - ./nginx/logs:/var/log/nginx:ro
    depends_on:
      - kafka
      - log_generator

  clickhouse:
    image: yandex/clickhouse-server:latest
    container_name: clickhouse
    ports:
      - "8123:8123"
      - "9000:9000"
    volumes:
      - ./clickhouse/init.sql:/docker-entrypoint-initdb.d/init.sql

  spark:
    build: ./spark
    container_name: spark
    user: root
    volumes:
      - ./spark:/opt/spark-apps  
      - ./spark/ivy:/home/spark/.ivy2
    depends_on:
      - kafka
      - clickhouse
    command: >
      bash -c "/opt/spark/bin/spark-submit
      --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.4.1,com.clickhouse:clickhouse-jdbc:0.4.6
      /opt/spark-apps/spark_processor.py"

  log_generator:
      image: python:3.11-slim
      container_name: log_generator
      volumes:
        - ./nginx/logs:/var/log/nginx
        - ./generate_logs.py:/app/generate_logs.py
      # УДАЛИТЬ command, чтобы он использовал CMD/ENTRYPOINT из Dockerfile или просто работал
      # command: >
      #   sh -c "pip install faker && python3 /app/generate_logs.py && echo 'Log generation finished.'"
      command: sh -c "pip install faker && python3 /app/generate_logs.py" # Оставить, чтобы установить faker и запустить скрипт бесконечно
      depends_on:
        - nginx

  streamlit:
    build:
      context: ./streamlit
    container_name: streamlit
    ports:
      - "8501:8501"
    depends_on:
      - clickhouse
```

### generate_logs.py

```
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
```

### filebeat.yml

```
filebeat.inputs:
- type: log
  enabled: true
  paths:
  - /var/log/nginx/access.log
  fields:
    log_type: "access"
  fields_under_root: true

- type: log
  enabled: true
  paths:
  - /var/log/nginx/error.log
  fields:
    log_type: "error"
  fields_under_root: true
  multiline:
    pattern: '^[0-9]{4}/[0-9]{2}/[0-9]{2}'
    negate: true
    match: after

output.kafka:
  hosts: [ "kafka:9092" ]
  topic: "nginx_logs"
  codec.json:
    pretty: false
  required_acks: 1
  max_message_bytes: 1000000

```

### .gitignore

```
./spark/GeoLite2-Country_20251028
./presentation.md
```

### nginx/nginx.conf

```
events {}

http {
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    server {
        listen 80;
        server_name localhost;
        root /usr/share/nginx/html;
        index index.html;
    }
}

```

### nginx/site1/index.html

```
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Test Site 1</title>
</head>
<body>
    <h1>Добро пожаловать!</h1>
    <p>Это тестовая страница для логов Nginx.</p>
    <a href="/about.html">О сайте</a>
</body>
</html>

```

### clickhouse/init.sql

```
-- clickhouse/init.sql

-- 1. Таблица Измерения: Время (для лучшей организации/анализа, хотя в CH DateTime и так хорош)
CREATE TABLE IF NOT EXISTS dim_time (
    time_id DateTime,
    hour UInt8,
    day_of_week UInt8,
    is_weekend UInt8
) ENGINE = MergeTree()
ORDER BY time_id;

-- 2. Таблица Измерения: IP / Геолокация
-- Используем MATERIALIZED/ReplacingMergeTree для генерации ключа (ip_id) и обновления/удаления устаревших записей
CREATE TABLE IF NOT EXISTS dim_ip (
    ip_id UInt64 MATERIALIZED toUInt64(abs(cityHash64(ip))), -- Простой хэш как ID
    ip String,
    country LowCardinality(String)
) ENGINE = ReplacingMergeTree(ip_id) -- Используем Replacing для обновления записей с тем же IP
ORDER BY ip;

-- 3. Таблица Измерения: Типы Аномалий и Логирования
CREATE TABLE IF NOT EXISTS dim_anomaly_type (
    anomaly_type_id UInt8 MATERIALIZED toUInt8(abs(cityHash64(anomaly_type, is_anomaly) % 255)), -- Простой ID
    anomaly_type String,
    is_anomaly UInt8 -- 1 или 0
) ENGINE = ReplacingMergeTree(anomaly_type_id)
ORDER BY anomaly_type;

-- 4. Таблица Фактов: События Nginx
CREATE TABLE IF NOT EXISTS fact_nginx_requests (
    -- Ключи Измерений (Foreign Keys)
    time_key DateTime,        -- Ключ времени (ссылка на dim_time, или просто DateTime)
    ip_key UInt64,             -- Ключ IP (ссылка на dim_ip.ip_id)
    anomaly_type_key UInt8,    -- Ключ типа аномалии (ссылка на dim_anomaly_type.anomaly_type_id)
    log_type LowCardinality(String), -- Разделение на access/error

    -- Метрики (Values)
    status UInt16,
    bytes UInt32,

    -- Текст ошибки (для ошибок, не помещается в размерности)
    error_message Nullable(String),

    -- Поля для ускорения поиска (для логов ошибок)
    method Nullable(String),
    page Nullable(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(time_key)
ORDER BY (time_key, ip_key);


-- Таблица для прогнозов остается
CREATE TABLE IF NOT EXISTS nginx_predictions (
    timestamp DateTime,
    predicted_requests Float64,
    predicted_lower Float64,
    predicted_upper Float64
) ENGINE = MergeTree()
ORDER BY timestamp;
```

### streamlit/dashboard.py

```
import streamlit as st
import pandas as pd
from clickhouse_driver import Client
import plotly.express as px
import pycountry_convert as pc
from datetime import datetime, timedelta
import altair as alt

# --- Конфигурация страницы и подключение к БД ---
st.set_page_config(page_title="Log Dashboard", layout="wide")

@st.cache_resource
def get_clickhouse_client():
    client = Client(host="clickhouse", port=9000)
    return client

CLIENT = get_clickhouse_client()


# --- Вспомогательные функции ---
@st.cache_data(ttl=60)
def run_query(_client, query):
    """Выполняет запрос к ClickHouse и возвращает DataFrame."""
    try:
        data, columns = _client.execute(query, with_column_types=True)
        column_names = [col[0] for col in columns]
        df = pd.DataFrame(data, columns=column_names)
        return df
    except Exception as e:
        st.error(f"Ошибка выполнения SQL-запроса: {e}")
        st.code(query)
        return pd.DataFrame()


def get_country_iso_alpha3(country_name):
    """Преобразует название страны в ISO Alpha-3 код для карты."""
    try:
        return pc.country_name_to_country_alpha3(country_name)
    except:
        return None

# --- Основной интерфейс ---
st.title("📊 Комплексная аналитика логов веб-сервера (Star Schema)")


# --- Боковая панель с фильтры ---
st.sidebar.title("Фильтры")

# --- ПРОВЕРКА ГОТОВНОСТИ DIM ТАБЛИЦ (НОВОЕ) ---
dim_check_df = run_query(CLIENT, "SELECT count() FROM dim_ip")
if dim_check_df.empty or dim_check_df.iloc[0, 0] == 0:
    st.error("⚠️ DIM таблица 'dim_ip' пуста. Пожалуйста, убедитесь, что 'spark_processor' запущен и обработал первые логи.")
    st.stop() # Останавливаем выполнение скрипта, чтобы избежать ошибок JOIN
# -------------------------------------------------

# Запрос для определения диапазона времени теперь идет к таблице Фактов
min_max_time_df = run_query(CLIENT, "SELECT min(time_key), max(time_key) FROM fact_nginx_requests")
if not min_max_time_df.empty and min_max_time_df.iloc[0, 0] is not None:
    min_ts = min_max_time_df.iloc[0, 0]
    max_ts = min_max_time_df.iloc[0, 1]

    # ИСПРАВЛЕНИЕ: Принудительно конвертируем pandas.Timestamp в стандартный python datetime
    min_dt = min_ts.to_pydatetime()
    max_dt = max_ts.to_pydatetime()

    # ИСПРАВЛЕНИЕ: Проверка, если min == max
    if min_dt >= max_dt:
        max_dt = min_dt + timedelta(minutes=1) 
        st.warning("В данных обнаружен только один временной интервал. Слайдер расширен на 1 минуту.")

    time_range = st.sidebar.slider(
        "Временной диапазон",
        min_value=min_dt,
        max_value=max_dt,
        value=(min_dt, max_dt),
        format="DD/MM/YYYY - HH:mm",
    )
    start_time, end_time = time_range
else:
    start_time, end_time = datetime.now() - timedelta(hours=1), datetime.now()

# Запросы к DIM таблицам для получения доступных значений
statuses_df = run_query(CLIENT, "SELECT DISTINCT status FROM fact_nginx_requests WHERE status IS NOT NULL ORDER BY status")
methods_df = run_query(CLIENT, "SELECT DISTINCT method FROM fact_nginx_requests WHERE method IS NOT NULL AND method != '' ORDER BY method")

# Запрос для получения стран (из DIM таблицы)
countries_df = run_query(CLIENT, "SELECT DISTINCT country FROM dim_ip WHERE country IS NOT NULL AND country != 'Unknown' AND country != 'Error' ORDER BY country")

all_statuses = statuses_df["status"].tolist() if not statuses_df.empty else []
all_countries = countries_df["country"].tolist() if not countries_df.empty else []
all_methods = methods_df["method"].tolist() if not methods_df.empty else []

selected_statuses = st.sidebar.multiselect("Статус ответа", all_statuses, default=all_statuses)
selected_countries = st.sidebar.multiselect("Страна", all_countries, default=all_countries)
selected_methods = st.sidebar.multiselect("Метод запроса", all_methods, default=all_methods)

if st.sidebar.button("🔄 Применить фильтры и обновить"):
    st.rerun()

# --- Формирование SQL-условия на основе фильтров ---
where_clauses = [f"T1.time_key BETWEEN toDateTime('{start_time}') AND toDateTime('{end_time}')"]

# Фильтры для Fact Table
if selected_statuses and len(selected_statuses) != len(all_statuses):
    where_clauses.append(f"T1.status IN {tuple(selected_statuses)}")
if selected_methods and len(selected_methods) != len(all_methods):
    where_clauses.append(f"T1.method IN {tuple(selected_methods)}")

# Фильтр для DIM IP (Страна)
if selected_countries and len(selected_countries) != len(all_countries):
    # JOIN и фильтр по DIM таблице
    where_clauses.append(f"T2.country IN {tuple(selected_countries)}")

where_sql = " AND ".join(where_clauses)
if where_sql:
    where_sql = "WHERE " + where_sql

# --- KPI-метрики ---
kpi_query = f"""
SELECT
    count() as total,
    uniq(T1.ip_key) as unique_ips,
    avg(T1.bytes) as avg_bytes,
    (countIf(T1.status >= 500) / toFloat64(countIf(true))) * 100 as server_error_rate,
    (countIf(T1.status >= 400 AND T1.status < 500) / toFloat64(countIf(true))) * 100 as client_error_rate
FROM fact_nginx_requests AS T1
INNER JOIN dim_ip AS T2 ON T1.ip_key = T2.ip_id
{where_sql.replace("WHERE", "WHERE T1.log_type = 'access' AND " if "WHERE" in where_sql else "WHERE T1.log_type = 'access' AND ")}
"""
kpi_df = run_query(CLIENT, kpi_query)
if not kpi_df.empty:
    kpi_data = kpi_df.iloc[0]
    total_requests, unique_ips, avg_bytes, server_error_rate, client_error_rate = (
        kpi_data.get("total", 0), kpi_data.get("unique_ips", 0), kpi_data.get("avg_bytes", 0),
        kpi_data.get("server_error_rate", 0.0), kpi_data.get("client_error_rate", 0.0)
    )
else:
    total_requests, unique_ips, avg_bytes, server_error_rate, client_error_rate = (0, 0, 0, 0.0, 0.0)

kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
kpi1.metric("Всего запросов", f"{total_requests:,}")
kpi2.metric("Уникальные IP", f"{unique_ips:,}")
kpi3.metric("Средний ответ (байт)", f"{int(avg_bytes):,}")
kpi4.metric("Ошибки клиента (4xx %)", f"{client_error_rate:.2f}%")
kpi5.metric("Ошибки сервера (5xx %)", f"{server_error_rate:.2f}%")
st.markdown("---")

# --- Вкладки с графиками ---
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
    ["📈 Обзор и динамика", "🌍 Гео-аналитика", "🚦 Топ-листы и статусы", "🚨 Детекция аномалий", "🔧 Анализ ошибок сервера", "🔮 Прогнозирование и Рекомендации"]
)

# --- ВКЛАДКА 1: Обзор и динамика ---
with tab1:
    st.subheader("Динамика запросов по типам ответов (Stacked Area Chart)")
    time_series_query_stacked = f"""
    SELECT
        toStartOfMinute(T1.time_key) as minute,
        countIf(T1.status >= 200 AND T1.status < 300) as success_2xx,
        countIf(T1.status >= 300 AND T1.status < 400) as redirects_3xx,
        countIf(T1.status >= 400 AND T1.status < 500) as client_errors_4xx,
        countIf(T1.status >= 500) as server_errors_5xx
    FROM fact_nginx_requests AS T1
    {where_sql.replace("WHERE", "WHERE T1.log_type = 'access' AND " if "WHERE" in where_sql else "WHERE T1.log_type = 'access' AND ")}
    GROUP BY minute ORDER BY minute
    """
    df_time_stacked = run_query(CLIENT, time_series_query_stacked)
    if not df_time_stacked.empty:
        st.area_chart(df_time_stacked.set_index("minute"))

    st.subheader("Динамика среднего размера ответа (в байтах)")
    avg_bytes_query = f"""
    SELECT
        toStartOfMinute(T1.time_key) as minute,
        avg(T1.bytes) as avg_bytes
    FROM fact_nginx_requests AS T1
    {where_sql.replace("WHERE", "WHERE T1.log_type = 'access' AND " if "WHERE" in where_sql else "WHERE T1.log_type = 'access' AND ")}
    GROUP BY minute ORDER BY minute
    """
    df_avg_bytes = run_query(CLIENT, avg_bytes_query)
    if not df_avg_bytes.empty:
        st.line_chart(df_avg_bytes.set_index("minute"))

# --- ВКЛАДКА 2: Гео-аналитика ---
with tab2:
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Карта запросов по странам")
        # JOIN Fact с Dim IP
        country_query = f"""
        SELECT 
            T2.country, 
            count() as cnt
        FROM fact_nginx_requests AS T1
        INNER JOIN dim_ip AS T2 ON T1.ip_key = T2.ip_id
        {where_sql.replace("WHERE", "WHERE T1.log_type = 'access' AND " if "WHERE" in where_sql else "WHERE T1.log_type = 'access' AND ")}
        GROUP BY T2.country
        """
        df_country = run_query(CLIENT, country_query)
        if not df_country.empty:
            df_country["iso_alpha"] = df_country["country"].apply(get_country_iso_alpha3)
            df_country = df_country.dropna(subset=["iso_alpha"])
            fig = px.choropleth(df_country, locations="iso_alpha", color="cnt", hover_name="country",
                                color_continuous_scale=px.colors.sequential.Plasma, title="Количество запросов")
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Карта уровня ошибок по странам")
        # JOIN Fact с Dim IP и фильтрация ошибок
        country_error_query = f"""
        SELECT
            T2.country,
            countIf(T1.status >= 400) as error_count,
            count() as total_count,
            (error_count / toFloat64(total_count)) * 100 as error_rate
        FROM fact_nginx_requests AS T1
        INNER JOIN dim_ip AS T2 ON T1.ip_key = T2.ip_id
        {where_sql.replace("WHERE", "WHERE T1.log_type = 'access' AND " if "WHERE" in where_sql else "WHERE T1.log_type = 'access' AND ")}
        GROUP BY T2.country HAVING total_count > 0
        """
        df_country_errors = run_query(CLIENT, country_error_query)
        if not df_country_errors.empty:
            df_country_errors["iso_alpha"] = df_country_errors["country"].apply(get_country_iso_alpha3)
            df_country_errors = df_country_errors.dropna(subset=["iso_alpha"])
            fig_errors = px.choropleth(df_country_errors, locations="iso_alpha", color="error_rate", hover_name="country",
                                       color_continuous_scale=px.colors.sequential.Reds, title="Процент ошибок (%)")
            st.plotly_chart(fig_errors, use_container_width=True)

    st.subheader("Сводная таблица по странам и ошибкам")
    if not df_country_errors.empty:
        st.dataframe(df_country_errors[['country', 'total_count', 'error_count', 'error_rate']].sort_values('error_rate', ascending=False), use_container_width=True)


# --- ВКЛАДКА 3: Топ-листы и статусы ---
with tab3:
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Топ 10 страниц по запросам")
        # JOIN Fact с Dim IP для фильтрации по стране, если она выбрана
        pages_query = f"""
        SELECT page, count() AS hits 
        FROM fact_nginx_requests AS T1
        {where_sql.replace("WHERE", "WHERE T1.log_type = 'access' AND " if "WHERE" in where_sql else "WHERE T1.log_type = 'access' AND ")}
        GROUP BY page ORDER BY hits DESC LIMIT 10
        """
        pages_df = run_query(CLIENT, pages_query)
        st.dataframe(pages_df, use_container_width=True)

        st.subheader("Топ 10 IP по объему трафика (MB)")
        # JOIN Fact с Dim IP для получения IP адреса
        ip_traffic_query = f"""
        SELECT 
            T2.ip, 
            sum(T1.bytes) / 1024 / 1024 as total_mb 
        FROM fact_nginx_requests AS T1
        INNER JOIN dim_ip AS T2 ON T1.ip_key = T2.ip_id
        {where_sql.replace("WHERE", "WHERE T1.log_type = 'access' AND " if "WHERE" in where_sql else "WHERE T1.log_type = 'access' AND ")}
        GROUP BY T2.ip ORDER BY total_mb DESC LIMIT 10
        """
        ip_traffic_df = run_query(CLIENT, ip_traffic_query)
        if not ip_traffic_df.empty:
            st.bar_chart(ip_traffic_df.set_index('ip'))

    with col2:
        st.subheader("Распределение по статусам")
        status_query = f"SELECT status, count() AS cnt FROM fact_nginx_requests {where_sql} AND log_type = 'access' GROUP BY status ORDER BY status"
        status_df = run_query(CLIENT, status_query)
        if not status_df.empty:
            fig = px.pie(status_df, names="status", values="cnt", title="Статусы ответов")
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Топ 10 IP по ошибкам")
        # JOIN Fact с Dim IP
        ip_errors_query = f"""
        SELECT 
            T2.ip, 
            count() as errors 
        FROM fact_nginx_requests AS T1
        INNER JOIN dim_ip AS T2 ON T1.ip_key = T2.ip_id
        {where_sql.replace("WHERE", "WHERE T1.log_type = 'access' AND T1.status >= 400 AND " if "WHERE" in where_sql else "WHERE T1.log_type = 'access' AND T1.status >= 400 AND ")}
        GROUP BY T2.ip ORDER BY errors DESC LIMIT 10
        """
        ip_errors_df = run_query(CLIENT, ip_errors_query)
        st.dataframe(ip_errors_df, use_container_width=True)

    st.subheader("Тепловая карта ошибок: Страница vs Статус")
    # JOIN Fact с Dim IP (для фильтрации по стране, если выбрана) и DIM Anomaly
    heatmap_query = f"""
    SELECT T1.page, T1.status, count() as count
    FROM fact_nginx_requests AS T1
    -- JOIN с Dim IP, чтобы применить фильтры по стране
    INNER JOIN dim_ip AS T2 ON T1.ip_key = T2.ip_id 
    {where_sql.replace("WHERE", "WHERE T1.log_type = 'access' AND T1.status >= 400 AND " if "WHERE" in where_sql else "WHERE T1.log_type = 'access' AND T1.status >= 400 AND ")}
    AND T1.page IN (
        SELECT page FROM fact_nginx_requests AS T_inner
        {where_sql.replace("WHERE", "WHERE T_inner.log_type = 'access' AND " if "WHERE" in where_sql else "WHERE T_inner.log_type = 'access' AND ")}
        GROUP BY page ORDER BY count() DESC LIMIT 15
    )
    GROUP BY T1.page, T1.status
    """
    heatmap_df = run_query(CLIENT, heatmap_query)
    if not heatmap_df.empty:
        heatmap_pivot = heatmap_df.pivot_table(index='page', columns='status', values='count').fillna(0)
        fig_heatmap = px.imshow(heatmap_pivot, text_auto=True, aspect="auto",
                                color_continuous_scale='Reds',
                                labels=dict(x="HTTP Статус", y="Страница", color="Кол-во ошибок"))
        st.plotly_chart(fig_heatmap, use_container_width=True)

# --- ВКЛАДКА 4: Детекция аномалий ---
with tab4:
    st.subheader("Обнаруженные аномалии")
    # Фильтр по временному диапазону и аномалиям
    anomaly_where = f"WHERE T1.time_key BETWEEN toDateTime('{start_time}') AND toDateTime('{end_time}')"

    col1, col2 = st.columns([2,1])
    with col1:
        st.subheader("Временная шкала аномалий (Timeline)")
        # JOIN Fact с Dim Anomaly и Dim IP
        anomaly_timeline_query = f"""
        SELECT 
            T1.time_key as timestamp, 
            T3.ip, 
            T2.anomaly_type
        FROM fact_nginx_requests AS T1
        INNER JOIN dim_anomaly_type AS T2 ON T1.anomaly_type_key = T2.anomaly_type_id
        INNER JOIN dim_ip AS T3 ON T1.ip_key = T3.ip_id
        {anomaly_where} AND T1.is_anomaly = 1 AND T2.anomaly_type != 'NoAnomaly' 
        ORDER BY timestamp DESC LIMIT 500
        """
        df_anomalies_timeline = run_query(CLIENT, anomaly_timeline_query)
        if not df_anomalies_timeline.empty:
            fig_timeline = px.scatter(df_anomalies_timeline, x='timestamp', y='ip', color='anomaly_type',
                                      title="Временная шкала аномальной активности",
                                      labels={"timestamp": "Время", "ip": "IP адрес атакующего", "anomaly_type": "Тип аномалии"})
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("Аномальная активность не обнаружена в выбранном диапазоне.")

    with col2:
        st.subheader("Распределение по типам аномалий")
        # Агрегация по Dim Anomaly
        anomaly_pie_query = f"""
        SELECT 
            T2.anomaly_type, 
            count() as cnt 
        FROM fact_nginx_requests AS T1
        INNER JOIN dim_anomaly_type AS T2 ON T1.anomaly_type_key = T2.anomaly_type_id
        {anomaly_where} AND T1.is_anomaly = 1 AND T2.anomaly_type != 'NoAnomaly' 
        GROUP BY T2.anomaly_type
        """
        df_anomaly_pie = run_query(CLIENT, anomaly_pie_query)
        if not df_anomaly_pie.empty:
            fig_pie = px.pie(df_anomaly_pie, names='anomaly_type', values='cnt')
            st.plotly_chart(fig_pie, use_container_width=True)

    st.subheader("Сводная таблица по аномалиям")
    # JOIN Fact с Dim IP и Dim Anomaly
    anomaly_table_query = f"""
    SELECT 
        T3.ip, 
        T3.country, 
        T2.anomaly_type, 
        max(T1.time_key) as last_seen, 
        count() as request_count 
    FROM fact_nginx_requests AS T1
    INNER JOIN dim_anomaly_type AS T2 ON T1.anomaly_type_key = T2.anomaly_type_id
    INNER JOIN dim_ip AS T3 ON T1.ip_key = T3.ip_id
    {anomaly_where} AND T1.is_anomaly = 1 AND T2.anomaly_type != 'NoAnomaly' 
    GROUP BY T3.ip, T3.country, T2.anomaly_type 
    ORDER BY last_seen DESC LIMIT 20
    """
    df_anomalies_table = run_query(CLIENT, anomaly_table_query)
    if not df_anomalies_table.empty:
        st.dataframe(df_anomalies_table, use_container_width=True)

# --- ВКЛАДКА 5: Анализ ошибок сервера ---
with tab5:
    st.subheader("Анализ логов ошибок")
    # Фильтрация по логам ошибок
    error_where = f"WHERE log_type = 'error' AND time_key BETWEEN toDateTime('{start_time}') AND toDateTime('{end_time}')"
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Топ 10 сообщений об ошибках")
        # Агрегация по полю error_message в Fact Table
        top_errors_query = f"SELECT error_message, count() as cnt FROM fact_nginx_requests {error_where} GROUP BY error_message ORDER BY cnt DESC LIMIT 10"
        df_top_errors = run_query(CLIENT, top_errors_query)
        if not df_top_errors.empty:
            fig_top_errors = px.bar(df_top_errors, x='cnt', y='error_message', orientation='h', title="Самые частые ошибки")
            st.plotly_chart(fig_top_errors, use_container_width=True)

    with col2:
        st.subheader("Динамика ошибок по уровням (error/warn) - **Требует DIM_ANOMALY**")
        # Для простоты, используем error_message как прокси
        error_level_query = f"""
        SELECT
            toStartOfMinute(time_key) as minute,
            countIf(error_message LIKE '%error%') as errors, 
            countIf(error_message LIKE '%warn%') as warnings
        FROM fact_nginx_requests {error_where}
        GROUP BY minute ORDER BY minute
        """
        df_error_level = run_query(CLIENT, error_level_query)
        if not df_error_level.empty and (df_error_level['errors'].sum() > 0 or df_error_level['warnings'].sum() > 0):
            st.line_chart(df_error_level.set_index('minute'))

    st.subheader("Последние 100 ошибок сервера")
    # JOIN Fact с Dim IP
    df_errors_table = run_query(CLIENT, f"""
        SELECT 
            T1.time_key as timestamp, 
            T2.ip, 
            T2.country, 
            T1.log_level, -- Это поле Nullable в Fact Table
            T1.error_message 
        FROM fact_nginx_requests AS T1
        INNER JOIN dim_ip AS T2 ON T1.ip_key = T2.ip_id
        {error_where} 
        ORDER BY timestamp DESC LIMIT 100
    """)
    if not df_errors_table.empty:
        st.dataframe(df_errors_table, use_container_width=True)
    else:
        st.info("Ошибки сервера не найдены в выбранном диапазоне.")
        
with tab6:
    st.subheader("Прогноз нагрузки на сервер (запросов в час)")
    
    # 1. Загружаем фактические данные за последние 3 дня
    actuals_query = """
    SELECT 
        toStartOfHour(time_key) as hour, 
        count() as actual_requests
    FROM fact_nginx_requests
    WHERE log_type = 'access' AND time_key >= now() - INTERVAL 3 DAY
    GROUP BY hour ORDER BY hour
    """
    df_actuals = run_query(CLIENT, actuals_query)
    
    # 2. Загружаем прогнозные данные (таблица осталась прежней)
    predictions_query = "SELECT timestamp as hour, predicted_requests, predicted_lower, predicted_upper FROM nginx_predictions ORDER BY hour"
    df_predictions = run_query(CLIENT, predictions_query)

    if not df_actuals.empty and not df_predictions.empty:
        # --- Блок предписывающей аналитики ---
        CRITICAL_LOAD_THRESHOLD = df_actuals['actual_requests'].quantile(0.95) # Порог = 95-й перцентиль исторической нагрузки
        
        future_predictions = df_predictions[df_predictions['hour'] > datetime.now()]
        
        if not future_predictions.empty:
            peak_prediction = future_predictions.sort_values('predicted_upper', ascending=False).iloc[0]

            st.info(f"**Прогноз:** Ожидается пиковая нагрузка **~{int(peak_prediction['predicted_requests'])}** запросов/час в **{peak_prediction['hour'].strftime('%Y-%m-%d %H:%M')}**.")

            if peak_prediction['predicted_upper'] > CRITICAL_LOAD_THRESHOLD:
                st.error(
                    f"""
                    **⚠️ РЕКОМЕНДАЦИЯ (Предписывающая аналитика):**
                    Прогнозируемая пиковая нагрузка ({int(peak_prediction['predicted_upper'])} запросов/час) превышает критический порог ({int(CRITICAL_LOAD_THRESHOLD)} запросов/час).
                    **Рекомендуется рассмотреть возможность масштабирования ресурсов веб-сервера (например, увеличения количества подов/контейнеров) перед пиковым временем.**
                    """
                )
            else:
                st.success(
                    """
                    **✅ РЕКОМЕНДАЦИЯ (Предписывающая аналитика):**
                    Прогнозируемая нагрузка находится в пределах нормы. Дополнительных действий не требуется.
                    """
                )

            # --- Визуализация ---
            # Преобразуем для Altair
            df_actuals['type'] = 'Фактические данные'
            df_actuals.rename(columns={'actual_requests': 'requests'}, inplace=True)
            
            df_pred_main = df_predictions[['hour', 'predicted_requests']].copy()
            df_pred_main['type'] = 'Прогноз'
            df_pred_main.rename(columns={'predicted_requests': 'requests'}, inplace=True)

            # Соединяем для основного графика
            source = pd.concat([df_actuals[['hour', 'requests', 'type']], df_pred_main])

            # Основной график
            line = alt.Chart(source).mark_line().encode(
                x='hour:T',
                y='requests:Q',
                color='type:N'
            ).properties(
                 title='Сравнение фактической нагрузки и прогноза'
            )

            # Область неопределенности для прогноза
            band = alt.Chart(df_predictions).mark_area(opacity=0.3).encode(
                x='hour:T',
                y='predicted_lower:Q',
                y2='predicted_upper:Q'
            ).properties(
                title='Доверительный интервал прогноза'
            )
            
            st.altair_chart((band + line).interactive(), use_container_width=True)
        else:
            st.warning("Нет будущих прогнозов для отображения.")
    else:
        st.warning("Нет данных для построения прогноза. Сначала необходимо запустить скрипты обучения и генерации прогнозов.")
```

### streamlit/Dockerfile

```
    
FROM python:3.11-slim

RUN pip install --no-cache-dir streamlit pandas clickhouse-driver plotly pycountry-convert

WORKDIR /app
COPY dashboard.py /app/dashboard.py

EXPOSE 8501
CMD ["streamlit", "run", "dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

### spark/make_predictions.py

```
import pandas as pd
from clickhouse_driver import Client
import pickle
import os # <-- ДОБАВИТЬ ЭТУ СТРОКУ

CLICKHOUSE_HOST = 'clickhouse'
MODEL_DIR = '/opt/spark-apps/model' # <-- ДОБАВИТЬ ЭТУ СТРОКУ
MODEL_PATH = os.path.join(MODEL_DIR, 'prophet_model.pkl') # <-- ИЗМЕНИТЬ ЭТУ СТРОКУ
PREDICTIONS_TABLE = 'nginx_predictions'

print("--- Начало генерации прогнозов ---")

# 1. Загрузка обученной модели
print(f"Загрузка модели из файла: {MODEL_PATH}")
with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)
print("✅ Модель загружена.")

# 2. Создание датафрейма для будущего
future = model.make_future_dataframe(periods=24, freq='H') # Прогноз на 24 часа вперед
forecast = model.predict(future)
print("✅ Прогноз сгенерирован.")

# 3. Подготовка данных для ClickHouse
forecast_to_save = forecast[['ds', 'yhat', 'yhat_lower', 'yhat_upper']].copy()
forecast_to_save.rename(columns={
    'ds': 'timestamp',
    'yhat': 'predicted_requests',
    'yhat_lower': 'predicted_lower',
    'yhat_upper': 'predicted_upper'
}, inplace=True)

# Оставляем только будущие прогнозы
now = pd.Timestamp.now().tz_localize(None)
forecast_to_save = forecast_to_save[forecast_to_save['timestamp'] > now]

# 4. Сохранение в ClickHouse
client = Client(host=CLICKHOUSE_HOST)
print(f"Подключение к ClickHouse для сохранения в таблицу {PREDICTIONS_TABLE}...")

# Очищаем старые прогнозы и вставляем новые
client.execute(f'TRUNCATE TABLE {PREDICTIONS_TABLE}')
print("Старые прогнозы удалены.")

client.execute(
    f'INSERT INTO {PREDICTIONS_TABLE} VALUES',
    forecast_to_save.to_dict('records')
)
print(f"✅ {len(forecast_to_save)} строк прогноза сохранено в ClickHouse.")

print("--- Генерация прогнозов завершена ---")
```

### spark/spark_processor.py

```
# spark/spark_processor.py
import time
import geoip2.database
from kafka.admin import KafkaAdminClient, NewTopic
from kafka.errors import TopicAlreadyExistsError
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    udf,
    col,
    from_json,
    when,
    lit,
    count,
    countDistinct,
    regexp_extract,
    to_timestamp,
    split,
    greatest,
    coalesce,
    hash, 
    date_trunc 
)
from pyspark.sql.types import StringType, StructField, StructType, IntegerType

KAFKA_BROKER = "kafka:9092"
TOPIC = "nginx_logs"
CHECKPOINT_DIR = "/tmp/spark_checkpoints_nginx_v3" # ИЗМЕНЕНО: Новый путь для сброса состояния
INIT_SCRIPT_EXECUTED = False # Флаг для однократного выполнения инициализации DIM

# Поведенческие пороги
REQUEST_RATE_THRESHOLD = 20
LOGIN_ATTACK_THRESHOLD = 10
SCANNING_THRESHOLD = 15

# Регулярные выражения для сигнатурных атак
SQLI_PATTERN = r"('|%27|--|%2D%2D|union|%75%6E%69%6F%6E)"
PATH_TRAVERSAL_PATTERN = r"(\.\./|%2E%2E%2F)"
VULN_SCAN_PATTERN = r"(wp-admin|phpmyadmin|/.git|/solr)"
BAD_AGENT_PATTERN = r"(sqlmap|nikto|nmap|masscan)"

CLICKHOUSE_URL = "jdbc:clickhouse://clickhouse:8123/default"
CLICKHOUSE_FACT_TABLE = "fact_nginx_requests"
CLICKHOUSE_DIM_IP = "dim_ip"
CLICKHOUSE_DIM_ANOMALY = "dim_anomaly_type"
GEO_DB_PATH = "/opt/spark-apps/GeoLite2-Country.mmdb"

def ensure_topic():
    for i in range(10):
        try:
            admin = KafkaAdminClient(bootstrap_servers=KAFKA_BROKER, client_id="spark-topic-checker")
            topic_list = [NewTopic(name=TOPIC, num_partitions=1, replication_factor=1)]
            admin.create_topics(new_topics=topic_list, validate_only=False)
            print(f"✅ Kafka topic '{TOPIC}' создан.")
            admin.close()
            return
        except TopicAlreadyExistsError:
            print(f"ℹ️ Kafka topic '{TOPIC}' уже существует.")
            admin.close()
            return
        except Exception as e:
            print(f"⚠️ Kafka пока не готов ({e}), ждём...")
            time.sleep(5)
    print("❌ Не удалось создать Kafka-топик. Проверь kafka logs.")

ensure_topic()

spark = SparkSession.builder.appName("NginxLogProcessorStarSchema").config("spark.sql.streaming.checkpointLocation", CHECKPOINT_DIR).getOrCreate()

@udf(StringType())
def get_country_from_ip(ip):
    try:
        with geoip2.database.Reader(GEO_DB_PATH) as reader:
            response = reader.country(ip)
            return response.country.name
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return "Unknown"
    except Exception:
        return "Error"

kafka_schema = StructType([StructField("message", StringType()), StructField("log_type", StringType())])
df = spark.readStream.format("kafka").option("kafka.bootstrap.servers", KAFKA_BROKER).option("subscribe", TOPIC).option("startingOffsets", "earliest").load()
json_df = df.select(from_json(col("value").cast("string"), kafka_schema).alias("data")).select("data.*")

access_pattern = r'(\S+) - - \[(.*?)\] "(\S+)\s*(\S*)\s*(\S*)" (\d{3}) (\d+) "(.*?)" "(.*?)"'
error_pattern = r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] .*? client: (\S+), server: .*?, request: ".*?", (.*?), host: ".*?"'

access_logs = json_df.filter(col("log_type") == "access").select(
    regexp_extract("message", access_pattern, 1).alias("ip"),
    regexp_extract("message", access_pattern, 2).alias("time"),
    regexp_extract("message", access_pattern, 3).alias("method"),
    regexp_extract("message", access_pattern, 4).alias("page"),
    regexp_extract("message", access_pattern, 6).alias("status"),
    regexp_extract("message", access_pattern, 7).alias("bytes"),
    regexp_extract("message", access_pattern, 8).alias("referrer"),
    regexp_extract("message", access_pattern, 9).alias("agent"),
    lit("access").alias("log_type"),
).withColumn("request", col("page")).withColumn("timestamp", to_timestamp(col("time"), "dd/MMM/yyyy:HH:mm:ss Z")).withColumn("status", col("status").cast(IntegerType())).withColumn("bytes", col("bytes").cast(IntegerType())).withColumn("error_message", lit(None).cast(StringType())).withColumn("log_level", lit(None).cast(StringType())).drop("time")

# ИСПРАВЛЕНО: Упрощенная и более надежная логика для IP в логах ошибок
# В spark_processor.py, замените старый блок error_logs:
error_logs = (
    json_df.filter(col("log_type") == "error")
    .select(
        regexp_extract("message", error_pattern, 1).alias("time"),
        regexp_extract("message", error_pattern, 2).alias("log_level"),
        regexp_extract("message", error_pattern, 3).alias("ip_raw"),
        regexp_extract("message", error_pattern, 4).alias("error_message"),
        lit("error").alias("log_type"),
    )
    .withColumn("ip", regexp_extract(col("ip_raw"), r'^(\S+)', 1))
    .withColumn("ip", when(col("ip") != "", col("ip")).otherwise(lit("0.0.0.0")))
    .withColumn("timestamp", to_timestamp(col("time"), "yyyy/MM/dd HH:mm:ss"))
    .select(
        "timestamp",
        "ip",
        "log_type",
        "log_level",
        "error_message",
        lit(None).cast(StringType()).alias("request"),
        lit(None).cast(StringType()).alias("method"),
        lit(None).cast(StringType()).alias("page"),
        lit(0).cast(IntegerType()).alias("status"),
        lit(0).cast(IntegerType()).alias("bytes"),
        lit(None).cast(StringType()).alias("referrer"),
        lit(None).cast(StringType()).alias("agent"),
    )
)


unified_df = access_logs.unionByName(error_logs).filter(col("ip") != "")


def write_to_clickhouse(batch_df, batch_id):
    if batch_df.rdd.isEmpty():
        print(f"⚠️ Пустой batch {batch_id}, пропущен.")
        return

    print(f"--- Processing Batch {batch_id} (Star Schema ETL) ---")
    batch_df.cache()

    # --- 1. Подготовка Данных для DIMENSION (IP/Geo) ---
    dim_ip_df = (
        batch_df.filter(col("ip").isNotNull())
        .select(
            col("ip"), 
            get_country_from_ip(col("ip")).alias("country"),
            hash(col("ip")).alias("ip_id")
        )
        .distinct()
    )
    
    # Заполняем пропущенные страны
    dim_ip_df = dim_ip_df.na.fill({'country': 'Unknown'})
    
    # ИСПРАВЛЕНИЕ (ФИНАЛЬНОЕ): Явно перевыбираем ВСЕ 3 столбца в нужном порядке перед записью. 
    # Это должно предотвратить потерю ip_id после .na.fill()
    dim_ip_df = dim_ip_df.select("ip", "country", "ip_id") 
    
    # Вставляем/Обновляем в dim_ip (используя ReplacingMergeTree)
    (
        dim_ip_df.write.format("jdbc")
        .option("url", CLICKHOUSE_URL)
        .option("driver", "com.clickhouse.jdbc.ClickHouseDriver")
        .option("dbtable", CLICKHOUSE_DIM_IP)
        .option("user", "default").option("password", "")
        .mode("append")
        .save()
    )

    # --- 2. Подготовка Данных для DIMENSION (Anomaly Type) ---
    # Определение аномалий (только сигнатурные для атомарности факта)
    enriched_for_dim = batch_df.withColumn("signature_anomaly_type",
        when(col("page").rlike(SQLI_PATTERN), "SQL Injection")
        .when(col("page").rlike(PATH_TRAVERSAL_PATTERN), "Path Traversal")
        .when(col("page").rlike(VULN_SCAN_PATTERN), "Vulnerability Scan")
        .when(col("agent").rlike(BAD_AGENT_PATTERN), "Bad User-Agent")
        .otherwise(lit(None))
    )
    
    dim_anomaly_df = (
        enriched_for_dim.filter(col("signature_anomaly_type").isNotNull())
        .select(col("signature_anomaly_type").alias("anomaly_type"), lit(1).cast(IntegerType()).alias("is_anomaly"))
        .distinct()
    )
    # Вставляем/Обновляем в dim_anomaly_type
    (
        dim_anomaly_df.write.format("jdbc")
        .option("url", CLICKHOUSE_URL)
        .option("driver", "com.clickhouse.jdbc.ClickHouseDriver")
        .option("dbtable", CLICKHOUSE_DIM_ANOMALY)
        .option("user", "default").option("password", "")
        .mode("append")
        .save()
    )

    # --- 3. Обогащение и вставка в FACT Table ---
    
    final_fact_df = (
        enriched_for_dim
        .withColumn("anomaly_type", coalesce(col("signature_anomaly_type"), lit("NoAnomaly")))
        .withColumn("is_anomaly", when(col("anomaly_type") != "NoAnomaly", 1).otherwise(0))
        .withColumn("country", get_country_from_ip(col("ip"))) # Страна нужна только для DIM, но оставим для отладки
        .withColumn("time_key", date_trunc("hour", col("timestamp"))) # Ключ времени
        .withColumn("ip_key", hash(col("ip"))) # Ключ IP (хэш от IP)
        .withColumn("anomaly_type_key", hash(col("anomaly_type"), col("is_anomaly")) % 255) # Вычисляем хэш напрямую
        .withColumn("log_type", coalesce(col("log_type"), lit("unknown")))
    )
    
    (
        final_fact_df.select(
            col("time_key"),
            col("ip_key"),
            col("anomaly_type_key"),
            "log_type",
            col("status"),
            col("bytes"),
            col("error_message"),
            col("method"),
            col("page")
        )
        .write.format("jdbc")
        .option("url", CLICKHOUSE_URL)
        .option("driver", "com.clickhouse.jdbc.ClickHouseDriver")
        .option("dbtable", CLICKHOUSE_FACT_TABLE)
        .option("user", "default")
        .option("password", "")
        .mode("append")
        .save()
    )

    print(f"✅ Batch {batch_id} записан в ClickHouse Fact Table. {final_fact_df.count()} строк.")
    batch_df.unpersist()
    
query = unified_df.writeStream.foreachBatch(write_to_clickhouse).outputMode("append").option("checkpointLocation", CHECKPOINT_DIR).trigger(processingTime="15 seconds").start()
query.awaitTermination()
```

### spark/Dockerfile

```
FROM apache/spark:3.4.1

USER root

RUN apt-get update && apt-get install -y python3-pip build-essential libssl-dev libffi-dev python3-dev && \
    pip install --no-cache-dir kafka-python clickhouse-driver pyspark geoip2 prophet

WORKDIR /opt/spark-apps

COPY . /opt/spark-apps

CMD ["/opt/spark/bin/spark-submit", \
     "--packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.4.1,com.clickhouse:clickhouse-jdbc:0.4.6", \
     "/opt/spark-apps/spark_processor.py"]
```

### spark/train_model.py

```
import pandas as pd
from prophet import Prophet
from clickhouse_driver import Client
import pickle
import os  # <-- ДОБАВИТЬ ЭТУ СТРОКУ

CLICKHOUSE_HOST = 'clickhouse'
MODEL_DIR = '/opt/spark-apps/model' # <-- ДОБАВИТЬ ЭТУ СТРОКУ
MODEL_PATH = os.path.join(MODEL_DIR, 'prophet_model.pkl') # <-- ИЗМЕНИТЬ ЭТУ СТРОКУ

print("--- Начало обучения модели прогнозирования ---")

# 1. Загрузка исторических данных из ClickHouse
print(f"Подключение к ClickHouse ({CLICKHOUSE_HOST})...")
client = Client(host=CLICKHOUSE_HOST)
query = """
SELECT 
    toStartOfHour(timestamp) as ds,
    count() as y
FROM nginx_logs
WHERE log_type = 'access'
GROUP BY ds
ORDER BY ds
"""
print("Выполнение запроса для получения исторических данных...")
data, columns = client.execute(query, with_column_types=True)
df = pd.DataFrame(data, columns=[c[0] for c in columns])
print(f"Загружено {len(df)} строк исторических данных.")

df['ds'] = pd.to_datetime(df['ds'])

if len(df) < 2:
    print("❌ Недостаточно данных для обучения. Требуется как минимум 2 точки.")
    exit()

# 2. Обучение модели Prophet
print("Обучение модели Prophet...")
model = Prophet(daily_seasonality=True, weekly_seasonality=True)
model.fit(df)
print("✅ Модель успешно обучена.")

# 3. Сохранение модели в файл
print(f"Сохранение модели в файл: {MODEL_PATH}")

# --- ВОТ ИСПРАВЛЕНИЕ ---
# Создаем директорию, если она не существует
os.makedirs(MODEL_DIR, exist_ok=True) # <-- ДОБАВИТЬ ЭТУ СТРОКУ
# -------------------------

with open(MODEL_PATH, 'wb') as f:
    pickle.dump(model, f)

print("--- Обучение модели завершено ---")
```

