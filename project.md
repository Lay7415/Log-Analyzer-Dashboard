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

### nginx/logs/access.log

```

```

### nginx/logs/error.log

```

```

### clickhouse/init.sql

```
CREATE TABLE IF NOT EXISTS nginx_logs (
    timestamp DateTime,
    ip String,
    country LowCardinality(String),
    log_type LowCardinality(String),

    request Nullable(String),
    method Nullable(String),
    page Nullable(String),
    status Nullable(UInt16),
    bytes Nullable(UInt32),
    referrer Nullable(String),
    agent Nullable(String),

    log_level LowCardinality(Nullable(String)),
    error_message Nullable(String),

    is_anomaly UInt8,
    anomaly_type String

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
st.title("📊 Комплексная аналитика логов веб-сервера")


# --- Боковая панель с фильтрами ---
st.sidebar.title("Фильтры")

min_max_time_df = run_query(CLIENT, "SELECT min(timestamp), max(timestamp) FROM nginx_logs")
if not min_max_time_df.empty and min_max_time_df.iloc[0, 0] is not None:
    min_ts = min_max_time_df.iloc[0, 0]
    max_ts = min_max_time_df.iloc[0, 1]

    # ИСПРАВЛЕНИЕ: Принудительно конвертируем pandas.Timestamp в стандартный python datetime
    min_dt = min_ts.to_pydatetime()
    max_dt = max_ts.to_pydatetime()

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

statuses_df = run_query(CLIENT, "SELECT DISTINCT status FROM nginx_logs WHERE status IS NOT NULL ORDER BY status")
countries_df = run_query(CLIENT, "SELECT DISTINCT country FROM nginx_logs WHERE country IS NOT NULL AND country != 'Unknown' AND country != 'Error' ORDER BY country")
methods_df = run_query(CLIENT, "SELECT DISTINCT method FROM nginx_logs WHERE method IS NOT NULL AND method != '' ORDER BY method")

all_statuses = statuses_df["status"].tolist() if not statuses_df.empty else []
all_countries = countries_df["country"].tolist() if not countries_df.empty else []
all_methods = methods_df["method"].tolist() if not methods_df.empty else []

selected_statuses = st.sidebar.multiselect("Статус ответа", all_statuses, default=all_statuses)
selected_countries = st.sidebar.multiselect("Страна", all_countries, default=all_countries)
selected_methods = st.sidebar.multiselect("Метод запроса", all_methods, default=all_methods)

if st.sidebar.button("🔄 Применить фильтры и обновить"):
    st.rerun()

# --- Формирование SQL-условия на основе фильтров ---
where_clauses = [f"timestamp BETWEEN toDateTime('{start_time}') AND toDateTime('{end_time}')"]
if selected_statuses and len(selected_statuses) != len(all_statuses):
    where_clauses.append(f"status IN {tuple(selected_statuses)}")
if selected_countries and len(selected_countries) != len(all_countries):
    where_clauses.append(f"country IN {tuple(selected_countries)}")
if selected_methods and len(selected_methods) != len(all_methods):
    where_clauses.append(f"method IN {tuple(selected_methods)}")

where_sql = " AND ".join(where_clauses)
if where_sql:
    where_sql = "WHERE " + where_sql

# --- KPI-метрики ---
kpi_query = f"""
SELECT
    count() as total,
    uniq(ip) as unique_ips,
    avg(bytes) as avg_bytes,
    (countIf(status >= 500) / toFloat64(countIf(true))) * 100 as server_error_rate,
    (countIf(status >= 400 AND status < 500) / toFloat64(countIf(true))) * 100 as client_error_rate
FROM nginx_logs
{where_sql.replace("WHERE", "WHERE log_type = 'access' AND " if "WHERE" in where_sql else "WHERE log_type = 'access'")}
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
tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["📈 Обзор и динамика", "🌍 Гео-аналитика", "🚦 Топ-листы и статусы", "🚨 Детекция аномалий", "🔧 Анализ ошибок сервера"]
)

# --- ВКЛАДКА 1: Обзор и динамика ---
with tab1:
    st.subheader("Динамика запросов по типам ответов (Stacked Area Chart)")
    time_series_query_stacked = f"""
    SELECT
        toStartOfMinute(timestamp) as minute,
        countIf(status >= 200 AND status < 300) as success_2xx,
        countIf(status >= 300 AND status < 400) as redirects_3xx,
        countIf(status >= 400 AND status < 500) as client_errors_4xx,
        countIf(status >= 500) as server_errors_5xx
    FROM nginx_logs
    {where_sql.replace("WHERE", "WHERE log_type = 'access' AND " if "WHERE" in where_sql else "WHERE log_type = 'access'")}
    GROUP BY minute ORDER BY minute
    """
    df_time_stacked = run_query(CLIENT, time_series_query_stacked)
    if not df_time_stacked.empty:
        st.area_chart(df_time_stacked.set_index("minute"))

    st.subheader("Динамика среднего размера ответа (в байтах)")
    avg_bytes_query = f"""
    SELECT
        toStartOfMinute(timestamp) as minute,
        avg(bytes) as avg_bytes
    FROM nginx_logs
    {where_sql.replace("WHERE", "WHERE log_type = 'access' AND " if "WHERE" in where_sql else "WHERE log_type = 'access'")}
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
        country_query = f"SELECT country, count() as cnt FROM nginx_logs {where_sql} GROUP BY country"
        df_country = run_query(CLIENT, country_query)
        if not df_country.empty:
            df_country["iso_alpha"] = df_country["country"].apply(get_country_iso_alpha3)
            df_country = df_country.dropna(subset=["iso_alpha"])
            fig = px.choropleth(df_country, locations="iso_alpha", color="cnt", hover_name="country",
                                color_continuous_scale=px.colors.sequential.Plasma, title="Количество запросов")
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Карта уровня ошибок по странам")
        country_error_query = f"""
        SELECT
            country,
            countIf(status >= 400) as error_count,
            count() as total_count,
            (error_count / toFloat64(total_count)) * 100 as error_rate
        FROM nginx_logs {where_sql}
        GROUP BY country HAVING total_count > 0
        """
        df_country_errors = run_query(CLIENT, country_error_query)
        if not df_country_errors.empty:
            df_country_errors["iso_alpha"] = df_country_errors["country"].apply(get_country_iso_alpha3)
            df_country_errors = df_country_errors.dropna(subset=["iso_alpha"])
            fig_errors = px.choropleth(df_country_errors, locations="iso_alpha", color="error_rate", hover_name="country",
                                       color_continuous_scale=px.colors.sequential.Reds, title="Процент ошибок (%)")
            st.plotly_chart(fig_errors, use_container_width=True)

    st.subheader("Таблица с гео-данными и ошибками")
    if not df_country_errors.empty:
        st.dataframe(df_country_errors[['country', 'total_count', 'error_count', 'error_rate']].sort_values('error_rate', ascending=False), use_container_width=True)


# --- ВКЛАДКА 3: Топ-листы и статусы ---
with tab3:
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Топ 10 страниц по запросам")
        pages_df = run_query(CLIENT, f"SELECT page, count() AS hits FROM nginx_logs {where_sql} AND log_type = 'access' GROUP BY page ORDER BY hits DESC LIMIT 10")
        st.dataframe(pages_df, use_container_width=True)

        st.subheader("Топ 10 IP по объему трафика (MB)")
        ip_traffic_df = run_query(CLIENT, f"SELECT ip, sum(bytes) / 1024 / 1024 as total_mb FROM nginx_logs {where_sql} AND log_type = 'access' GROUP BY ip ORDER BY total_mb DESC LIMIT 10")
        if not ip_traffic_df.empty:
            st.bar_chart(ip_traffic_df.set_index('ip'))

    with col2:
        st.subheader("Распределение по статусам")
        status_df = run_query(CLIENT, f"SELECT status, count() AS cnt FROM nginx_logs {where_sql} AND log_type = 'access' GROUP BY status ORDER BY status")
        if not status_df.empty:
            fig = px.pie(status_df, names="status", values="cnt", title="Статусы ответов")
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Топ 10 IP по ошибкам")
        ip_errors_df = run_query(CLIENT, f"SELECT ip, count() as errors FROM nginx_logs {where_sql} AND log_type = 'access' AND status >= 400 GROUP BY ip ORDER BY errors DESC LIMIT 10")
        st.dataframe(ip_errors_df, use_container_width=True)

    st.subheader("Тепловая карта ошибок: Страница vs Статус")
    heatmap_query = f"""
    SELECT page, status, count() as count
    FROM nginx_logs
    {where_sql}
    AND page IN (SELECT page FROM nginx_logs {where_sql} GROUP BY page ORDER BY count() DESC LIMIT 15)
    AND status >= 400
    GROUP BY page, status
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
    anomaly_where = f"WHERE timestamp BETWEEN toDateTime('{start_time}') AND toDateTime('{end_time}')"

    col1, col2 = st.columns([2,1])
    with col1:
        st.subheader("Временная шкала аномалий (Timeline)")
        anomaly_timeline_query = f"SELECT timestamp, ip, anomaly_type FROM nginx_logs {anomaly_where} AND is_anomaly = 1 AND anomaly_type != '' ORDER BY timestamp DESC LIMIT 500"
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
        anomaly_pie_query = f"SELECT anomaly_type, count() as cnt FROM nginx_logs {anomaly_where} AND is_anomaly = 1 AND anomaly_type != '' GROUP BY anomaly_type"
        df_anomaly_pie = run_query(CLIENT, anomaly_pie_query)
        if not df_anomaly_pie.empty:
            fig_pie = px.pie(df_anomaly_pie, names='anomaly_type', values='cnt')
            st.plotly_chart(fig_pie, use_container_width=True)

    st.subheader("Сводная таблица по аномалиям")
    anomaly_table_query = f"SELECT ip, country, anomaly_type, max(timestamp) as last_seen, count() as request_count FROM nginx_logs {anomaly_where} AND is_anomaly = 1 AND anomaly_type != '' GROUP BY ip, country, anomaly_type ORDER BY last_seen DESC LIMIT 20"
    df_anomalies_table = run_query(CLIENT, anomaly_table_query)
    if not df_anomalies_table.empty:
        st.dataframe(df_anomalies_table, use_container_width=True)

# --- ВКЛАДКА 5: Анализ ошибок сервера ---
with tab5:
    st.subheader("Анализ логов ошибок")
    error_where = f"WHERE log_type = 'error' AND timestamp BETWEEN toDateTime('{start_time}') AND toDateTime('{end_time}')"
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Топ 10 сообщений об ошибках")
        top_errors_query = f"SELECT error_message, count() as cnt FROM nginx_logs {error_where} GROUP BY error_message ORDER BY cnt DESC LIMIT 10"
        df_top_errors = run_query(CLIENT, top_errors_query)
        if not df_top_errors.empty:
            fig_top_errors = px.bar(df_top_errors, x='cnt', y='error_message', orientation='h', title="Самые частые ошибки")
            st.plotly_chart(fig_top_errors, use_container_width=True)

    with col2:
        st.subheader("Динамика ошибок по уровням (error/warn)")
        error_level_query = f"""
        SELECT
            toStartOfMinute(timestamp) as minute,
            countIf(log_level = 'error') as errors,
            countIf(log_level = 'warn') as warnings
        FROM nginx_logs {error_where}
        GROUP BY minute ORDER BY minute
        """
        df_error_level = run_query(CLIENT, error_level_query)
        if not df_error_level.empty and (df_error_level['errors'].sum() > 0 or df_error_level['warnings'].sum() > 0):
            st.line_chart(df_error_level.set_index('minute'))

    st.subheader("Последние 100 ошибок сервера")
    df_errors_table = run_query(CLIENT, f"SELECT timestamp, ip, country, log_level, error_message FROM nginx_logs {error_where} ORDER BY timestamp DESC LIMIT 100")
    if not df_errors_table.empty:
        st.dataframe(df_errors_table, use_container_width=True)
    else:
        st.info("Ошибки сервера не найдены в выбранном диапазоне.")
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

### spark/spark_processor.py

```
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
    coalesce
)
from pyspark.sql.types import StringType, StructType, StructField, IntegerType

KAFKA_BROKER = "kafka:9092"
TOPIC = "nginx_logs"
CHECKPOINT_DIR = "/tmp/spark_checkpoints_nginx"
CLICKHOUSE_URL = "jdbc:clickhouse://clickhouse:8123/default"
CLICKHOUSE_TABLE = "nginx_logs"
GEO_DB_PATH = "/opt/spark-apps/GeoLite2-Country.mmdb"

# Поведенческие пороги
REQUEST_RATE_THRESHOLD = 20
LOGIN_ATTACK_THRESHOLD = 10
SCANNING_THRESHOLD = 15

# НОВИНКА: Регулярные выражения для сигнатурных атак
SQLI_PATTERN = r"('|%27|--|%2D%2D|union|%75%6E%69%6F%6E)"
PATH_TRAVERSAL_PATTERN = r"(\.\./|%2E%2E%2F)"
VULN_SCAN_PATTERN = r"(wp-admin|phpmyadmin|/.git|/solr)"
BAD_AGENT_PATTERN = r"(sqlmap|nikto|nmap|masscan)"

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

spark = SparkSession.builder.appName("NginxLogProcessor").config("spark.sql.streaming.checkpointLocation", CHECKPOINT_DIR).getOrCreate()

@udf(StringType())
def get_country_from_ip(ip):
    try:
        # Указываем with, чтобы Reader корректно закрывался
        with geoip2.database.Reader(GEO_DB_PATH) as reader:
            response = reader.country(ip)
            return response.country.name
    except (geoip2.errors.AddressNotFoundError, ValueError):
        # Ошибки поиска или невалидный IP
        return "Unknown"
    except Exception:
        # Любые другие ошибки (например, файл БД не найден)
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
error_logs = json_df.filter(col("log_type") == "error").select(
    regexp_extract("message", error_pattern, 1).alias("time"),
    regexp_extract("message", error_pattern, 2).alias("log_level"),
    regexp_extract("message", error_pattern, 3).alias("ip_raw"),
    regexp_extract("message", error_pattern, 4).alias("error_message"),
    lit("error").alias("log_type"),
).withColumn("ip", split(col("ip_raw"), ",")[0]).withColumn("timestamp", to_timestamp(col("time"), "yyyy/MM/dd HH:mm:ss")).select("timestamp", "ip", "log_type", "log_level", "error_message", lit(None).cast(StringType()).alias("request"), lit(None).cast(StringType()).alias("method"), lit(None).cast(StringType()).alias("page"), lit(None).cast(IntegerType()).alias("status"), lit(None).cast(IntegerType()).alias("bytes"), lit(None).cast(StringType()).alias("referrer"), lit(None).cast(StringType()).alias("agent"))
unified_df = access_logs.unionByName(error_logs).filter(col("ip") != "")


def write_to_clickhouse(batch_df, batch_id):
    if batch_df.rdd.isEmpty():
        print(f"⚠️ Пустой batch {batch_id}, пропущен.")
        return

    print(f"--- Processing Batch {batch_id} ---")
    batch_df.cache()

    # ЭТАП 1: Сигнатурный анализ (проверка каждой строки)
    signature_df = batch_df.withColumn("signature_anomaly_type",
        when(col("page").rlike(SQLI_PATTERN), "SQL Injection")
        .when(col("page").rlike(PATH_TRAVERSAL_PATTERN), "Path Traversal")
        .when(col("page").rlike(VULN_SCAN_PATTERN), "Vulnerability Scan")
        .when(col("agent").rlike(BAD_AGENT_PATTERN), "Bad User-Agent")
        .otherwise(lit(None))
    )

    # ЭТАП 2: Поведенческий анализ (агрегация по IP)
    behavioral_df = (
        batch_df.filter(col("log_type") == "access")
        .groupBy("ip")
        .agg(
            count("*").alias("request_count"),
            countDistinct("page").alias("distinct_pages"),
            count(when((col("page") == "/login") & (col("method") == "POST"), 1)).alias("login_posts"),
        )
        .withColumn("behavioral_anomaly_type",
            when(col("login_posts") > LOGIN_ATTACK_THRESHOLD, "Login Attack")
            .when(col("distinct_pages") > SCANNING_THRESHOLD, "Scanning Activity")
            .when(col("request_count") > REQUEST_RATE_THRESHOLD, "Request Rate Anomaly")
            .otherwise(lit(None))
        )
    )

    # ЭТАП 3: Объединение результатов
    enriched_df = signature_df.join(behavioral_df, "ip", "left")

    final_df = (
        enriched_df
        # coalesce берет первое не-null значение. Приоритет у сигнатурных атак
        .withColumn("anomaly_type", coalesce(col("signature_anomaly_type"), col("behavioral_anomaly_type")))
        .withColumn("is_anomaly", when(col("anomaly_type").isNotNull(), 1).otherwise(0))
        .withColumn("country", get_country_from_ip(col("ip")))
        .withColumn("anomaly_type", coalesce(col("anomaly_type"), lit(""))) # Заменяем null на пустую строку для ClickHouse
    )
    
    (
        final_df.select(
            "timestamp", "ip", "country", "log_type", "request", "method",
            "page", "status", "bytes", "referrer", "agent", "log_level",
            "error_message", "is_anomaly", "anomaly_type",
        )
        .write.format("jdbc")
        .option("url", CLICKHOUSE_URL)
        .option("driver", "com.clickhouse.jdbc.ClickHouseDriver")
        .option("dbtable", CLICKHOUSE_TABLE)
        .option("user", "default")
        .option("password", "")
        .mode("append")
        .save()
    )

    print(f"✅ Batch {batch_id} записан в ClickHouse ({final_df.count()} строк).")
    batch_df.unpersist()

query = unified_df.writeStream.foreachBatch(write_to_clickhouse).outputMode("append").option("checkpointLocation", CHECKPOINT_DIR).trigger(processingTime="15 seconds").start()
query.awaitTermination()
```

### spark/Dockerfile

```
FROM apache/spark:3.4.1

USER root

RUN apt-get update && apt-get install -y python3-pip && \
    pip install --no-cache-dir kafka-python clickhouse-driver pyspark geoip2

WORKDIR /opt/spark-apps

COPY . /opt/spark-apps

CMD ["/opt/spark/bin/spark-submit", \
     "--packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.4.1,com.clickhouse:clickhouse-jdbc:0.4.6", \
     "/opt/spark-apps/spark_processor.py"]
```

