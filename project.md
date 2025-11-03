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
      bash -c "until curl -sS http://clickhouse:8123/ >/dev/null 2>&1; do echo 'waiting clickhouse...'; sleep 2; done;
      /opt/spark/bin/spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.4.1,com.clickhouse:clickhouse-jdbc:0.4.6 /opt/spark-apps/spark_processor.py"


  log_generator:
      image: python:3.11-slim
      container_name: log_generator
      volumes:
        - ./nginx/logs:/var/log/nginx
        - ./generate_logs.py:/app/generate_logs.py
      command: sh -c "pip install faker && python3 /app/generate_logs.py"
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
-- Dimension Tables
-- Using ReplacingMergeTree to handle deduplication automatically based on the ID.

CREATE TABLE IF NOT EXISTS dim_ip (
    ip_id UInt64,
    ip String,
    country LowCardinality(String)
) ENGINE = ReplacingMergeTree(ip_id)
ORDER BY ip_id;

CREATE TABLE IF NOT EXISTS dim_request (
    request_id UInt64,
    request Nullable(String),
    method LowCardinality(Nullable(String)),
    page Nullable(String),
    referrer Nullable(String)
) ENGINE = ReplacingMergeTree(request_id)
ORDER BY request_id;

CREATE TABLE IF NOT EXISTS dim_user_agent (
    agent_id UInt64,
    agent Nullable(String)
) ENGINE = ReplacingMergeTree(agent_id)
ORDER BY agent_id;

CREATE TABLE IF NOT EXISTS dim_anomaly_type (
    anomaly_type_id UInt64,
    anomaly_type String
) ENGINE = ReplacingMergeTree(anomaly_type_id)
ORDER BY anomaly_type_id;

CREATE TABLE IF NOT EXISTS dim_error_details (
    error_details_id UInt64,
    log_level LowCardinality(Nullable(String)),
    error_message Nullable(String)
) ENGINE = ReplacingMergeTree(error_details_id)
ORDER BY error_details_id;


-- Fact Table
CREATE TABLE IF NOT EXISTS fact_nginx_events (
    timestamp DateTime,
    log_type LowCardinality(String),

    ip_id UInt64,
    request_id Nullable(UInt64),
    agent_id Nullable(UInt64),
    error_details_id Nullable(UInt64),
    anomaly_type_id Nullable(UInt64),

    status Nullable(UInt16),
    bytes Nullable(UInt32),
    is_anomaly UInt8
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, ip_id);

-- Predictions table remains unchanged
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


st.set_page_config(page_title="Log Dashboard", layout="wide")


@st.cache_resource
def get_clickhouse_client():
    client = Client(host="clickhouse", port=9000)
    return client


CLIENT = get_clickhouse_client()


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

    try:
        return pc.country_name_to_country_alpha3(country_name)
    except:
        return None


st.title("📊 Комплексная аналитика логов веб-сервера (Star Schema)")


st.sidebar.title("Фильтры")
min_max_time_df = run_query(
    CLIENT, "SELECT min(timestamp), max(timestamp) FROM fact_nginx_events"
)
if not min_max_time_df.empty and min_max_time_df.iloc[0, 0] is not None:

    min_dt = min_max_time_df.iloc[0, 0].to_pydatetime()
    max_dt = min_max_time_df.iloc[0, 1].to_pydatetime()
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


statuses_df = run_query(
    CLIENT,
    "SELECT DISTINCT status FROM fact_nginx_events WHERE status IS NOT NULL ORDER BY status",
)
countries_df = run_query(
    CLIENT,
    "SELECT DISTINCT country FROM dim_ip WHERE country IS NOT NULL AND country != 'Unknown' AND country != 'Error' ORDER BY country",
)
methods_df = run_query(
    CLIENT,
    "SELECT DISTINCT method FROM dim_request WHERE method IS NOT NULL AND method != '' ORDER BY method",
)

all_statuses = statuses_df["status"].tolist() if not statuses_df.empty else []
all_countries = countries_df["country"].tolist() if not countries_df.empty else []
all_methods = methods_df["method"].tolist() if not methods_df.empty else []

selected_statuses = st.sidebar.multiselect(
    "Статус ответа", all_statuses, default=all_statuses
)
selected_countries = st.sidebar.multiselect(
    "Страна", all_countries, default=all_countries
)
selected_methods = st.sidebar.multiselect(
    "Метод запроса", all_methods, default=all_methods
)

if st.sidebar.button("🔄 Применить фильтры и обновить"):
    st.rerun()


FROM_SQL = """
FROM fact_nginx_events f
LEFT JOIN dim_ip ip ON f.ip_id = ip.ip_id
LEFT JOIN dim_request req ON f.request_id = req.request_id
LEFT JOIN dim_user_agent ua ON f.agent_id = ua.agent_id
LEFT JOIN dim_error_details ed ON f.error_details_id = ed.error_details_id
LEFT JOIN dim_anomaly_type at ON f.anomaly_type_id = at.anomaly_type_id
"""


where_clauses = [
    f"f.timestamp BETWEEN toDateTime('{start_time}') AND toDateTime('{end_time}')"
]
if selected_statuses and len(selected_statuses) != len(all_statuses):
    where_clauses.append(f"f.status IN {tuple(selected_statuses)}")
if selected_countries and len(selected_countries) != len(all_countries):
    where_clauses.append(f"ip.country IN {tuple(selected_countries)}")
if selected_methods and len(selected_methods) != len(all_methods):
    where_clauses.append(f"req.method IN {tuple(selected_methods)}")

where_sql = "WHERE " + " AND ".join(where_clauses)


access_where_clauses = ["f.log_type = 'access'"] + where_clauses
access_where_sql = "WHERE " + " AND ".join(access_where_clauses)


kpi_query = f"""
SELECT
    count() as total,
    uniq(ip.ip) as unique_ips,
    avg(f.bytes) as avg_bytes,
    (countIf(f.status >= 500) / toFloat64(countIf(true))) * 100 as server_error_rate,
    (countIf(f.status >= 400 AND f.status < 500) / toFloat64(countIf(true))) * 100 as client_error_rate
{FROM_SQL}
{access_where_sql}
"""
kpi_df = run_query(CLIENT, kpi_query)
if not kpi_df.empty:

    kpi_data = kpi_df.iloc[0]
    total_requests, unique_ips, avg_bytes, server_error_rate, client_error_rate = (
        kpi_data.get("total", 0),
        kpi_data.get("unique_ips", 0),
        kpi_data.get("avg_bytes", 0),
        kpi_data.get("server_error_rate", 0.0),
        kpi_data.get("client_error_rate", 0.0),
    )
else:
    total_requests, unique_ips, avg_bytes, server_error_rate, client_error_rate = (
        0,
        0,
        0,
        0.0,
        0.0,
    )

kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
kpi1.metric("Всего запросов", f"{total_requests:,}")
kpi2.metric("Уникальные IP", f"{unique_ips:,}")
kpi3.metric("Средний ответ (байт)", f"{int(avg_bytes or 0):,}")
kpi4.metric("Ошибки клиента (4xx %)", f"{client_error_rate or 0:.2f}%")
kpi5.metric("Ошибки сервера (5xx %)", f"{server_error_rate or 0:.2f}%")
st.markdown("---")


tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
    [
        "📈 Обзор и динамика",
        "🌍 Гео-аналитика",
        "🚦 Топ-листы и статусы",
        "🚨 Детекция аномалий",
        "🔧 Анализ ошибок сервера",
        "🔮 Прогнозирование и Рекомендации",
    ]
)


with tab1:
    st.subheader("Динамика запросов по типам ответов (Stacked Area Chart)")
    time_series_query_stacked = f"""
    SELECT
        toStartOfMinute(f.timestamp) as minute,
        countIf(f.status >= 200 AND f.status < 300) as success_2xx,
        countIf(f.status >= 300 AND f.status < 400) as redirects_3xx,
        countIf(f.status >= 400 AND f.status < 500) as client_errors_4xx,
        countIf(f.status >= 500) as server_errors_5xx
    {FROM_SQL}
    {access_where_sql}
    GROUP BY minute ORDER BY minute
    """
    df_time_stacked = run_query(CLIENT, time_series_query_stacked)
    if not df_time_stacked.empty:
        st.area_chart(df_time_stacked.set_index("minute"))

    st.subheader("Динамика среднего размера ответа (в байтах)")
    avg_bytes_query = f"""
    SELECT
        toStartOfMinute(f.timestamp) as minute,
        avg(f.bytes) as avg_bytes
    {FROM_SQL}
    {access_where_sql}
    GROUP BY minute ORDER BY minute
    """
    df_avg_bytes = run_query(CLIENT, avg_bytes_query)
    if not df_avg_bytes.empty:
        st.line_chart(df_avg_bytes.set_index("minute"))

with tab2:

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Карта запросов по странам")

        country_query = f"""
        SELECT
            ip.country AS country,
            count() as cnt
        {FROM_SQL}
        {where_sql}
            AND ip.country IS NOT NULL
            AND ip.country != 'Unknown'
            AND ip.country != 'Error'
        GROUP BY ip.country
        """
        df_country = run_query(CLIENT, country_query)

        if not df_country.empty:

            df_country["iso_alpha"] = df_country["country"].apply(
                get_country_iso_alpha3
            )

            df_country = df_country.dropna(subset=["iso_alpha"])

            if not df_country.empty:

                fig_requests = px.choropleth(
                    df_country,
                    locations="iso_alpha",
                    color="cnt",
                    hover_name="country",
                    color_continuous_scale=px.colors.sequential.Plasma,
                    title="Количество запросов",
                )

                st.plotly_chart(fig_requests, use_container_width=True)
            else:
                st.warning(
                    "Не удалось определить ISO-коды для стран в выбранном диапазоне."
                )
        else:
            st.info("Нет данных о запросах по странам для выбранных фильтров.")

    with col2:
        st.subheader("Карта уровня ошибок по странам")

        country_error_query = f"""
        SELECT
            ip.country AS country,
            countIf(f.status >= 400) as error_count,
            count() as total_count,
            (error_count / toFloat64(total_count)) * 100 as error_rate
        {FROM_SQL}
        {where_sql}
            AND ip.country IS NOT NULL
            AND ip.country != 'Unknown'
            AND ip.country != 'Error'
        GROUP BY ip.country
        HAVING total_count > 0
        """
        df_country_errors = run_query(CLIENT, country_error_query)

        if not df_country_errors.empty:

            df_country_errors["iso_alpha"] = df_country_errors["country"].apply(
                get_country_iso_alpha3
            )
            df_country_errors = df_country_errors.dropna(subset=["iso_alpha"])

            if not df_country_errors.empty:
                fig_errors = px.choropleth(
                    df_country_errors,
                    locations="iso_alpha",
                    color="error_rate",
                    hover_name="country",
                    color_continuous_scale=px.colors.sequential.Reds,
                    title="Процент ошибок (%)",
                )
                st.plotly_chart(fig_errors, use_container_width=True)

        else:
            st.info("Нет данных об ошибках по странам для выбранных фильтров.")

    st.subheader("Таблица с гео-данными и ошибками")

    if not df_country_errors.empty:
        st.dataframe(
            df_country_errors[
                ["country", "total_count", "error_count", "error_rate"]
            ].sort_values("error_rate", ascending=False),
            use_container_width=True,
            hide_index=True,
        )


with tab3:
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Топ 10 страниц по запросам")

        pages_df = run_query(
            CLIENT,
            f"SELECT req.page AS page, count() AS hits {FROM_SQL} {access_where_sql} GROUP BY req.page ORDER BY hits DESC LIMIT 10",
        )
        st.dataframe(pages_df, use_container_width=True)

        st.subheader("Топ 10 IP по объему трафика (MB)")

        ip_traffic_df = run_query(
            CLIENT,
            f"SELECT ip.ip AS ip, sum(f.bytes) / 1024 / 1024 as total_mb {FROM_SQL} {access_where_sql} GROUP BY ip.ip ORDER BY total_mb DESC LIMIT 10",
        )
        if not ip_traffic_df.empty:
            st.bar_chart(ip_traffic_df.set_index("ip"))

    with col2:
        st.subheader("Распределение по статусам")

        status_df = run_query(
            CLIENT,
            f"SELECT f.status AS status, count() AS cnt {FROM_SQL} {access_where_sql} GROUP BY f.status ORDER BY f.status",
        )
        if not status_df.empty:
            fig = px.pie(
                status_df, names="status", values="cnt", title="Статусы ответов"
            )
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Топ 10 IP по ошибкам")
        error_ip_where_clauses = ["f.status >= 400"] + access_where_clauses[1:]
        error_ip_where_sql = "WHERE " + " AND ".join(error_ip_where_clauses)

        ip_errors_df = run_query(
            CLIENT,
            f"SELECT ip.ip AS ip, count() as errors {FROM_SQL} {error_ip_where_sql} GROUP BY ip.ip ORDER BY errors DESC LIMIT 10",
        )
        st.dataframe(ip_errors_df, use_container_width=True)

    st.subheader("Тепловая карта ошибок: Страница vs Статус")

    heatmap_query = f"""
    SELECT req.page AS page, f.status AS status, count() as count
    {FROM_SQL}
    {where_sql}
    AND req.page IN (SELECT req.page FROM fact_nginx_events f LEFT JOIN dim_request req ON f.request_id = req.request_id {where_sql} GROUP BY req.page ORDER BY count() DESC LIMIT 15)
    AND f.status >= 400
    GROUP BY req.page, f.status
    """

    heatmap_df = run_query(CLIENT, heatmap_query)
    if not heatmap_df.empty:
        heatmap_pivot = heatmap_df.pivot_table(
            index="page", columns="status", values="count"
        ).fillna(0)
        fig_heatmap = px.imshow(
            heatmap_pivot,
            text_auto=True,
            aspect="auto",
            color_continuous_scale="Reds",
            labels=dict(x="HTTP Статус", y="Страница", color="Кол-во ошибок"),
        )
        st.plotly_chart(fig_heatmap, use_container_width=True)


with tab4:
    st.subheader("Обнаруженные аномалии")
    anomaly_where = f"WHERE f.timestamp BETWEEN toDateTime('{start_time}') AND toDateTime('{end_time}') AND f.is_anomaly = 1"

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Временная шкала аномалий (Timeline)")

        anomaly_timeline_query = f"""
        SELECT
            f.timestamp AS timestamp,
            ip.ip AS ip,
            at.anomaly_type AS anomaly_type
        {FROM_SQL} {anomaly_where} AND at.anomaly_type != ''
        ORDER BY f.timestamp DESC LIMIT 500
        """
        df_anomalies_timeline = run_query(CLIENT, anomaly_timeline_query)
        if not df_anomalies_timeline.empty:

            fig_timeline = px.scatter(
                df_anomalies_timeline,
                x="timestamp",
                y="ip",
                color="anomaly_type",
                title="Временная шкала аномальной активности",
                labels={
                    "timestamp": "Время",
                    "ip": "IP адрес атакующего",
                    "anomaly_type": "Тип аномалии",
                },
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("Аномальная активность не обнаружена в выбранном диапазоне.")

    with col2:
        st.subheader("Распределение по типам аномалий")

        anomaly_pie_query = f"""
        SELECT at.anomaly_type AS anomaly_type, count() as cnt
        {FROM_SQL} {anomaly_where} AND at.anomaly_type != ''
        GROUP BY at.anomaly_type
        """
        df_anomaly_pie = run_query(CLIENT, anomaly_pie_query)
        if not df_anomaly_pie.empty:
            fig_pie = px.pie(df_anomaly_pie, names="anomaly_type", values="cnt")
            st.plotly_chart(fig_pie, use_container_width=True)

    st.subheader("Сводная таблица по аномалиям")

    anomaly_table_query = f"""
    SELECT
        ip.ip AS ip,
        ip.country AS country,
        at.anomaly_type AS anomaly_type,
        max(f.timestamp) as last_seen,
        count() as request_count
    {FROM_SQL} {anomaly_where} AND at.anomaly_type != ''
    GROUP BY ip.ip, ip.country, at.anomaly_type
    ORDER BY last_seen DESC LIMIT 20
    """
    df_anomalies_table = run_query(CLIENT, anomaly_table_query)
    if not df_anomalies_table.empty:
        st.dataframe(df_anomalies_table, use_container_width=True)


with tab5:
    st.subheader("Анализ логов ошибок")
    error_where = f"WHERE f.log_type = 'error' AND f.timestamp BETWEEN toDateTime('{start_time}') AND toDateTime('{end_time}')"

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Топ 10 сообщений об ошибках")

        top_errors_query = f"""
        SELECT ed.error_message AS error_message, count() as cnt
        {FROM_SQL} {error_where}
        GROUP BY ed.error_message ORDER BY cnt DESC LIMIT 10
        """
        df_top_errors = run_query(CLIENT, top_errors_query)
        if not df_top_errors.empty:
            fig_top_errors = px.bar(
                df_top_errors,
                x="cnt",
                y="error_message",
                orientation="h",
                title="Самые частые ошибки",
            )
            st.plotly_chart(fig_top_errors, use_container_width=True)

    with col2:

        st.subheader("Динамика ошибок по уровням (error/warn)")
        error_level_query = f"""
        SELECT
            toStartOfMinute(f.timestamp) as minute,
            countIf(ed.log_level = 'error') as errors,
            countIf(ed.log_level = 'warn') as warnings
        {FROM_SQL} {error_where}
        GROUP BY minute ORDER BY minute
        """
        df_error_level = run_query(CLIENT, error_level_query)
        if not df_error_level.empty and (
            df_error_level["errors"].sum() > 0 or df_error_level["warnings"].sum() > 0
        ):
            st.line_chart(df_error_level.set_index("minute"))

    st.subheader("Последние 100 ошибок сервера")

    errors_table_query = f"""
    SELECT
        f.timestamp AS timestamp,
        ip.ip AS ip,
        ip.country AS country,
        ed.log_level AS log_level,
        ed.error_message AS error_message
    {FROM_SQL} {error_where}
    ORDER BY f.timestamp DESC LIMIT 100
    """
    df_errors_table = run_query(CLIENT, errors_table_query)
    if not df_errors_table.empty:
        st.dataframe(df_errors_table, use_container_width=True)
    else:
        st.info("Ошибки сервера не найдены в выбранном диапазоне.")


with tab6:
    st.subheader("Прогноз нагрузки на сервер (запросов в час)")

    actuals_query = """
    SELECT toStartOfHour(timestamp) as hour, count() as actual_requests
    FROM fact_nginx_events
    WHERE log_type = 'access' AND timestamp >= now() - INTERVAL 3 DAY
    GROUP BY hour ORDER BY hour
    """
    df_actuals = run_query(CLIENT, actuals_query)

    predictions_query = "SELECT timestamp as hour, predicted_requests, predicted_lower, predicted_upper FROM nginx_predictions ORDER BY hour"
    df_predictions = run_query(CLIENT, predictions_query)

    if not df_actuals.empty and not df_predictions.empty:

        CRITICAL_LOAD_THRESHOLD = df_actuals["actual_requests"].quantile(0.95)

        future_predictions = df_predictions[df_predictions["hour"] > datetime.now()]
        if not future_predictions.empty:

            peak_prediction = future_predictions.sort_values(
                "predicted_upper", ascending=False
            ).iloc[0]

            st.info(
                f"**Прогноз:** Ожидается пиковая нагрузка **~{int(peak_prediction['predicted_requests'])}** запросов/час в **{peak_prediction['hour'].strftime('%Y-%m-%d %H:%M')}**."
            )

            if peak_prediction["predicted_upper"] > CRITICAL_LOAD_THRESHOLD:
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

            df_actuals["type"] = "Фактические данные"
            df_actuals.rename(columns={"actual_requests": "requests"}, inplace=True)

            df_pred_main = df_predictions[["hour", "predicted_requests"]].copy()
            df_pred_main["type"] = "Прогноз"
            df_pred_main.rename(
                columns={"predicted_requests": "requests"}, inplace=True
            )

            source = pd.concat([df_actuals[["hour", "requests", "type"]], df_pred_main])
            line = (
                alt.Chart(source)
                .mark_line()
                .encode(x="hour:T", y="requests:Q", color="type:N")
                .properties(title="Сравнение фактической нагрузки и прогноза")
            )

            band = (
                alt.Chart(df_predictions)
                .mark_area(opacity=0.3)
                .encode(x="hour:T", y="predicted_lower:Q", y2="predicted_upper:Q")
                .properties(title="Доверительный интервал прогноза")
            )

            st.altair_chart((band + line).interactive(), use_container_width=True)
        else:
            st.warning("Нет будущих прогнозов для отображения.")
    else:
        st.warning(
            "Нет данных для построения прогноза. Сначала необходимо запустить скрипты обучения и генерации прогнозов."
        )

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
    coalesce,
    xxhash64,
)
from pyspark.sql.types import StringType, StructType, StructField, IntegerType
import time
from pyspark.sql.utils import AnalysisException

KAFKA_BROKER = "kafka:9092"
TOPIC = "nginx_logs"
CHECKPOINT_DIR = "/tmp/spark_checkpoints_nginx"
CLICKHOUSE_URL = "jdbc:clickhouse://clickhouse:8123/default"
CLICKHOUSE_TABLE = "fact_nginx_events"
GEO_DB_PATH = "/opt/spark-apps/GeoLite2-Country.mmdb"

# Behavioral thresholds
REQUEST_RATE_THRESHOLD = 20
LOGIN_ATTACK_THRESHOLD = 10
SCANNING_THRESHOLD = 15

# Signature-based attack patterns
SQLI_PATTERN = r"('|%27|--|%2D%2D|union|%75%6E%69%6F%6E)"
PATH_TRAVERSAL_PATTERN = r"(\.\./|%2E%2E%2F)"
VULN_SCAN_PATTERN = r"(wp-admin|phpmyadmin|/.git|/solr)"
BAD_AGENT_PATTERN = r"(sqlmap|nikto|nmap|masscan)"


def ensure_topic():
    for i in range(10):
        try:
            admin = KafkaAdminClient(
                bootstrap_servers=KAFKA_BROKER, client_id="spark-topic-checker"
            )
            topic_list = [NewTopic(name=TOPIC, num_partitions=1, replication_factor=1)]
            admin.create_topics(new_topics=topic_list, validate_only=False)
            print(f"✅ Kafka topic '{TOPIC}' created.")
            admin.close()
            return
        except TopicAlreadyExistsError:
            print(f"ℹ️ Kafka topic '{TOPIC}' already exists.")
            admin.close()
            return
        except Exception as e:
            print(f"⚠️ Kafka is not ready yet ({e}), waiting...")
            time.sleep(5)
    print("❌ Could not create Kafka topic. Check Kafka logs.")


ensure_topic()

spark = (
    SparkSession.builder.appName("NginxLogProcessor")
    .config("spark.sql.streaming.checkpointLocation", CHECKPOINT_DIR)
    .getOrCreate()
)


@udf(StringType())
def get_country_from_ip(ip):
    try:
        if ip is None or str(ip).strip() == "":
            return "Unknown"
        with geoip2.database.Reader(GEO_DB_PATH) as reader:
            resp = reader.country(ip)
            return resp.country.name or "Unknown"
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return "Unknown"
    except Exception:
        return "Error"



kafka_schema = StructType(
    [StructField("message", StringType()), StructField("log_type", StringType())]
)
df = (
    spark.readStream.format("kafka")
    .option("kafka.bootstrap.servers", KAFKA_BROKER)
    .option("subscribe", TOPIC)
    .option("startingOffsets", "earliest")
    .load()
)
json_df = df.select(
    from_json(col("value").cast("string"), kafka_schema).alias("data")
).select("data.*")

access_pattern = (
    r'(\S+) - - \[(.*?)\] "(\S+)\s*(\S*)\s*(\S*)" (\d{3}) (\d+) "(.*?)" "(.*?)"'
)
error_pattern = r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] .*? client: (\S+), server: .*?, request: ".*?", (.*?), host: ".*?"'

access_logs = (
    json_df.filter(col("log_type") == "access")
    .select(
        regexp_extract("message", access_pattern, 1).alias("ip"),
        regexp_extract("message", access_pattern, 2).alias("time"),
        regexp_extract("message", access_pattern, 3).alias("method"),
        regexp_extract("message", access_pattern, 4).alias("page"),
        regexp_extract("message", access_pattern, 6).alias("status"),
        regexp_extract("message", access_pattern, 7).alias("bytes"),
        regexp_extract("message", access_pattern, 8).alias("referrer"),
        regexp_extract("message", access_pattern, 9).alias("agent"),
        lit("access").alias("log_type"),
    )
    .withColumn("request", col("page"))
    .withColumn("timestamp", to_timestamp(col("time"), "dd/MMM/yyyy:HH:mm:ss Z"))
    .withColumn("status", col("status").cast(IntegerType()))
    .withColumn("bytes", col("bytes").cast(IntegerType()))
    .withColumn("error_message", lit(None).cast(StringType()))
    .withColumn("log_level", lit(None).cast(StringType()))
    .drop("time")
)
error_logs = (
    json_df.filter(col("log_type") == "error")
    .select(
        regexp_extract("message", error_pattern, 1).alias("time"),
        regexp_extract("message", error_pattern, 2).alias("log_level"),
        regexp_extract("message", error_pattern, 3).alias("ip_raw"),
        regexp_extract("message", error_pattern, 4).alias("error_message"),
        lit("error").alias("log_type"),
    )
    .withColumn("ip", split(col("ip_raw"), ",")[0])
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
        lit(None).cast(IntegerType()).alias("status"),
        lit(None).cast(IntegerType()).alias("bytes"),
        lit(None).cast(StringType()).alias("referrer"),
        lit(None).cast(StringType()).alias("agent"),
    )
)
unified_df = access_logs.unionByName(error_logs).filter(col("ip") != "")


def write_dim_table(df, table_name, retries=3, delay=2):
    for i in range(retries):
        try:
            (
                df.write.format("jdbc")
                .option("url", CLICKHOUSE_URL)
                .option("driver", "com.clickhouse.jdbc.ClickHouseDriver")
                .option("dbtable", table_name)
                .option("user", "default")
                .option("password", "")
                .mode("append")
                .save()
            )
            return
        except Exception as e:
            print(f"Write to {table_name} failed (attempt {i+1}/{retries}): {e}")
            if i + 1 == retries:
                raise
            time.sleep(delay)


def write_to_clickhouse(batch_df, batch_id):
    if batch_df.rdd.isEmpty():
        print(f"⚠️ Empty batch {batch_id}, skipping.")
        return

    print(f"--- Processing Batch {batch_id} ---")
    batch_df.cache()

    # STAGE 1: Signature Analysis
    signature_df = batch_df.withColumn(
        "signature_anomaly_type",
        when(col("page").rlike(SQLI_PATTERN), "SQL Injection")
        .when(col("page").rlike(PATH_TRAVERSAL_PATTERN), "Path Traversal")
        .when(col("page").rlike(VULN_SCAN_PATTERN), "Vulnerability Scan")
        .when(col("agent").rlike(BAD_AGENT_PATTERN), "Bad User-Agent")
        .otherwise(lit(None)),
    )

    # STAGE 2: Behavioral Analysis
    behavioral_df = (
        batch_df.filter(col("log_type") == "access")
        .groupBy("ip")
        .agg(
            count("*").alias("request_count"),
            countDistinct("page").alias("distinct_pages"),
            count(when((col("page") == "/login") & (col("method") == "POST"), 1)).alias(
                "login_posts"
            ),
        )
        .withColumn(
            "behavioral_anomaly_type",
            when(col("login_posts") > LOGIN_ATTACK_THRESHOLD, "Login Attack")
            .when(col("distinct_pages") > SCANNING_THRESHOLD, "Scanning Activity")
            .when(col("request_count") > REQUEST_RATE_THRESHOLD, "Request Rate Anomaly")
            .otherwise(lit(None)),
        )
    )
    
    print("==== batch schema ====")
    batch_df.printSchema()
    batch_df.show(5, truncate=False)
    
    base_df = (
        signature_df.join(behavioral_df, "ip", "left")
        # объединяем сигнатуры и поведение
        .withColumn(
            "anomaly_type",
            coalesce(col("signature_anomaly_type"), col("behavioral_anomaly_type")),
        ).withColumn(
            "is_anomaly",
            when(col("anomaly_type").isNotNull(), lit(1)).otherwise(lit(0)),
        )
        # создаём country прямо здесь из ip — так мы точно гарантируем её наличие в схеме
        .withColumn("country", coalesce(get_country_from_ip(col("ip")), lit("Unknown")))
        # если нужно, обеспечим пустую строку для anomaly_type
        .withColumn("anomaly_type", coalesce(col("anomaly_type"), lit("")))
    )

    # STAGE 4: Extract and write dimensions
    dim_ip_df = (
        base_df.select("ip", "country")
        .distinct()
        .withColumn("country", coalesce(col("country"), lit("Unknown")))
        .withColumn("ip_id", xxhash64(col("ip")))
    )
    write_dim_table(dim_ip_df, "dim_ip")

    dim_request_df = (
        base_df.select("request", "method", "page", "referrer")
        .distinct()
        .withColumn("request_id", xxhash64("request", "method", "page", "referrer"))
    )
    write_dim_table(dim_request_df, "dim_request")

    dim_agent_df = (
        base_df.select("agent").distinct().withColumn("agent_id", xxhash64("agent"))
    )
    write_dim_table(dim_agent_df, "dim_user_agent")

    dim_error_df = (
        base_df.filter(col("log_type") == "error")
        .select("log_level", "error_message")
        .distinct()
        .withColumn("error_details_id", xxhash64("log_level", "error_message"))
    )
    if not dim_error_df.rdd.isEmpty():
        write_dim_table(dim_error_df, "dim_error_details")

    dim_anomaly_df = (
        base_df.filter(col("is_anomaly") == 1)
        .select("anomaly_type")
        .distinct()
        .withColumn("anomaly_type_id", xxhash64("anomaly_type"))
    )
    if not dim_anomaly_df.rdd.isEmpty():
        write_dim_table(dim_anomaly_df, "dim_anomaly_type")

    # STAGE 5: Join dimension IDs back to create the fact table
    fact_df = (
        base_df.join(dim_ip_df, ["ip", "country"], "left")
        .join(dim_request_df, ["request", "method", "page", "referrer"], "left")
        .join(dim_agent_df, "agent", "left")
        .join(dim_error_df, ["log_level", "error_message"], "left")
        .join(dim_anomaly_df, "anomaly_type", "left")
    )

    # STAGE 6: Write to the fact table
    (
        fact_df.select(
            "timestamp",
            "log_type",
            "ip_id",
            "request_id",
            "agent_id",
            "error_details_id",
            "anomaly_type_id",
            "status",
            "bytes",
            "is_anomaly",
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

    print(f"✅ Batch {batch_id} written to ClickHouse ({fact_df.count()} rows).")
    batch_df.unpersist()


query = (
    unified_df.writeStream.foreachBatch(write_to_clickhouse)
    .outputMode("append")
    .option("checkpointLocation", CHECKPOINT_DIR)
    .trigger(processingTime="15 seconds")
    .start()
)
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
import os

CLICKHOUSE_HOST = 'clickhouse'
MODEL_DIR = '/opt/spark-apps/model'
MODEL_PATH = os.path.join(MODEL_DIR, 'prophet_model.pkl')

print("--- Начало обучения модели прогнозирования ---")

# 1. Загрузка исторических данных из ClickHouse
print(f"Подключение к ClickHouse ({CLICKHOUSE_HOST})...")
client = Client(host=CLICKHOUSE_HOST)
# ИЗМЕНЕНИЕ: Запрос к новой таблице фактов
query = """
SELECT
    toStartOfHour(timestamp) as ds,
    count() as y
FROM fact_nginx_events
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

os.makedirs(MODEL_DIR, exist_ok=True)

with open(MODEL_PATH, 'wb') as f:
    pickle.dump(model, f)

print("--- Обучение модели завершено ---")
```

