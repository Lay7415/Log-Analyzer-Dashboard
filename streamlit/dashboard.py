import streamlit as st
import pandas as pd
from clickhouse_driver import Client
import plotly.express as px
import pycountry_convert as pc
from datetime import datetime, timedelta

st.set_page_config(page_title="Log Dashboard", layout="wide")

CLIENT = Client(host="clickhouse", port=9000)


def run_query(query):
    """Выполняет запрос к ClickHouse и возвращает данные."""
    try:
        data, columns = CLIENT.execute(query, with_column_types=True)
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


st.title("📊 Комплексная аналитика логов веб-сервера")


st.sidebar.title("Фильтры")


min_max_time = run_query("SELECT min(timestamp), max(timestamp) FROM nginx_logs")
if not min_max_time.empty and min_max_time.iloc[0, 0] is not None:
    min_ts = min_max_time.iloc[0, 0]
    max_ts = min_max_time.iloc[0, 1]

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


statuses_df = run_query(
    "SELECT DISTINCT status FROM nginx_logs WHERE status IS NOT NULL ORDER BY status"
)
countries_df = run_query(
    "SELECT DISTINCT country FROM nginx_logs WHERE country IS NOT NULL AND country != 'Unknown' AND country != 'Error' ORDER BY country"
)
methods_df = run_query(
    "SELECT DISTINCT method FROM nginx_logs WHERE method != '' ORDER BY method"
)

all_statuses = statuses_df["status"].tolist()
all_countries = countries_df["country"].tolist()
all_methods = methods_df["method"].tolist()

selected_statuses = st.sidebar.multiselect(
    "Статус ответа", all_statuses, default=all_statuses
)
selected_countries = st.sidebar.multiselect(
    "Страна", all_countries, default=all_countries
)
selected_methods = st.sidebar.multiselect(
    "Метод запроса", all_methods, default=all_methods
)

if st.sidebar.button("🔄 Обновить данные"):
    st.rerun()


where_clauses = [
    f"timestamp BETWEEN toDateTime('{start_time}') AND toDateTime('{end_time}')"
]
if selected_statuses:
    where_clauses.append(f"status IN {tuple(selected_statuses)}")
if selected_countries:
    where_clauses.append(f"country IN {tuple(selected_countries)}")
if selected_methods:
    where_clauses.append(f"method IN {tuple(selected_methods)}")

where_sql = " AND ".join(where_clauses)
if where_sql:
    where_sql = "WHERE " + where_sql


kpi_query = f"""
SELECT
    count() as total,
    uniq(ip) as unique_ips,
    avg(bytes) as avg_bytes,
    (countIf(status >= 500) / toFloat64(countIf(true))) * 100 as server_error_rate,
    (countIf(status >= 400 AND status < 500) / toFloat64(countIf(true))) * 100 as client_error_rate
FROM nginx_logs
{where_sql} AND log_type = 'access'
"""
kpi_df = run_query(kpi_query)
if not kpi_df.empty:
    kpi_data = kpi_df.iloc[0]
    total_requests = kpi_data.get("total", 0)
    unique_ips = kpi_data.get("unique_ips", 0)
    avg_bytes = kpi_data.get("avg_bytes", 0)
    server_error_rate = kpi_data.get("server_error_rate", 0.0)
    client_error_rate = kpi_data.get("client_error_rate", 0.0)
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
kpi3.metric("Средний ответ (байт)", f"{int(avg_bytes):,}")
kpi4.metric("Ошибки клиента (4xx %)", f"{client_error_rate:.2f}%")
kpi5.metric("Ошибки сервера (5xx %)", f"{server_error_rate:.2f}%")
st.markdown("---")


tab1, tab2, tab3, tab4, tab5 = st.tabs(
    [
        "📈 Обзор и динамика",
        "🌍 Гео-аналитика",
        "🚦 Топ-листы и статусы",
        "🚨 Детекция аномалий",
        "🔧 Анализ ошибок сервера",
    ]
)

with tab1:
    st.subheader("Динамика запросов по минутам")
    time_series_query = f"""
    SELECT
        toStartOfMinute(timestamp) as minute,
        count() as total_requests,
        countIf(status >= 400) as error_requests
    FROM nginx_logs
    {where_sql} AND log_type = 'access'
    GROUP BY minute ORDER BY minute
    """
    df_time = run_query(time_series_query)
    if not df_time.empty:
        st.line_chart(df_time.set_index("minute"))

with tab2:
    st.subheader("Карта запросов по странам")
    country_query = (
        f"SELECT country, count() as cnt FROM nginx_logs {where_sql} GROUP BY country"
    )
    df_country = run_query(country_query)
    if not df_country.empty:
        df_country["iso_alpha"] = df_country["country"].apply(get_country_iso_alpha3)
        df_country = df_country.dropna(subset=["iso_alpha"])
        fig = px.choropleth(
            df_country,
            locations="iso_alpha",
            color="cnt",
            hover_name="country",
            color_continuous_scale=px.colors.sequential.Plasma,
            title="Количество запросов по странам",
        )
        st.plotly_chart(fig, use_container_width=True)

with tab3:
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Топ 10 страниц")
        pages_df = run_query(
            f"SELECT page, count() AS hits FROM nginx_logs {where_sql} AND log_type = 'access' GROUP BY page ORDER BY hits DESC LIMIT 10"
        )
        if not pages_df.empty:
            st.dataframe(pages_df, use_container_width=True)

        st.subheader("Топ 10 IP по ошибкам")
        ip_errors_df = run_query(
            f"SELECT ip, count() as errors FROM nginx_logs {where_sql} AND log_type = 'access' AND status >= 400 GROUP BY ip ORDER BY errors DESC LIMIT 10"
        )
        if not ip_errors_df.empty:
            st.dataframe(ip_errors_df, use_container_width=True)

    with col2:
        st.subheader("Распределение по статусам")
        status_df = run_query(
            f"SELECT status, count() AS cnt FROM nginx_logs {where_sql} AND log_type = 'access' GROUP BY status ORDER BY status"
        )
        if not status_df.empty:
            fig = px.pie(
                status_df, names="status", values="cnt", title="Статусы ответов"
            )
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Распределение по методам")
        method_df = run_query(
            f"SELECT method, count() AS cnt FROM nginx_logs {where_sql} AND log_type = 'access' GROUP BY method"
        )
        if not method_df.empty:
            fig_meth = px.pie(
                method_df, names="method", values="cnt", title="Методы запросов"
            )
            st.plotly_chart(fig_meth, use_container_width=True)

with tab4:
    st.subheader("🚨 Обнаруженные аномалии")
    anomaly_query = f"SELECT ip, country, anomaly_type, max(timestamp) as last_seen, count() as request_count FROM nginx_logs WHERE is_anomaly = 1 GROUP BY ip, country, anomaly_type ORDER BY last_seen DESC LIMIT 20"
    df_anomalies = run_query(anomaly_query)
    if not df_anomalies.empty:
        st.dataframe(df_anomalies, use_container_width=True)
    else:
        st.info("Аномальная активность не обнаружена.")

with tab5:
    st.subheader("Последние ошибки сервера")
    error_query = f"""
    SELECT timestamp, ip, country, log_level, error_message
    FROM nginx_logs
    WHERE log_type = 'error' AND {where_clauses[0]}
    ORDER BY timestamp DESC
    LIMIT 100
    """
    df_errors = run_query(error_query)
    if not df_errors.empty:
        st.dataframe(df_errors, use_container_width=True)
    else:
        st.info("Ошибки сервера не найдены в выбранном диапазоне.")
