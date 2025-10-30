# streamlit/dashboard.py

import streamlit as st
import pandas as pd
from clickhouse_driver import Client
import plotly.express as px
import pycountry_convert as pc

st.set_page_config(page_title="Real-Time Log Dashboard", layout="wide")
CLIENT = Client(host='clickhouse', port=9000)

def run_query(query):
    """Выполняет запрос к ClickHouse и возвращает данные."""
    try:
        data, columns = CLIENT.execute(query, with_column_types=True)
        column_names = [col[0] for col in columns]
        return data, column_names
    except Exception as e:
        st.error(f"Ошибка выполнения SQL-запроса:")
        st.code(query)
        st.error(e)
        return [], []

def get_country_iso_alpha3(country_name):
    """Преобразует название страны в ISO Alpha-3 код для карты."""
    try:
        return pc.country_name_to_country_alpha3(country_name)
    except:
        return None

st.sidebar.title("Фильтры")

if st.sidebar.button('🔄 Обновить данные'):
    st.rerun()

statuses_data, _ = run_query("SELECT DISTINCT status FROM nginx_logs ORDER BY status")
countries_data, _ = run_query("SELECT DISTINCT country FROM nginx_logs WHERE country IS NOT NULL AND country != 'Unknown' AND country != 'Error' ORDER BY country")
all_statuses = [s[0] for s in statuses_data]
all_countries = [c[0] for c in countries_data]

selected_statuses = st.sidebar.multiselect("Статус ответа", all_statuses, default=all_statuses)
selected_countries = st.sidebar.multiselect("Страна", all_countries, default=all_countries)

where_clauses = []
if selected_statuses:
    where_clauses.append(f"status IN {tuple(selected_statuses) if len(selected_statuses) > 1 else f'({selected_statuses[0]})'}")
if selected_countries:
    if len(selected_countries) > 1:
        where_clauses.append(f"country IN {tuple(selected_countries)}")
    else:
        where_clauses.append(f"country IN ('{selected_countries[0]}')")

where_sql = " AND ".join(where_clauses)
if where_sql:
    where_sql = "WHERE " + where_sql

st.title("📊 Аналитическая панель логов веб-сервера")

kpi_query = f"""
SELECT
    count() as total,
    uniq(ip) as unique_ips,
    (countIf(status >= 400) / toFloat64(countIf(true))) * 100 as error_rate
FROM nginx_logs {where_sql}
"""
kpi_data, _ = run_query(kpi_query)
total_requests, unique_ips, error_rate = kpi_data[0] if kpi_data and kpi_data[0][2] is not None else (0, 0, 0.0)
kpi1, kpi2, kpi3 = st.columns(3)
kpi1.metric("Всего запросов", f"{total_requests:,}")
kpi2.metric("Уникальные посетители (IP)", f"{unique_ips:,}")
kpi3.metric("Уровень ошибок (%)", f"{error_rate:.2f}%")
st.markdown("---")


tab1, tab2, tab3, tab4 = st.tabs(["📈 Обзор и динамика", "🌍 Гео-аналитика и ошибки", "🚨 Детекция аномалий", "🔧 Конструктор отчетов"])

with tab1:
    st.subheader("Динамика запросов по минутам")
    time_series_query = f"""
    SELECT
        toStartOfMinute(timestamp) as minute,
        count() as total_requests,
        countIf(status >= 400) as error_requests
    FROM nginx_logs
    {where_sql}
    GROUP BY minute
    ORDER BY minute
    """
    time_data, time_cols = run_query(time_series_query)
    if time_data:
        df_time = pd.DataFrame(time_data, columns=time_cols)
        df_time = df_time.set_index('minute')
        st.line_chart(df_time)
    else:
        st.warning("Нет данных для отображения динамики.")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Топ 10 страниц")
        pages_data, pages_cols = run_query(f"SELECT request, count() AS hits FROM nginx_logs {where_sql} GROUP BY request ORDER BY hits DESC LIMIT 10")
        if pages_data:
            df_pages = pd.DataFrame(pages_data, columns=pages_cols).set_index('request')
            st.bar_chart(df_pages)

    with col2:
        st.subheader("Распределение по статусам")
        status_data, status_cols = run_query(f"SELECT status, count() AS cnt FROM nginx_logs {where_sql} GROUP BY status ORDER BY status")
        if status_data:
            df_status = pd.DataFrame(status_data, columns=status_cols)
            fig = px.pie(df_status, names='status', values='cnt', title='Распределение статусов ответа')
            st.plotly_chart(fig, use_container_width=True)

with tab2:
    st.subheader("Карта запросов по странам")
    country_query = f"SELECT country, count() as cnt FROM nginx_logs {where_sql} GROUP BY country"
    country_data, country_cols = run_query(country_query)

    if country_data:
        df_country = pd.DataFrame(country_data, columns=country_cols)
        df_country['iso_alpha'] = df_country['country'].apply(get_country_iso_alpha3)
        df_country = df_country.dropna(subset=['iso_alpha']) # Удаляем страны, которые не распознали

        fig = px.choropleth(df_country,
                            locations="iso_alpha",
                            color="cnt",
                            hover_name="country",
                            color_continuous_scale=px.colors.sequential.Plasma,
                            title="Количество запросов по странам")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("Нет данных для отображения карты.")

    st.subheader("Топ 10 страниц с ошибкой 404 (Not Found)")
    error_404_query = f"""
    SELECT request, count() as count
    FROM nginx_logs
    {'WHERE status = 404' if not where_sql else where_sql + ' AND status = 404'}
    GROUP BY request
    ORDER BY count DESC
    LIMIT 10
    """
    error_data, error_cols = run_query(error_404_query)
    if error_data:
        df_errors = pd.DataFrame(error_data, columns=error_cols)
        st.dataframe(df_errors, use_container_width=True)
    else:
        st.info("Страниц с ошибкой 404 не найдено.")

with tab3:
    st.subheader("🚨 Обнаруженные аномалии (подозрительная активность)")
    anomaly_query = "SELECT ip, country, max(timestamp) as last_seen, count() as request_count FROM nginx_logs WHERE is_anomaly = 1 GROUP BY ip, country ORDER BY last_seen DESC LIMIT 20"
    anomaly_data, anomaly_cols = run_query(anomaly_query)
    if anomaly_data:
        df_anomalies = pd.DataFrame(anomaly_data, columns=anomaly_cols)
        st.dataframe(df_anomalies, use_container_width=True)
    else:
        st.info("Аномальная активность не обнаружена.")

with tab4:
    st.subheader("🔍 Конструктор отчетов (Ad-hoc запросы)")
    dimensions = {
        'Страна': 'country', 'Страница': 'request', 'IP-адрес': 'ip',
        'Статус ответа': 'status', 'User Agent': 'agent'
    }
    metrics = {
        'Количество запросов': 'count()', 'Количество уникальных IP': 'uniq(ip)',
        'Средний размер ответа (bytes)': 'avg(bytes)'
    }

    c1, c2, c3 = st.columns(3)
    with c1:
        selected_dimension = st.selectbox("Сгруппировать по:", options=list(dimensions.keys()))
    with c2:
        selected_metric = st.selectbox("Рассчитать:", options=list(metrics.keys()))
    with c3:
        limit = st.number_input("Показать топ N:", min_value=5, max_value=50, value=10, step=5)

    if st.button('Сформировать отчет'):
        dimension_sql = dimensions[selected_dimension]
        metric_sql = metrics[selected_metric]
        
        ad_hoc_query = f"""
        SELECT {dimension_sql} AS dimension, {metric_sql} AS metric
        FROM nginx_logs {where_sql}
        GROUP BY dimension ORDER BY metric DESC LIMIT {limit}
        """
        st.info("Выполняется ваш запрос:")
        st.code(ad_hoc_query, language='sql')
        
        ad_hoc_data, ad_hoc_cols = run_query(ad_hoc_query)
        if ad_hoc_data:
            df_ad_hoc = pd.DataFrame(ad_hoc_data, columns=[selected_dimension, selected_metric])
            st.dataframe(df_ad_hoc, use_container_width=True)
            try:
                st.bar_chart(df_ad_hoc.set_index(selected_dimension))
            except Exception as e:
                st.warning(f"Не удалось построить график для этих данных. Ошибка: {e}")
        else:
            st.warning("По вашему запросу ничего не найдено.")