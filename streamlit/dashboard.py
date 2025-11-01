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
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
    ["📈 Обзор и динамика", "🌍 Гео-аналитика", "🚦 Топ-листы и статусы", "🚨 Детекция аномалий", "🔧 Анализ ошибок сервера", "🔮 Прогнозирование и Рекомендации"]
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
        
with tab6:
    st.subheader("Прогноз нагрузки на сервер (запросов в час)")
    
    # 1. Загружаем фактические данные за последние 3 дня
    actuals_query = """
    SELECT toStartOfHour(timestamp) as hour, count() as actual_requests
    FROM nginx_logs
    WHERE log_type = 'access' AND timestamp >= now() - INTERVAL 3 DAY
    GROUP BY hour ORDER BY hour
    """
    df_actuals = run_query(CLIENT, actuals_query)
    
    # 2. Загружаем прогнозные данные
    predictions_query = "SELECT timestamp as hour, predicted_requests, predicted_lower, predicted_upper FROM nginx_predictions ORDER BY hour"
    df_predictions = run_query(CLIENT, predictions_query)

    if not df_actuals.empty and not df_predictions.empty:
        # --- Блок предписывающей аналитики ---
        CRITICAL_LOAD_THRESHOLD = df_actuals['actual_requests'].quantile(0.95) # Порог = 95-й перцентиль исторической нагрузки
        
        future_predictions = df_predictions[df_predictions['hour'] > datetime.now()]
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
        line = alt.Chart(source).mark_line(point=True).encode(
            x=alt.X('hour:T', title='Время'),
            y=alt.Y('requests:Q', title='Количество запросов'),
            color=alt.Color('type:N', title='Тип данных'),
            tooltip=[
                alt.Tooltip('hour:T', title='Время'),
                alt.Tooltip('requests:Q', title='Запросов', format=',.0f'),
                alt.Tooltip('type:N', title='Тип')
            ]
        ).properties(
             title='Сравнение фактической нагрузки и прогноза'
        )

        # Область неопределенности для прогноза
        band = alt.Chart(df_predictions).mark_area(opacity=0.3).encode(
            x=alt.X('hour:T'),
            y=alt.Y('predicted_lower:Q'),
            y2='predicted_upper:Q',
            tooltip=[
                alt.Tooltip('hour:T', title='Время'),
                alt.Tooltip('predicted_lower:Q', title='Мин. прогноз', format=',.0f'),
                alt.Tooltip('predicted_upper:Q', title='Макс. прогноз', format=',.0f')
            ]
        ).properties(
            title='Доверительный интервал прогноза'
        )
        
        st.altair_chart((band + line).interactive(), use_container_width=True)

    else:
        st.warning("Нет данных для построения прогноза. Сначала необходимо запустить скрипты обучения и генерации прогнозов.")