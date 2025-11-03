import pandas as pd
from prophet import Prophet
from clickhouse_driver import Client
import pickle
import os

CLICKHOUSE_HOST = "clickhouse"
MODEL_DIR = "/opt/spark-apps/model"
MODEL_PATH = os.path.join(MODEL_DIR, "prophet_model.pkl")

print("--- Начало обучения модели прогнозирования ---")


print(f"Подключение к ClickHouse ({CLICKHOUSE_HOST})...")
client = Client(host=CLICKHOUSE_HOST)

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

df["ds"] = pd.to_datetime(df["ds"])

if len(df) < 2:
    print("❌ Недостаточно данных для обучения. Требуется как минимум 2 точки.")
    exit()


print("Обучение модели Prophet...")
model = Prophet(daily_seasonality=True, weekly_seasonality=True)
model.fit(df)
print("✅ Модель успешно обучена.")


print(f"Сохранение модели в файл: {MODEL_PATH}")

os.makedirs(MODEL_DIR, exist_ok=True)

with open(MODEL_PATH, "wb") as f:
    pickle.dump(model, f)

print("--- Обучение модели завершено ---")
