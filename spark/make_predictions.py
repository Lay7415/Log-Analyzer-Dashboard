import pandas as pd
from clickhouse_driver import Client
import pickle
import os

CLICKHOUSE_HOST = "clickhouse"
MODEL_DIR = "/opt/spark-apps/model"
MODEL_PATH = os.path.join(MODEL_DIR, "prophet_model.pkl")
PREDICTIONS_TABLE = "nginx_predictions"

print("--- Начало генерации прогнозов ---")


print(f"Загрузка модели из файла: {MODEL_PATH}")
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)
print("✅ Модель загружена.")


future = model.make_future_dataframe(periods=24, freq="H")
forecast = model.predict(future)
print("✅ Прогноз сгенерирован.")


forecast_to_save = forecast[["ds", "yhat", "yhat_lower", "yhat_upper"]].copy()
forecast_to_save.rename(
    columns={
        "ds": "timestamp",
        "yhat": "predicted_requests",
        "yhat_lower": "predicted_lower",
        "yhat_upper": "predicted_upper",
    },
    inplace=True,
)


now = pd.Timestamp.now().tz_localize(None)
forecast_to_save = forecast_to_save[forecast_to_save["timestamp"] > now]


client = Client(host=CLICKHOUSE_HOST)
print(f"Подключение к ClickHouse для сохранения в таблицу {PREDICTIONS_TABLE}...")


client.execute(f"TRUNCATE TABLE {PREDICTIONS_TABLE}")
print("Старые прогнозы удалены.")

client.execute(
    f"INSERT INTO {PREDICTIONS_TABLE} VALUES", forecast_to_save.to_dict("records")
)
print(f"✅ {len(forecast_to_save)} строк прогноза сохранено в ClickHouse.")

print("--- Генерация прогнозов завершена ---")
