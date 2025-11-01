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