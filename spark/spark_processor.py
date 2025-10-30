import time
import geoip2.database
from kafka.admin import KafkaAdminClient, NewTopic
from kafka.errors import TopicAlreadyExistsError
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf, col, lit, count, when, regexp_extract, to_timestamp
from pyspark.sql.types import StringType

KAFKA_BROKER = "kafka:9092"
TOPIC = "nginx_logs"
CHECKPOINT_DIR = "/tmp/spark_checkpoints_nginx"
CLICKHOUSE_URL = "jdbc:clickhouse://clickhouse:8123/default"
CLICKHOUSE_TABLE = "nginx_logs"
GEO_DB_PATH = "/opt/spark-apps/GeoLite2-Country.mmdb" # Путь к базе GeoIP
ANOMALY_THRESHOLD = 10

def ensure_topic():
    """Создаёт Kafka-топик, если его нет."""
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

spark = (
    SparkSession.builder
    .appName("NginxLogProcessor")
    .config("spark.sql.streaming.checkpointLocation", CHECKPOINT_DIR)
    .getOrCreate()
)

def get_country_from_ip(ip):
    """
    Определяет страну по IP-адресу с помощью базы GeoLite2.
    Обрабатывает приватные и некорректные IP.
    """
    try:
        with geoip2.database.Reader(GEO_DB_PATH) as reader:
            response = reader.country(ip)
            return response.country.name
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return "Unknown"
    except Exception:
        return "Error"

country_udf = udf(get_country_from_ip, StringType())

df = (
    spark.readStream
    .format("kafka")
    .option("kafka.bootstrap.servers", KAFKA_BROKER)
    .option("subscribe", TOPIC)
    .option("startingOffsets", "earliest") # Читаем с самого начала при каждом запуске
    .load()
)

lines = df.selectExpr("CAST(value AS STRING) as raw")
pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+) "(.*?)" "(.*?)"'

parsed = (
    lines.select(
        regexp_extract('raw', pattern, 1).alias('ip'),
        regexp_extract('raw', pattern, 2).alias('time'),
        regexp_extract('raw', pattern, 3).alias('request'),
        regexp_extract('raw', pattern, 4).alias('status'),
        regexp_extract('raw', pattern, 5).alias('bytes'),
        regexp_extract('raw', pattern, 6).alias('referrer'),
        regexp_extract('raw', pattern, 7).alias('agent')
    )
    .withColumn("timestamp", to_timestamp(col("time"), "dd/MMM/yyyy:HH:mm:ss Z"))
)

validated = parsed.filter((col("ip") != "") & (col("timestamp").isNotNull()))

def write_to_clickhouse(batch_df, batch_id):
    if not batch_df.rdd.isEmpty():
        print(f"--- Processing Batch {batch_id} ---")
        batch_df.cache()

        anomalies_in_batch = (
            batch_df.groupBy("ip")
            .agg(count("*").alias("requests_in_batch"))
            .withColumn("is_anomaly", when(col("requests_in_batch") > ANOMALY_THRESHOLD, 1).otherwise(0))
            .select("ip", "is_anomaly")
        )
        
        enriched_df = batch_df.withColumn("country", country_udf(col("ip")))
        
        final_df = (
            enriched_df.join(anomalies_in_batch, "ip", "left_outer")
            .withColumn("country", when(col("country").isNotNull(), col("country")).otherwise(lit("Unknown")))
            .withColumn("is_anomaly", when(col("is_anomaly").isNotNull(), col("is_anomaly")).otherwise(lit(0)))
            .select("ip", "time", "request", "status", "bytes", "referrer", "agent", "timestamp", "country", "is_anomaly")
        )
        
        (
            final_df.write
            .format("jdbc")
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
    else:
        print(f"⚠️ Пустой batch {batch_id}, пропущен.")

query = (
    validated.writeStream
    .foreachBatch(write_to_clickhouse)
    .outputMode("append")
    .option("checkpointLocation", CHECKPOINT_DIR)
    .trigger(processingTime='10 seconds')
    .start()
)

query.awaitTermination()