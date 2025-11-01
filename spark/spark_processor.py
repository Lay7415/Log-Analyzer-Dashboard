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