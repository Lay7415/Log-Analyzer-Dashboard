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
