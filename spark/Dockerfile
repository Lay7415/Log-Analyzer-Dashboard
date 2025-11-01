FROM apache/spark:3.4.1

USER root

RUN apt-get update && apt-get install -y python3-pip build-essential libssl-dev libffi-dev python3-dev && \
    pip install --no-cache-dir kafka-python clickhouse-driver pyspark geoip2 prophet

WORKDIR /opt/spark-apps

COPY . /opt/spark-apps

CMD ["/opt/spark/bin/spark-submit", \
     "--packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.4.1,com.clickhouse:clickhouse-jdbc:0.4.6", \
     "/opt/spark-apps/spark_processor.py"]