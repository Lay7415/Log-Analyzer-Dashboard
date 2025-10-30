# streamlit/Dockerfile

FROM python:3.11-slim

# Устанавливаем все библиотеки одним слоем
RUN pip install --no-cache-dir streamlit pandas clickhouse-driver plotly pycountry-convert

WORKDIR /app
COPY dashboard.py /app/dashboard.py

EXPOSE 8501
CMD ["streamlit", "run", "dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]