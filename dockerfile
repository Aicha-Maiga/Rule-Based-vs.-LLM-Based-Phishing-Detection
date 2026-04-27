FROM python:3.11-slim

WORKDIR /app

COPY packages.txt .
RUN pip install -r packages.txt

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]