FROM python:3.10-slim

WORKDIR /app

COPY requirements_flask.txt .

RUN pip install --no-cache-dir -r requirements_flask.txt

COPY . .

EXPOSE 80

CMD ["python", "app.py"]