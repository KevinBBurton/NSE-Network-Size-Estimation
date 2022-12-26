FROM python:3.10-slim

RUN pip install --upgrade pip
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

COPY . /app

CMD ["bash", "test.sh"]