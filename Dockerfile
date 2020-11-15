FROM python:3 AS builder
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3-slim
WORKDIR /usr/src/app
COPY --from=builder /root/.local /root/.local
COPY . .
ENV PATH=/root/local/:$PATH
CMD [ "python", "./proxy.py" ]
