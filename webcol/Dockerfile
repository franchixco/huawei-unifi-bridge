FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
RUN uv pip install --system --no-cache playwright==1.49.0
WORKDIR /app
COPY webcol.py huawei_api.py inventory.py webonly.py operations.py operation_service.py /app/
ENV PYTHONUNBUFFERED=1
EXPOSE 7560
CMD ["python", "webcol.py"]
