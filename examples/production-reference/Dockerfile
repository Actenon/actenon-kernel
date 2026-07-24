FROM python:3.12-slim

WORKDIR /app

# Install the kernel (in a real deployment, use the published wheel)
COPY pyproject.toml .
COPY actenon/ actenon/
COPY examples/production-reference/verifier_service.py .

RUN pip install --no-cache-dir -e ".[asymmetric,fastapi]" uvicorn

EXPOSE 8000

CMD ["python", "verifier_service.py"]
