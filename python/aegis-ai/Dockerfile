# Stage 1: Build Rust AEGIS Core
FROM rust:1.75-slim AS builder
WORKDIR /build
COPY crates/ ./crates/
COPY Cargo.toml ./
RUN cargo build --release --bin aegis

# Stage 2: Python Backend
FROM python:3.11-slim
WORKDIR /app

# Install system dependencies (curl for healthcheck, libssl for Rust binary)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Rust binary from builder
COPY --from=builder /build/target/release/aegis /usr/local/bin/aegis

# Copy packaging configuration
COPY python/aegis-ai/pyproject.toml ./

# Install python dependencies
RUN pip install --no-cache-dir fastapi uvicorn pydantic openai python-dotenv httpx sqlalchemy qdrant-client psycopg2-binary win11toast websockets slowapi

# Copy application source
COPY python/aegis-ai/src/ ./src/

# Expose API port
EXPOSE 8000

# Run the API
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
