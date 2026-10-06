# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="apkguard" \
      org.opencontainers.image.description="Static security scanner for Android APKs" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels \
    && useradd --create-home --uid 10001 apkguard
USER apkguard
WORKDIR /work
ENTRYPOINT ["apkguard"]
CMD ["--help"]
