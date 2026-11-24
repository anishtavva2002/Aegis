# Gateway image (the Docker-based sandbox runner needs a host Docker daemon and is not used here).
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY aegis ./aegis
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin aegis \
 && mkdir /data && chown aegis /data
COPY --from=build /install /usr/local
USER 10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
ENTRYPOINT ["aegis", "serve", "--host", "0.0.0.0", "--port", "8080", "--gateway-audit", "/data/audit.jsonl"]
CMD ["--gateway-policy", "/data/policy.yaml"]
