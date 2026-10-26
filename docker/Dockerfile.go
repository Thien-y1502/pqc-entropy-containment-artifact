FROM golang:1.24.13-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build
WORKDIR /src
COPY src/go/go.mod src/go/main.go src/go/main_test.go ./
RUN gofmt -w main.go main_test.go \
    && go test ./... \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pair-worker .

FROM python:3.13-slim-bookworm@sha256:e32be0e55814a08977501ca863271d9bd02443710db8f2afaf8372e2c4508530
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 artifact \
    && useradd --uid 10001 --gid 10001 --create-home artifact \
    && mkdir -p /opt/p01 /data \
    && chown -R 10001:10001 /data
COPY --from=build /out/pair-worker /opt/p01/pair-worker
COPY runners/runner.py /opt/p01/confirmation_runner.py
COPY runners/benchmark_runner.py /opt/p01/benchmark_runner.py
COPY contracts/performance_contract.frozen.json /opt/p01/performance_contract.frozen.json
USER 10001:10001
ENTRYPOINT ["python", "/opt/p01/confirmation_runner.py", "--binary", "/opt/p01/pair-worker", "--implementation", "go-crypto-tls-go1.24.13"]
