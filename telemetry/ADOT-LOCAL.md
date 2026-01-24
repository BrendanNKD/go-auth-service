# ADOT local collector for OpenTelemetry testing

This repository uses OTLP exporters configured by environment variables. The
collector config below listens on the default OTLP gRPC port `4317` and OTLP HTTP
port `4318` so you can verify traces/metrics locally without sending data to AWS.

## 1) Save the collector config

The repo includes a minimal config at `telemetry/adot-collector.yaml`.

## 2) Run the ADOT collector in Docker or Podman

Run the command from the **repo root** (so `$PWD/telemetry/adot-collector.yaml`
resolves correctly). If you run it elsewhere, replace `$PWD/...` with the full
path to `telemetry/adot-collector.yaml`.

```bash
docker run --rm --name adot-collector \
  -p 4317:4317 \
  -p 4318:4318 \
  -v "$PWD/telemetry/adot-collector.yaml:/etc/otel-collector-config.yaml:ro" \
  public.ecr.aws/aws-observability/aws-otel-collector:latest \
  --config /etc/otel-collector-config.yaml
```

```bash
podman run --rm --name adot-collector \
  -p 4317:4317 \
  -p 4318:4318 \
  -v "$PWD/telemetry/adot-collector.yaml:/etc/otel-collector-config.yaml:ro" \
  public.ecr.aws/aws-observability/aws-otel-collector:latest \
  --config /etc/otel-collector-config.yaml
```

## 3) Point the service at the local collector

Use these environment variables (set in your `.env` or shell):

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export OTEL_EXPORTER_OTLP_INSECURE=true
```

Optionally override traces/metrics endpoints:

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=localhost:4317
export OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=localhost:4317
```

## 4) Generate traffic

Start the service and hit any HTTP route. The ADOT collector logs should show
received spans/metrics because the config uses the `debug` exporter.

## 5) Switching to AWS backends (optional)

Once you confirm local exports, swap the `debug` exporter in the collector
config for AWS exporters (e.g., X-Ray, CloudWatch, AMP) and supply credentials.

## ECS sidecar setup

If you are running this service on ECS with a per-service ADOT sidecar,
see [`telemetry/ADOT-ECS-SIDECAR.md`](ADOT-ECS-SIDECAR.md) for a task definition
example and collector configuration that forwards to X-Ray, CloudWatch, and AMP.
