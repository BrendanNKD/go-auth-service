# ADOT sidecar on ECS (per-service collector)

This service already exports OTLP traces and metrics. On ECS you can run the
AWS Distro for OpenTelemetry (ADOT) Collector as a sidecar and point the app to
`localhost:4317`. The sidecar then forwards to X-Ray, CloudWatch, and AMP.

## 1) Collector configuration

Use the provided config at `telemetry/adot-collector-ecs.yaml`. It receives OTLP
over gRPC on `4317` and exports:

- **Traces** → X-Ray (`awsxray` exporter)
- **Metrics** → CloudWatch (`awsemf` exporter) and AMP (`prometheusremotewrite`)

The config expects these environment variables in the collector container:

```bash
AWS_REGION=us-east-1
AMP_ENDPOINT=https://aps-workspaces.us-east-1.amazonaws.com/workspaces/<workspace-id>/api/v1/remote_write
CW_LOG_GROUP=/aws/ecs/auth-service/metrics
CW_LOG_STREAM=otel
CW_METRIC_NAMESPACE=AuthService
```

## 2) App container settings

Set the app to export to the local sidecar:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
OTEL_EXPORTER_OTLP_INSECURE=true
OTEL_SERVICE_NAME=auth-service
```

## 3) ECS task definition example

Below is a condensed task definition snippet that runs the collector sidecar and
injects the config from SSM Parameter Store. The collector writes the config to
disk before starting.

```json
{
  "family": "auth-service",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["EC2", "FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "auth-service",
      "image": "<your-app-image>",
      "portMappings": [{ "containerPort": 8080, "protocol": "tcp" }],
      "environment": [
        { "name": "OTEL_EXPORTER_OTLP_ENDPOINT", "value": "localhost:4317" },
        { "name": "OTEL_EXPORTER_OTLP_PROTOCOL", "value": "grpc" },
        { "name": "OTEL_EXPORTER_OTLP_INSECURE", "value": "true" },
        { "name": "OTEL_SERVICE_NAME", "value": "auth-service" }
      ],
      "dependsOn": [{ "containerName": "adot-collector", "condition": "START" }]
    },
    {
      "name": "adot-collector",
      "image": "public.ecr.aws/aws-observability/aws-otel-collector:latest",
      "essential": true,
      "command": [
        "/bin/sh",
        "-c",
        "echo \"$ADOT_COLLECTOR_CONFIG\" > /etc/otel-collector-config.yaml && /awscollector --config /etc/otel-collector-config.yaml"
      ],
      "secrets": [
        {
          "name": "ADOT_COLLECTOR_CONFIG",
          "valueFrom": "arn:aws:ssm:us-east-1:123456789012:parameter/auth-service/adot-config"
        }
      ],
      "environment": [
        { "name": "AWS_REGION", "value": "us-east-1" },
        { "name": "AMP_ENDPOINT", "value": "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/<workspace-id>/api/v1/remote_write" },
        { "name": "CW_LOG_GROUP", "value": "/aws/ecs/auth-service/metrics" },
        { "name": "CW_LOG_STREAM", "value": "otel" },
        { "name": "CW_METRIC_NAMESPACE", "value": "AuthService" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/aws/ecs/auth-service",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "adot"
        }
      }
    }
  ]
}
```

## 4) IAM permissions

Ensure the task role has permissions to export telemetry:

- `xray:PutTraceSegments`, `xray:PutTelemetryRecords`
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`
- `aps:RemoteWrite`

Also allow the task execution role to read the SSM parameter that stores
`ADOT_COLLECTOR_CONFIG`.
