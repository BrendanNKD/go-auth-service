package telemetry

import (
	"context"
	"fmt"
	"log"
	"time"

	"auth-service/config"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

func Init(ctx context.Context, cfg config.Config) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if cfg.Telemetry.OTLPEndpoint == "" && cfg.Telemetry.OTLPTracesEndpoint == "" && cfg.Telemetry.OTLPMetricsEndpoint == "" {
		log.Println("OpenTelemetry disabled: OTEL_EXPORTER_OTLP_ENDPOINT is empty")
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(
		ctx,
		resource.WithFromEnv(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.Telemetry.ServiceName),
			semconv.ServiceVersion(cfg.Telemetry.ServiceVersion),
			attribute.String("deployment.environment", cfg.AppEnv),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	traceEndpoint := cfg.Telemetry.OTLPEndpoint
	if cfg.Telemetry.OTLPTracesEndpoint != "" {
		traceEndpoint = cfg.Telemetry.OTLPTracesEndpoint
	}
	metricEndpoint := cfg.Telemetry.OTLPEndpoint
	if cfg.Telemetry.OTLPMetricsEndpoint != "" {
		metricEndpoint = cfg.Telemetry.OTLPMetricsEndpoint
	}

	var traceExporter trace.SpanExporter
	var metricExporter metric.Exporter
	switch cfg.Telemetry.OTLPProtocol {
	case "http/protobuf", "http":
		traceExporterOptions := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(traceEndpoint),
			otlptracehttp.WithHeaders(cfg.Telemetry.OTLPHeaders),
			otlptracehttp.WithTimeout(cfg.Telemetry.ExportTimeout),
		}
		metricExporterOptions := []otlpmetrichttp.Option{
			otlpmetrichttp.WithEndpoint(metricEndpoint),
			otlpmetrichttp.WithHeaders(cfg.Telemetry.OTLPHeaders),
			otlpmetrichttp.WithTimeout(cfg.Telemetry.ExportTimeout),
		}
		if cfg.Telemetry.OTLPInsecure {
			traceExporterOptions = append(traceExporterOptions, otlptracehttp.WithInsecure())
			metricExporterOptions = append(metricExporterOptions, otlpmetrichttp.WithInsecure())
		}

		traceExporter, err = otlptracehttp.New(ctx, traceExporterOptions...)
		if err != nil {
			return nil, fmt.Errorf("create trace exporter: %w", err)
		}

		metricExporter, err = otlpmetrichttp.New(ctx, metricExporterOptions...)
		if err != nil {
			return nil, fmt.Errorf("create metric exporter: %w", err)
		}
	default:
		traceExporterOptions := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(traceEndpoint),
			otlptracegrpc.WithHeaders(cfg.Telemetry.OTLPHeaders),
			otlptracegrpc.WithTimeout(cfg.Telemetry.ExportTimeout),
		}
		metricExporterOptions := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpoint(metricEndpoint),
			otlpmetricgrpc.WithHeaders(cfg.Telemetry.OTLPHeaders),
			otlpmetricgrpc.WithTimeout(cfg.Telemetry.ExportTimeout),
		}
		if cfg.Telemetry.OTLPInsecure {
			traceExporterOptions = append(traceExporterOptions, otlptracegrpc.WithInsecure())
			metricExporterOptions = append(metricExporterOptions, otlpmetricgrpc.WithInsecure())
		}

		traceExporter, err = otlptracegrpc.New(ctx, traceExporterOptions...)
		if err != nil {
			return nil, fmt.Errorf("create trace exporter: %w", err)
		}

		metricExporter, err = otlpmetricgrpc.New(ctx, metricExporterOptions...)
		if err != nil {
			return nil, fmt.Errorf("create metric exporter: %w", err)
		}
	}

	traceProvider := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter),
		trace.WithResource(res),
	)
	metricProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(
			metricExporter,
			metric.WithInterval(cfg.Telemetry.MetricExportInterval),
		)),
	)

	otel.SetTracerProvider(traceProvider)
	otel.SetMeterProvider(metricProvider)

	return func(shutdownCtx context.Context) error {
		shutdownCtx, cancel := context.WithTimeout(shutdownCtx, 5*time.Second)
		defer cancel()

		var shutdownErr error
		if err := traceProvider.Shutdown(shutdownCtx); err != nil {
			shutdownErr = err
		}
		if err := metricProvider.Shutdown(shutdownCtx); err != nil {
			if shutdownErr != nil {
				shutdownErr = fmt.Errorf("%w; %v", shutdownErr, err)
			} else {
				shutdownErr = err
			}
		}
		return shutdownErr
	}, nil
}
