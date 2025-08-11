# Anomalo Diag Container

This is a basic container to ascertain if we'll be able to run functionality of Anomalo within your k8s environment.

## CLI Usage

There is a cli that we can pass flags to in order to test various outputs.

```bash
anomalo-diag - environment diagnostics

USAGE:
  anomalo-diag <command> [flags]

COMMANDS:
  helm                 Check if helm is installed and print version
  k8s                  Check Kubernetes API reachability; print node count & sizes
  arch                 Print CPU architecture (errors on arm/arm64)
  postgres --dsn DSN   Validate a PostgreSQL connection (pgx format)
  redis --url URL      Validate a Redis connection URL (rediss:// or redis://)
  network [flags]      Run bundled network checks
  aws-secrets [flags]  Attempt to list AWS Secrets Manager secrets
  s3 --bucket NAME [--region REGION]
                       Check connectivity to an S3 bucket (HeadBucket)
  all [flags]          Run everything at once; accepts superset of flags

NETWORK FLAGS:
  --check-gcr                  Check https://gcr.io
  --check-logging              Check https://logging.anomalo.com
  --sentry-host HOST           Check TLS to Sentry ingest subdomain (e.g. o123456.ingest.sentry.io)
  --smtp-region REGION         Check email-smtp.<region>.amazonaws.com:587 connectivity (default us-west-1)

AWS FLAGS:
  --region REGION              AWS region for SDK calls (falls back to env/config)

GLOBAL:
  -t, --timeout SECONDS        Per-check timeout (default 10)
  --json
```  