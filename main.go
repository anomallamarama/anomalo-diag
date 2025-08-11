package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	osexec "os/exec"
	"runtime"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	// Kubernetes
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	// AWS
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type Result struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Err    error  `json:"-"`
}

type resultForJSON struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (r Result) String() string {
	status := "✅"
	if !r.OK {
		status = "❌"
	}
	if r.Err != nil {
		return fmt.Sprintf("[%s] %s: %s\n", status, r.Name, r.Err.Error())
	}
	if r.Detail != "" {
		return fmt.Sprintf("[%s] %s: %s\n", status, r.Name, r.Detail)
	}
	return fmt.Sprintf("[%s] %s\n", status, r.Name)
}

func toJSON(rs []Result) ([]byte, error) {
	out := make([]resultForJSON, 0, len(rs))
	for _, r := range rs {
		jr := resultForJSON{Name: r.Name, OK: r.OK, Detail: r.Detail}
		if r.Err != nil {
			jr.Error = r.Err.Error()
		}
		out = append(out, jr)
	}
	return json.MarshalIndent(out, "", "  ")
}

// printResults prints results in either text or JSON and returns an exit code (0 if all OK, 2 otherwise).
func printResults(rs []Result, jsonOut bool) int {
	code := 0
	for _, r := range rs {
		if !r.OK {
			code = 2
		}
	}
	if jsonOut {
		b, err := toJSON(rs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to marshal json: %v\n", err)
			return 2
		}
		fmt.Println(string(b))
		return code
	}
	for _, r := range rs {
		fmt.Print(r)
	}
	return code
}

func printSectionHeader(title string) {
	fmt.Printf("\n==== %s ====\n", strings.ToUpper(title))
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "helm":
		fs := flag.NewFlagSet("helm", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "Output JSON")
		_ = fs.Parse(os.Args[2:])
		code := printResults([]Result{checkHelm()}, *jsonOut)
		os.Exit(code)
	case "k8s":
		fs := flag.NewFlagSet("k8s", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "Output JSON")
		_ = fs.Parse(os.Args[2:])
		code := printResults([]Result{checkK8s()}, *jsonOut)
		os.Exit(code)
	case "arch":
		fs := flag.NewFlagSet("arch", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "Output JSON")
		_ = fs.Parse(os.Args[2:])
		code := printResults([]Result{checkArch()}, *jsonOut)
		os.Exit(code)
	case "postgres":
		postgresCmd(os.Args[2:])
	case "redis":
		redisCmd(os.Args[2:])
	case "network":
		networkCmd(os.Args[2:])
	case "aws-secrets":
		awsSecretsCmd(os.Args[2:])
	case "s3":
		s3Cmd(os.Args[2:])
	case "all":
		allCmd(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`anomalo-diag - environment diagnostics

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
  --json                       Output JSON instead of text (available on all commands)
`)
}

// -----------------------
// Checks
// -----------------------

func checkHelm() Result {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path, err := execLookPath("helm")
	if err != nil {
		return Result{Name: "helm", OK: false, Err: errors.New("helm not found in PATH")}
	}
	out, err := execCommandContext(ctx, path, "version", "--short")
	if err != nil {
		return Result{Name: "helm", OK: false, Err: fmt.Errorf("failed to run helm: %w", err)}
	}
	return Result{Name: "helm", OK: true, Detail: strings.TrimSpace(out)}
}

func checkK8s() Result {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg, err := inClusterOrKubeconfig()
	if err != nil {
		return Result{Name: "k8s", OK: false, Err: err}
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return Result{Name: "k8s", OK: false, Err: err}
	}
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{Name: "k8s", OK: false, Err: err}
	}
	if len(nodes.Items) == 0 {
		return Result{Name: "k8s", OK: true, Detail: "API reachable, 0 nodes"}
	}

	// Tally instance types (sizes) without exposing node names
	instanceCount := make(map[string]int)
	for _, n := range nodes.Items {
		instance := n.Labels["node.kubernetes.io/instance-type"]
		if instance == "" {
			instance = n.Labels["beta.kubernetes.io/instance-type"]
		}
		if instance == "" {
			instance = "unknown"
		}
		instanceCount[instance]++
	}

	var sizeSummary []string
	for size, count := range instanceCount {
		sizeSummary = append(sizeSummary, fmt.Sprintf("%dx %s", count, size))
	}

	return Result{
		Name:   "k8s",
		OK:     true,
		Detail: fmt.Sprintf("API reachable, nodes=%d: %s", len(nodes.Items), strings.Join(sizeSummary, ", ")),
	}
}
func checkArch() Result {
	arch := runtime.GOARCH
	if arch == "arm64" || arch == "arm" {
		return Result{Name: "arch", OK: false, Detail: arch, Err: fmt.Errorf("unsupported architecture: %s", arch)}
	}
	return Result{Name: "arch", OK: true, Detail: arch}
}

func checkPostgres(dsn string, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if dsn == "" {
		return Result{Name: "postgres", OK: false, Err: errors.New("missing --dsn")}
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return Result{Name: "postgres", OK: false, Err: err}
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return Result{Name: "postgres", OK: false, Err: err}
	}
	return Result{Name: "postgres", OK: true, Detail: "connection successful"}
}

func checkRedis(url string, timeout time.Duration) Result {
	if url == "" {
		return Result{Name: "redis", OK: false, Err: errors.New("missing --url")}
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		return Result{Name: "redis", OK: false, Err: err}
	}
	opt.DialTimeout = timeout
	opt.ReadTimeout = timeout
	opt.WriteTimeout = timeout
	rdb := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return Result{Name: "redis", OK: false, Err: err}
	}
	return Result{Name: "redis", OK: true, Detail: "ping OK"}
}

func checkHTTPS(url string, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Result{Name: url, OK: false, Err: err}
	}
	defer resp.Body.Close()
	return Result{Name: url, OK: resp.StatusCode < 500, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

func checkTLS(host string, port string, timeout time.Duration) Result {
	if host == "" {
		return Result{Name: "tls", OK: false, Err: errors.New("missing host")}
	}
	addr := net.JoinHostPort(host, port)
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return Result{Name: addr, OK: false, Err: err}
	}
	defer conn.Close()
	return Result{Name: addr, OK: true, Detail: "TLS handshake OK"}
}

func checkTCP(host string, port string, timeout time.Duration) Result {
	addr := net.JoinHostPort(host, port)
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return Result{Name: addr, OK: false, Err: err}
	}
	conn.Close()
	return Result{Name: addr, OK: true, Detail: "TCP connect OK"}
}

func listAWSSecrets(region string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg, err := loadAWS(region)
	if err != nil {
		return Result{Name: "aws-secrets", OK: false, Err: err}
	}
	sm := secretsmanager.NewFromConfig(cfg)
	_, err = sm.ListSecrets(ctx, &secretsmanager.ListSecretsInput{MaxResults: aws.Int32(1)})
	if err != nil {
		return Result{Name: "aws-secrets", OK: false, Err: err}
	}
	return Result{Name: "aws-secrets", OK: true, Detail: "ListSecrets succeeded (credentials & perms OK)"}
}

func headS3Bucket(bucket, region string) Result {
	if bucket == "" {
		return Result{Name: "s3", OK: false, Err: errors.New("missing --bucket")}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg, err := loadAWS(region)
	if err != nil {
		return Result{Name: "s3", OK: false, Err: err}
	}
	c := s3.NewFromConfig(cfg)
	_, err = c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket})
	if err != nil {
		return Result{Name: "s3", OK: false, Err: err}
	}
	return Result{Name: "s3", OK: true, Detail: fmt.Sprintf("HeadBucket OK for %s", bucket)}
}

// -----------------------
// Commands (flag parsing)
// -----------------------

func postgresCmd(args []string) {
	fs := flag.NewFlagSet("postgres", flag.ExitOnError)
	dsn := fs.String("dsn", "", "Postgres DSN (pgx format)")
	timeout := fs.Int("timeout", 10, "timeout seconds")
	jsonOut := fs.Bool("json", false, "Output JSON")
	_ = fs.Parse(args)
	code := printResults([]Result{checkPostgres(*dsn, time.Duration(*timeout)*time.Second)}, *jsonOut)
	os.Exit(code)
}

func redisCmd(args []string) {
	fs := flag.NewFlagSet("redis", flag.ExitOnError)
	url := fs.String("url", "", "Redis URL (redis:// or rediss://)")
	timeout := fs.Int("timeout", 10, "timeout seconds")
	jsonOut := fs.Bool("json", false, "Output JSON")
	_ = fs.Parse(args)
	code := printResults([]Result{checkRedis(*url, time.Duration(*timeout)*time.Second)}, *jsonOut)
	os.Exit(code)
}

func networkCmd(args []string) {
	fs := flag.NewFlagSet("network", flag.ExitOnError)
	checkGCR := fs.Bool("check-gcr", true, "Check https://gcr.io")
	checkLogging := fs.Bool("check-logging", true, "Check https://logging.anomalo.com")
	sentryHost := fs.String("sentry-host", "", "Sentry ingest subdomain (e.g. o123456.ingest.sentry.io)")
	smtpRegion := fs.String("smtp-region", "us-west-1", "AWS SES SMTP region (email-smtp.<region>.amazonaws.com:587)")
	timeout := fs.Int("timeout", 10, "timeout seconds")
	jsonOut := fs.Bool("json", false, "Output JSON")
	_ = fs.Parse(args)
	to := time.Duration(*timeout) * time.Second

	var results []Result
	if *checkGCR {
		results = append(results, checkHTTPS("https://gcr.io", to))
	}
	if *checkLogging {
		results = append(results, checkHTTPS("https://logging.anomalo.com", to))
	}
	if *sentryHost != "" {
		results = append(results, checkTLS(*sentryHost, "443", to))
	}
	if *smtpRegion != "" {
		results = append(results, checkTCP(fmt.Sprintf("email-smtp.%s.amazonaws.com", *smtpRegion), "587", to))
	}
	code := printResults(results, *jsonOut)
	os.Exit(code)
}

func awsSecretsCmd(args []string) {
	fs := flag.NewFlagSet("aws-secrets", flag.ExitOnError)
	region := fs.String("region", "", "AWS region")
	jsonOut := fs.Bool("json", false, "Output JSON")
	_ = fs.Parse(args)
	code := printResults([]Result{listAWSSecrets(*region)}, *jsonOut)
	os.Exit(code)
}

func s3Cmd(args []string) {
	fs := flag.NewFlagSet("s3", flag.ExitOnError)
	bucket := fs.String("bucket", "", "S3 bucket name")
	region := fs.String("region", "", "AWS region (optional)")
	jsonOut := fs.Bool("json", false, "Output JSON")
	_ = fs.Parse(args)
	code := printResults([]Result{headS3Bucket(*bucket, *region)}, *jsonOut)
	os.Exit(code)
}

func allCmd(args []string) {
	fs := flag.NewFlagSet("all", flag.ExitOnError)
	dsn := fs.String("dsn", "", "Postgres DSN (for postgres check)")
	redisURL := fs.String("redis-url", "", "Redis URL (for redis check)")
	sentryHost := fs.String("sentry-host", "", "Sentry ingest subdomain (o123456.ingest.sentry.io)")
	smtpRegion := fs.String("smtp-region", "us-west-1", "SES SMTP region")
	awsRegion := fs.String("region", "", "AWS region for SDK checks")
	s3Bucket := fs.String("bucket", "", "S3 bucket to check (HeadBucket)")
	timeout := fs.Int("timeout", 10, "timeout seconds")
	jsonOut := fs.Bool("json", false, "Output JSON")
	_ = fs.Parse(args)
	to := time.Duration(*timeout) * time.Second

	if *jsonOut {
		results := []Result{}
		results = append(results, checkHelm())
		results = append(results, checkK8s())
		results = append(results, checkArch())
		if *dsn != "" {
			results = append(results, checkPostgres(*dsn, to))
		} else {
			results = append(results, Result{Name: "postgres", OK: false, Err: errors.New("no DSN provided; skip")})
		}
		if *redisURL != "" {
			results = append(results, checkRedis(*redisURL, to))
		} else {
			results = append(results, Result{Name: "redis", OK: false, Err: errors.New("no URL provided; skip")})
		}
		results = append(results, checkHTTPS("https://gcr.io", to))
		results = append(results, checkHTTPS("https://logging.anomalo.com", to))
		if *sentryHost != "" {
			results = append(results, checkTLS(*sentryHost, "443", to))
		} else {
			results = append(results, Result{Name: "sentry", OK: false, Err: errors.New("no --sentry-host provided; skip")})
		}
		if *smtpRegion != "" {
			results = append(results, checkTCP(fmt.Sprintf("email-smtp.%s.amazonaws.com", *smtpRegion), "587", to))
		}
		results = append(results, listAWSSecrets(*awsRegion))
		if *s3Bucket != "" {
			results = append(results, headS3Bucket(*s3Bucket, *awsRegion))
		} else {
			results = append(results, Result{Name: "s3", OK: false, Err: errors.New("no --bucket provided; skip")})
		}
		code := printResults(results, true)
		os.Exit(code)
	}

	// Text mode with section headers
	exitCode := 0

	printSectionHeader("Helm")
	r := checkHelm()
	fmt.Print(r)
	if !r.OK {
		exitCode = 2
	}

	printSectionHeader("Kubernetes")
	r = checkK8s()
	fmt.Print(r)
	if !r.OK {
		exitCode = 2
	}

	printSectionHeader("Architecture")
	r = checkArch()
	fmt.Print(r)
	if !r.OK {
		exitCode = 2
	}

	printSectionHeader("Postgres")
	if *dsn != "" {
		r = checkPostgres(*dsn, to)
	} else {
		r = Result{Name: "postgres", OK: false, Err: errors.New("no DSN provided; skip")}
	}
	fmt.Print(r)
	if !r.OK {
		exitCode = 2
	}

	printSectionHeader("Redis")
	if *redisURL != "" {
		r = checkRedis(*redisURL, to)
	} else {
		r = Result{Name: "redis", OK: false, Err: errors.New("no URL provided; skip")}
	}
	fmt.Print(r)
	if !r.OK {
		exitCode = 2
	}

	printSectionHeader("Network")
	r = checkHTTPS("https://gcr.io", to)
	fmt.Print(r)
	if !r.OK {
		exitCode = 2
	}
	r = checkHTTPS("https://logging.anomalo.com", to)
	fmt.Print(r)
	if !r.OK {
		exitCode = 2
	}
	if *sentryHost != "" {
		r = checkTLS(*sentryHost, "443", to)
	} else {
		r = Result{Name: "sentry", OK: false, Err: errors.New("no --sentry-host provided; skip")}
	}
	fmt.Print(r)
	if !r.OK {
		exitCode = 2
	}
	if *smtpRegion != "" {
		r = checkTCP(fmt.Sprintf("email-smtp.%s.amazonaws.com", *smtpRegion), "587", to)
		fmt.Print(r)
		if !r.OK {
			exitCode = 2
		}
	}

	printSectionHeader("AWS Secrets Manager")
	r = listAWSSecrets(*awsRegion)
	fmt.Print(r)
	if !r.OK {
		exitCode = 2
	}

	printSectionHeader("S3")
	if *s3Bucket != "" {
		r = headS3Bucket(*s3Bucket, *awsRegion)
	} else {
		r = Result{Name: "s3", OK: false, Err: errors.New("no --bucket provided; skip")}
	}
	fmt.Print(r)
	if !r.OK {
		exitCode = 2
	}

	os.Exit(exitCode)
}

// -----------------------
// Helpers
// -----------------------

func execLookPath(file string) (string, error) { return osexec.LookPath(file) }

func execCommandContext(ctx context.Context, name string, args ...string) (string, error) {
	cmd := osexec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func inClusterOrKubeconfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = clientcmd.RecommendedHomeFile
	}
	cfg2, err2 := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err2 != nil {
		return nil, fmt.Errorf("kubeconfig not found or invalid: %w", err2)
	}
	return cfg2, nil
}

func loadAWS(region string) (aws.Config, error) {
	if region != "" {
		return config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	}
	return config.LoadDefaultConfig(context.Background())
}
