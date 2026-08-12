# Deploying mxruntime with Docker

## Quick Start

Build the image from the repository root:

```bash
docker build -f deploy/docker/Dockerfile -t mxruntime:latest .
```

Run with a config file:

```bash
docker run -d \
  --name mxruntime \
  -p 8443:8443 \
  -p 9090:9090 \
  -p 9091:9091 \
  -v /path/to/config.toml:/etc/mx/config.toml:ro \
  mxruntime:latest
```

## Dockerfile Architecture

The image uses a **multi-stage build**:

| Stage | Base | Purpose |
|-------|------|---------|
| `builder` | `rust:1-bookworm` | Compiles `mxruntime` in release mode with LTO |
| `runtime` | `debian:bookworm-slim` | Minimal runtime with only shared libraries |

The runtime image runs as a non-root `mxruntime` user.

## Port Layout

| Port | Protocol | Purpose |
|------|----------|---------|
| 8443 | HTTP/gRPC | Message channel inbound (configurable via config) |
| 9090 | HTTP | Admin API: `/health`, `/ready`, `/status`, `/metrics`, `/reload` |
| 9091 | gRPC | Admin gRPC API |

## Health Checks

The container includes a Docker `HEALTHCHECK` that polls `GET /health` every 30 seconds.
This endpoint requires no authentication.

For orchestration systems (Kubernetes, ECS), configure liveness and readiness probes:

```yaml
# Kubernetes example
livenessProbe:
  httpGet:
    path: /health
    port: 9090
  initialDelaySeconds: 15
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /ready
    port: 9090
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Graceful Shutdown / SIGTERM Lifecycle

`mxruntime` installs handlers for both **SIGINT** (Ctrl-C) and **SIGTERM**.
Either signal triggers the same drain sequence:

1. The signal is observed and logged (`received SIGTERM` / `received SIGINT`).
2. Each inbound channel is told to stop accepting new work and to begin a
   graceful shutdown of its server (`shutdown signal received, draining channels`).
3. In-flight pipeline tasks continue running until they complete or until
   the **30-second drain timeout** elapses (`DRAIN_TIMEOUT` in `engine.rs`).
4. On clean drain, the process logs `channels drained successfully` and
   exits with status `0`.
5. If the drain timeout is exceeded, the process logs
   `drain timeout exceeded, forcing shutdown` and exits with status `0`.
   Tasks still running at that point are dropped — their transactions
   remain in whatever lifecycle state they reached (commit, abort, or
   incomplete).

### Docker `stop` interaction

`docker stop` sends SIGTERM, then SIGKILL after `--time` (default **10 seconds**).
Because the runtime's drain timeout is 30 seconds, the default Docker
grace period is too short for a clean drain under load. Override it:

```bash
docker stop --time=35 mxruntime
```

The extra 5 seconds gives the runtime headroom to log the drain result
before Docker escalates to SIGKILL.

### Kubernetes / orchestration

Set `terminationGracePeriodSeconds` to at least **35** so the kubelet
waits for the drain to complete before sending SIGKILL:

```yaml
spec:
  terminationGracePeriodSeconds: 35
  containers:
    - name: mxruntime
      image: mxruntime:latest
      # ...
```

If you handle long-running pipelines (large batches, slow downstream
participants), raise `terminationGracePeriodSeconds` further and consider
tuning `DRAIN_TIMEOUT` in code.

### Recovery on restart

If the process is force-killed mid-drain (SIGKILL, `docker kill`, OOM,
crash), transactions left in an incomplete state are picked up on the
next start when `recover_incomplete_on_startup = true` is set in the
`[runtime]` config. See `docs/examples/quickstart.toml` for the flag.

### Verifying drain locally

```bash
./target/release/mxruntime --config docs/examples/quickstart.toml --serve-admin &
PID=$!
sleep 2
curl -sf http://127.0.0.1:19090/health   # → {"ok":true}
kill -TERM $PID
wait $PID                                  # exit code 0
```

You should see `received SIGTERM`, `draining in-flight tasks`, and
`channels drained successfully` in the logs.

## Configuration

The runtime requires a TOML config file mounted at `/etc/mx/config.toml`.
Override the path with `--config`:

```bash
docker run mxruntime:latest --config /custom/path/config.toml --serve-admin
```

**Important**: The default CMD includes `--serve-admin` so the admin HTTP endpoint
(and `/health`) is available. If you override the entrypoint or CMD, ensure
`--serve-admin` is passed when you need health checks.

The admin bind address defaults to `127.0.0.1:9090` inside the container.
This is fine for Docker health checks (they run inside the container). If you
need the admin API accessible from outside, set `admin_bind = "0.0.0.0:9090"`
and enable `runtime.admin_auth.mode` (`legacy_bearer` or `jwt_hs256`). Binding
`0.0.0.0` with auth disabled fails closed unless
`runtime.admin_allow_insecure_bind = true`. The unused HTTP or gRPC bind is
not checked when that surface is not being served.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level filter (trace/debug/info/warn/error) |

## Examples

### SQLite (local dev)

```bash
docker run -d --name mxruntime \
  -p 8443:8443 -p 9090:9090 \
  -v ./docs/examples/quickstart.toml:/etc/mx/config.toml:ro \
  mxruntime:latest
```

### With external PostgreSQL

```bash
docker run -d --name mxruntime \
  -p 8443:8443 -p 9090:9090 \
  -v ./my-production.toml:/etc/mx/config.toml:ro \
  -e RUST_LOG=info \
  mxruntime:latest
```

## Build Notes

The release profile (`Cargo.toml`) enables `lto = "fat"` and `codegen-units = 1`
for maximum optimization. Expect longer build times (10-20 min depending on hardware).

## Systemd (Alternative)

A systemd unit file is available at `deploy/systemd/mxruntime.service`
for bare-metal or VM deployments.
