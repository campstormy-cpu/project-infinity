# ENVIRONMENT AUDIT

Date: 2026-10-22. Every row below was observed by running a command in this session. Nothing is assumed.

## Hardware and OS

| Item | Observed |
|---|---|
| OS | Linux 6.18.44 x86_64 (Ubuntu 24.04 userland) |
| CPU | 2 cores |
| RAM | 8 GB (about 7.4 GB free) |
| Disk | 252 GB volume, about 31 GB free |
| GPU / VRAM | None (`nvidia-smi` not found) |

## Toolchain

| Item | Observed |
|---|---|
| Python | 3.13.16 |
| Node.js | v22.22.0 |
| Rust | rustc / cargo 1.97.0 |
| GCC / make / cmake | gcc 13.3.0, make, cmake present |
| Git | 2.43.0 (identity: Claude <noreply@anthropic.com>) |
| Docker | CLI 29.9.1 present, **daemon not running** (no socket). Containers are unavailable. |
| FFmpeg | present, with `ffv1` and `flac` encoders |
| xz | 5.4.5 |
| ML libraries | numpy 2.5.3, pandas 3.0.5. **torch is not installed**, no GPU. |

## Python packages

Installed in this session with `pip install --break-system-packages`: zstandard 0.25.0, brotli 1.2.1, pytest 9.1.1, pyarrow 26.0.0.
Stdlib: lzma, zlib, bz2.

## Network

| Target | Result |
|---|---|
| pypi.org | HTTP 200 (package installs work) |
| github.com | HTTP 400 from a bare request; `gh auth status` reports **token login failed** |
| example.com | blocked (000). Egress is allowlisted through a proxy. |

Conclusions:

- Arbitrary internet access is **not** available. Dataset downloads from general sites will fail.
- GitHub access is **not verified**. Pushing, opening pull requests and running GitHub Actions remain **unavailable until the owner connects and approves it** (Directive 012).

## Automation and integrations

| Item | Observed |
|---|---|
| cron / crontab | not installed |
| Claude scheduled tasks | tools exist (`create_trigger`, `send_later`). **Not used or tested yet.** Creating one needs owner approval to be considered configured. |
| MCP connectors | Gmail, Calendar, Drive, Notion, Canva, Higgsfield and others are listed. None are needed for Phase 0/1 and **none were connected or used**. They hold private accounts, so Directive 012 requires approval. |
| Sub-agent mechanism | `Agent` tool is available. Used for the independent audit in step 9. |

## Capabilities that cannot be delivered right now

1. GPU training and neural compression experiments (Phase 3): no GPU, no torch. CPU-only prototypes are possible but small.
2. Containerized workers: Docker daemon not running.
3. Running CI on GitHub: not connected.
4. Persistent scheduling: no cron. Claude scheduled tasks are the candidate and need approval.
5. Long-lived background workers: processes left running after a reply are stopped within minutes.
