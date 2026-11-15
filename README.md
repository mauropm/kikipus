# Kikipus

**Know what lives inside your cloud.**

Kikipus is a read-only GCP reconnaissance, inventory, security, cost-analysis, and infrastructure-health tool.

**Repository:** <https://github.com/mauropm/kikipus>

## Overview

Point Kikipus at a Google Cloud environment and get an immediate answer to:

- How many projects?
- Which projects are active?
- Which projects appear abandoned?
- Who has access?
- What is running?
- What is expensive?
- What appears unused?
- What is publicly exposed?
- What security issues deserve attention?

## ● READ ONLY

Kikipus is **READ ONLY** by design. It will never:

- Delete, stop, or restart resources
- Modify IAM, firewall rules, or networks
- Modify billing or change project settings
- Create resources or rotate credentials

It only executes read-only `gcloud` commands and queries read-only GCP APIs.

## Installation

### From source

```bash
git clone https://github.com/mauropm/kikipus.git
cd kikipus
make build
```

### Go install

```bash
go install github.com/mauropm/kikipus@latest
```

## Authentication

Kikipus uses your existing `gcloud` authentication. No credentials are stored or requested.

```bash
# Login to gcloud first
gcloud auth login

# Verify your configuration
gcloud config list
```

## Usage

### Quick start

```bash
# Scan the current GCP environment
kikipus scan

# Scan a specific project
kikipus scan --project my-project

# Scan an entire organization
kikipus scan --organization 123456789
```

### Commands

| Command | Description |
|---------|-------------|
| `kikipus` | Launch interactive mode |
| `kikipus scan` | Scan GCP environment |
| `kikipus projects` | List discovered projects |
| `kikipus users` | List users and service accounts |
| `kikipus security` | Show security findings |
| `kikipus costs` | Show cost analysis |
| `kikipus report` | Generate scan report |
| `kikipus graph` | Export environment graph |
| `kikipus snapshot` | Create local snapshot |
| `kikipus diff` | Compare snapshots |

### Output formats

```bash
# JSON output
kikipus findings --json

# Markdown report
kikipus report --markdown > report.md

# CSV export
kikipus projects --csv > projects.csv
```

### Global flags

| Flag | Description |
|------|-------------|
| `--project, -p` | Specific GCP project to scan |
| `--organization, -o` | Organization ID to scan |
| `--folder, -f` | Folder ID to scan |
| `--json, -j` | Output in JSON format |
| `--csv` | Output in CSV format |
| `--markdown, -m` | Output in Markdown format |
| `--verbose, -v` | Verbose output |
| `--quiet, -q` | Quiet mode |
| `--no-cache` | Disable caching |
| `--read-only` | Read-only mode (default) |

## Configuration

Configuration file: `~/.config/kikipus/config.toml`

```toml
[scan]
concurrency = 8
timeout = "30s"

[ui]
theme = "dark"

[storage]
enabled = true

[thresholds]
old_service_account_key_days = 90
dormant_project_days = 90
idle_resource_days = 30
```

## Architecture

```
                    ┌─────────────────────┐
                    │      KIKIPUS TUI    │
                    │      CLI / Reports  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    ANALYSIS ENGINE  │
                    ├─────────────────────┤
                    │ Security            │
                    │ FinOps              │
                    │ Activity            │
                    │ Hygiene             │
                    │ Risk Scoring        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  NORMALIZED MODEL   │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
       ┌──────────────────┐       ┌──────────────────┐
       │  GCP API CLIENT  │       │  GCLOUD CLIENT   │
       └──────────────────┘       └──────────────────┘
                 │                           │
                 └─────────────┬─────────────┘
                               ▼
                         GOOGLE CLOUD
```

## Development

```bash
# Build
make build

# Run tests
make test

# Lint
make lint

# Clean
make clean
```

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

Copyright (c) 2026 Mauro Parra \<mauropm@gmail.com\>