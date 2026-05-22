# API and Account Setup

## Current MVP

No API key, paid account, or cloud subscription is required.

The project works using:

```text
data/sample/sample_nmap_scan.xml
```

For live scans, only Nmap needs to be installed locally.

## Where future API code should go

Future collectors should be placed here:

```text
infrascope/collectors/
```

Suggested future files:

```text
microsoft365_graph_collector.py
azure_cli_collector.py
aws_boto3_collector.py
backup_csv_collector.py
```

## Secrets

Create a local `.env` file only if future APIs are added.

Never upload `.env` to GitHub.

Keep `.env.example` only.
