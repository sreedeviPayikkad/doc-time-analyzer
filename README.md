# doc-time-analyzer

Estimate time spent editing Google Docs using Revisions timestamps.
Heuristic: duration per revision = max(2 min, gap to next revision), with an optional cap.

## Setup
1. Enable **Google Drive API** in your Google Cloud project.
2. Create OAuth **Desktop App** credentials and download `client_secret.json` to the repo root.

## Install & Run (Poetry)
```bash
poetry install
poetry run doc-time --doc <DOC_FILE_ID>
