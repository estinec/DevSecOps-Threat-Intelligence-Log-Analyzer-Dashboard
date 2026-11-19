# DevSecOps-Threat-Intelligence-Log-Analyzer-Dashboard

A full-stack security analytics application that ingests web or authentication logs, normalizes events into a consistent format, detects suspicious activity using configurable rules, and presents actionable alerts in a dashboard[cite: 1].

## File Structure

```text
DevSecOps-Threat-Intelligence-Log-Analyzer-Dashboard/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/              # route handlers
│   │   ├── core/             # config, logging, security settings
│   │   ├── db/               # database connection and models
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── ingestion/        # upload validation and import service
│   │   ├── parsers/          # nginx, apache, auth parsers
│   │   ├── detection/        # rules, evaluator and alert deduplication
│   │   └── analytics/        # aggregation queries
│   ├── tests/
│   ├── sample_logs/
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── app/
│   ├── components/
│   ├── lib/                  # API client and types
│   ├── hooks/
│   └── public/
├── docs/                     # architecture, API notes, screenshots
├── .gitignore
└── README.md