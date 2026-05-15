# API Reference

Base URL : `http://localhost:8000`
Interactive docs : `http://localhost:8000/docs`

## Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | API info |
| POST | `/auth/login` | Get JWT token |
| POST | `/scan` | Launch scan |
| GET | `/scan/{id}` | Get scan status |
| GET | `/scans` | List all scans |
| GET | `/download/{id}` | Download PDF |
| GET | `/download/html/{id}` | Download HTML |
| GET | `/download/md/{id}` | Download Markdown |
| GET | `/results/{id}` | Get JSON results |
| DELETE | `/scan/{id}` | Delete scan |
| GET | `/health` | Health check |
| WS | `/ws` | WebSocket updates |
| POST | `/waitlist` | Join waitlist |

## Launch A Scan

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_name"  : "My App",
    "target_type"  : "simulation",
    "system_prompt": "You are a banking assistant..."
  }'
```

## Check Status

```bash
curl http://localhost:8000/scan/abc12345
```
