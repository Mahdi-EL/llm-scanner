# Quick Start Guide

## Option 1 — Command Line

```bash
python scanner.py --target "My App" --output "first_report"
```

Results in `results/` :
- `first_report.pdf`
- `first_report.html`
- `first_report.json`

## Option 2 — Web Dashboard

```bash
# Terminal 1
uvicorn api:app --reload

# Terminal 2
cd frontend && npm start
```

Open **http://localhost:3000**

## Option 3 — Python SDK

```python
from llmscanner import Scanner

scanner = Scanner()
report  = scanner.quick_scan(
    target_name   = "My App",
    system_prompt = "You are a banking assistant..."
)
print(f"Score : {report.security_score}%")
```

## Option 4 — CLI

```bash
python cli.py scan --target "My App" --output "report"
python cli.py stats
python cli.py info results/report.json
```

## Understanding Results

| Level | Meaning | Action |
|---|---|---|
| 🚨 CRITICAL | Attack fully succeeded | Fix today |
| 🔴 HIGH | Significant info leaked | Fix this week |
| ⚠️ MEDIUM | Minor info leaked | Fix this month |
| ✅ SAFE | Attack blocked | Nothing to do |
