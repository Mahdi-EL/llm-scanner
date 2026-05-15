# Installation Guide

## Requirements

| Tool | Version | Download |
|---|---|---|
| Python | 3.10+ | python.org |
| Node.js | 18+ | nodejs.org |
| Git | Any | git-scm.com |

## Steps

```bash
# 1. Clone
git clone https://github.com/Mahdi-EL/llm-scanner
cd llm-scanner

# 2. Virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create .env file
# Add your Groq API key (free at console.groq.com)
# GROQ_API_KEY=your_key_here

# 5. Verify
python -m pytest tests.py -v
# Expected : 47 passed
```

## Common Issues

**PowerShell blocks venv :**
```bash
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**SSL errors :**
```bash
pip install -r requirements.txt --trusted-host pypi.org --trusted-host files.pythonhosted.org
```

**Rate limit :**
Groq free tier = 100,000 tokens/day. Resets at midnight automatically.
