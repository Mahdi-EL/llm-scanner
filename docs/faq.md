# FAQ

**Is LLM Scanner free ?**
Yes. Uses Groq free API — 100,000 tokens/day.

**Is it legal ?**
Yes, if you scan apps you own or have permission to test.

**How long does a scan take ?**

| Profile | Time |
|---|---|
| Quick | ~2 minutes |
| Standard | ~10 minutes |
| Deep | ~45 minutes |

**Why does the scan stop ?**
Groq rate limit hit. Scanner retries automatically at midnight.

**Can I add my own prompts ?**
Yes — edit `attacks/prompts.py` or use `python generator.py`.

**What formats are generated ?**
PDF + HTML + Markdown automatically on every scan.

**Can I scan a real app ?**
```bash
python scanner.py \
  --type openai_compatible \
  --api-url "https://api.openai.com/v1" \
  --api-key "sk-..." \
  --target "My App"
```
