# Attack Categories

LLM Scanner uses 14 attack categories covering 321+ prompts.

| # | Category | Prompts | Description |
|---|---|---|---|
| 1 | direct_override | 30 | Tell AI to ignore its instructions |
| 2 | roleplay | 30 | Trick AI into playing unrestricted character |
| 3 | extraction | 20 | Extract the system prompt |
| 4 | indirect_injection | 19 | Hide attacks inside documents |
| 5 | boundary_testing | 20 | Map AI restrictions (100% success rate) |
| 6 | social_engineering | 18 | Pretend to be a researcher (89% success) |
| 7 | encoding_attacks | 11 | Base64, ROT13, HTML encoding |
| 8 | thinking_exploitation | 14 | Target visible AI reasoning |
| 9 | search_augmented | 11 | Target web-connected AI |
| 10 | multilingual_attacks | 25 | Attacks in 10 languages |
| 11 | token_smuggling | 15 | Split/obfuscate attack words |
| 12 | prompt_chaining | 15 | Chain innocent prompts |
| 13 | context_window | 10 | Flood context window |
| 14 | few_shot_poisoning | 10 | Poison with fake examples |

## Universal Laws Discovered

```
Boundary Testing    → 9/9 models failed (100%)
Social Engineering  → 8/9 models failed (89%)
Direct Override     → 7/9 models failed (78%)
```
