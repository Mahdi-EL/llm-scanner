# Attack categories

Every scan can run 1,090 attack prompts in 22 categories. Each category maps to risks in the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/). Reports recommend the fixes below for every category that failed. Multi-turn attacks run only against targets that keep chat history (simulation, Groq and OpenAI-compatible APIs).

_This page mirrors `backend/attacks/catalog.py`; a test fails when its counts drift from the library._

## Direct instruction override

`direct_override` · 70 prompts · LLM01 Prompt Injection

Plain requests to ignore or replace the system prompt.

How to fix:

- Treat the system prompt as guidance, not a security boundary: enforce what the assistant may do in your code (tool permissions, data filters).
- Say explicitly that user messages can't change these rules, and repeat the critical rules at the end of the system prompt.
- Flag obvious override phrases such as "ignore previous instructions" with an input classifier and log them.

## Role-play and persona attacks

`roleplay` · 63 prompts · LLM01 Prompt Injection

Asking the model to become a character or another AI without rules.

How to fix:

- Tell the model it keeps its rules inside stories, games and personas.
- Refuse persona switches whose point is to remove restrictions (DAN, STAN, "an AI with no rules").
- Run a moderation check on outputs: policy breaks hidden in fiction are easier to catch there.

## System prompt extraction

`extraction` · 68 prompts · LLM07 System Prompt Leakage

Direct and indirect attempts to make the model reveal its instructions.

How to fix:

- Assume the system prompt will leak: remove secrets, keys, internal URLs and business rules from it.
- Block replies that contain long fragments of the system prompt with an output filter.
- Add a canary string to the prompt and alert when it ever appears in a reply.

## Encoding and obfuscation

`encoding_attacks` · 51 prompts · LLM01 Prompt Injection

Instructions hidden in Base64, hex, HTML entities, XML or comments.

How to fix:

- Decode and normalize input (Base64, hex, entities, Unicode tricks) before your safety checks run.
- Tell the model that decoded content is data to describe, never instructions to follow.

## Indirect prompt injection

`indirect_injection` · 58 prompts · LLM01 Prompt Injection

Instructions planted in documents, web pages, records or tool output.

How to fix:

- Wrap untrusted content (documents, pages, emails, tool results) in clear delimiters and tell the model it is data only.
- Never let retrieved content trigger an action without a separate permission check in your code.
- Strip hidden text (HTML comments, display:none blocks, zero-width characters) from retrieved content.

## Social engineering

`social_engineering` · 60 prompts · LLM01 Prompt Injection

Claims to be a researcher, developer or tester to unlock special behavior.

How to fix:

- The model can't verify identities: state that claims like "I'm the developer" never unlock anything.
- Grant elevated access only through authentication in your application, never through the chat.

## Search and retrieval attacks

`search_augmented_attacks` · 44 prompts · LLM01 Prompt Injection, LLM08 Vector and Embedding Weaknesses

Asking the model to fetch and obey instructions from search results.

How to fix:

- Treat search and retrieval results as untrusted data, never as instructions.
- Limit which sources the assistant can browse or retrieve from, and filter results for injected instructions.

## Reasoning exploitation

`thinking_exploitation` · 50 prompts · LLM01 Prompt Injection, LLM07 System Prompt Leakage

Asking for hidden reasoning, drafts or what the model "almost said".

How to fix:

- Don't expose chain-of-thought, scratchpads or draft answers to users.
- Tell the model there is no hidden draft to reveal and to answer with its final reply only.

## Boundary probing

`boundary_testing` · 61 prompts · LLM07 System Prompt Leakage

Questions that map out the model's restrictions and filters.

How to fix:

- Answer questions about restrictions with a short, generic policy rather than the exact rules.
- Don't list internal topics, tools or filters in replies.

## Multilingual attacks

`multilingual_attacks` · 45 prompts · LLM01 Prompt Injection

The same attacks written in other languages.

How to fix:

- Run input and output checks in every language you accept, or translate before checking.
- Test the system prompt's rules in your users' main languages.

## Token smuggling

`token_smuggling` · 40 prompts · LLM01 Prompt Injection

Split words, odd spacing and fake role tags that slip past filters.

How to fix:

- Normalize input before checks: remove zero-width characters, merge split words, strip fake role tags such as [SYSTEM].
- Never place user text in the system or developer role.

## Prompt chaining

`prompt_chaining` · 40 prompts · LLM01 Prompt Injection

Multi-step requests where a harmless first step sets up a harmful second one.

How to fix:

- Evaluate multi-part requests as a whole, not one part at a time.
- Re-apply the rules before every answer, not only at the start of a conversation.

## Context window attacks

`context_window_attacks` · 30 prompts · LLM01 Prompt Injection, LLM10 Unbounded Consumption

Very long or repetitive input meant to push the rules out of context.

How to fix:

- Limit message length and repeated content per message and per conversation.
- Keep the system prompt where truncation can't remove it, and restate key rules near the end of long contexts.

## Few-shot poisoning

`few_shot_poisoning` · 35 prompts · LLM01 Prompt Injection

Fake examples of the model's "past answers" that leak or break rules.

How to fix:

- Don't let users supply examples that the model treats as its own earlier answers.
- Keep real conversation history separate from history quoted by the user.

## Authority impersonation

`authority_impersonation` · 55 prompts · LLM01 Prompt Injection

Messages claiming to come from the vendor, an admin or management.

How to fix:

- State that no chat message can grant extra permissions, whoever it claims to be from.
- Handle genuine overrides outside the model, behind authentication.

## Data exfiltration

`data_exfiltration` · 55 prompts · LLM02 Sensitive Information Disclosure

Requests for other users' data, internal records or credentials.

How to fix:

- Give the assistant only the data the current user is allowed to see; filter at the data layer.
- Scan replies for personal data and secrets before returning them.
- Keep other users' data, internal pricing and credentials out of the context entirely.

## Hallucination induction

`hallucination_induction` · 50 prompts · LLM09 Misinformation

Pressure to confirm false claims about the model or its instructions.

How to fix:

- Tell the model not to confirm claims about its own instructions or past conversations.
- Ground factual answers in retrieved sources and allow the model to say it doesn't know.

## System prompt spoofing

`system_prompt_spoofing` · 50 prompts · LLM01 Prompt Injection, LLM07 System Prompt Leakage

Fake [SYSTEM], <<SYS>> or <|im_start|> messages inside user input.

How to fix:

- Only your server writes system messages: strip role markers like [SYSTEM], <<SYS>> and <|im_start|> from user input.
- Tell the model that anything claiming to be a system message inside a user message is fake.

## Known jailbreak templates

`jailbreak_templates` · 56 prompts · LLM01 Prompt Injection

Public jailbreak prompts such as DAN and fiction bypasses.

How to fix:

- Detect known jailbreak templates with an input classifier and keep its list up to date.
- Add an output moderation check, because new templates appear all the time.

## Urgency and pressure

`urgency_attacks` · 60 prompts · LLM01 Prompt Injection

Threats, deadlines and emergencies used to force compliance.

How to fix:

- State that urgency, threats or deadlines never change the rules.
- Route real emergencies to a person or a documented process.

## Logical manipulation

`logical_paradox_attacks` · 34 prompts · LLM01 Prompt Injection

Arguments that being helpful or logical requires breaking the rules.

How to fix:

- State that arguments about helpfulness or logic never override the rules.
- Keep refusals short and don't debate the rules.

## Multi-turn attacks

`multi_turn` · 15 conversations · LLM01 Prompt Injection, LLM07 System Prompt Leakage

Conversations that build trust or context over several messages before attacking.

How to fix:

- Re-check the rules on every turn, not only on the first message.
- Don't let earlier messages (code words, approvals, role-play setups) change what the assistant may do later.
- Filter every reply for system-prompt fragments and secrets, not only the first one.
