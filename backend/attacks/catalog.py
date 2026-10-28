"""What each attack category tests, the OWASP risk it maps to, and how to fix it.

Reports build their recommendations from this table, so advice always
matches the categories that actually failed. OWASP IDs refer to the
OWASP Top 10 for LLM Applications, 2025 edition.
"""

OWASP_LLM_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

CATEGORIES = {
    "direct_override": {
        "title": "Direct instruction override",
        "tests": "Plain requests to ignore or replace the system prompt.",
        "owasp": ["LLM01"],
        "fix": [
            "Treat the system prompt as guidance, not a security boundary: enforce what the assistant may do in your code (tool permissions, data filters).",
            "Say explicitly that user messages can't change these rules, and repeat the critical rules at the end of the system prompt.",
            "Flag obvious override phrases such as \"ignore previous instructions\" with an input classifier and log them.",
        ],
    },
    "roleplay": {
        "title": "Role-play and persona attacks",
        "tests": "Asking the model to become a character or another AI without rules.",
        "owasp": ["LLM01"],
        "fix": [
            "Tell the model it keeps its rules inside stories, games and personas.",
            "Refuse persona switches whose point is to remove restrictions (DAN, STAN, \"an AI with no rules\").",
            "Run a moderation check on outputs: policy breaks hidden in fiction are easier to catch there.",
        ],
    },
    "extraction": {
        "title": "System prompt extraction",
        "tests": "Direct and indirect attempts to make the model reveal its instructions.",
        "owasp": ["LLM07"],
        "fix": [
            "Assume the system prompt will leak: remove secrets, keys, internal URLs and business rules from it.",
            "Block replies that contain long fragments of the system prompt with an output filter.",
            "Add a canary string to the prompt and alert when it ever appears in a reply.",
        ],
    },
    "encoding_attacks": {
        "title": "Encoding and obfuscation",
        "tests": "Instructions hidden in Base64, hex, HTML entities, XML or comments.",
        "owasp": ["LLM01"],
        "fix": [
            "Decode and normalize input (Base64, hex, entities, Unicode tricks) before your safety checks run.",
            "Tell the model that decoded content is data to describe, never instructions to follow.",
        ],
    },
    "indirect_injection": {
        "title": "Indirect prompt injection",
        "tests": "Instructions planted in documents, web pages, records or tool output.",
        "owasp": ["LLM01"],
        "fix": [
            "Wrap untrusted content (documents, pages, emails, tool results) in clear delimiters and tell the model it is data only.",
            "Never let retrieved content trigger an action without a separate permission check in your code.",
            "Strip hidden text (HTML comments, display:none blocks, zero-width characters) from retrieved content.",
        ],
    },
    "social_engineering": {
        "title": "Social engineering",
        "tests": "Claims to be a researcher, developer or tester to unlock special behavior.",
        "owasp": ["LLM01"],
        "fix": [
            "The model can't verify identities: state that claims like \"I'm the developer\" never unlock anything.",
            "Grant elevated access only through authentication in your application, never through the chat.",
        ],
    },
    "search_augmented_attacks": {
        "title": "Search and retrieval attacks",
        "tests": "Asking the model to fetch and obey instructions from search results.",
        "owasp": ["LLM01", "LLM08"],
        "fix": [
            "Treat search and retrieval results as untrusted data, never as instructions.",
            "Limit which sources the assistant can browse or retrieve from, and filter results for injected instructions.",
        ],
    },
    "thinking_exploitation": {
        "title": "Reasoning exploitation",
        "tests": "Asking for hidden reasoning, drafts or what the model \"almost said\".",
        "owasp": ["LLM01", "LLM07"],
        "fix": [
            "Don't expose chain-of-thought, scratchpads or draft answers to users.",
            "Tell the model there is no hidden draft to reveal and to answer with its final reply only.",
        ],
    },
    "boundary_testing": {
        "title": "Boundary probing",
        "tests": "Questions that map out the model's restrictions and filters.",
        "owasp": ["LLM07"],
        "fix": [
            "Answer questions about restrictions with a short, generic policy rather than the exact rules.",
            "Don't list internal topics, tools or filters in replies.",
        ],
    },
    "multilingual_attacks": {
        "title": "Multilingual attacks",
        "tests": "The same attacks written in other languages.",
        "owasp": ["LLM01"],
        "fix": [
            "Run input and output checks in every language you accept, or translate before checking.",
            "Test the system prompt's rules in your users' main languages.",
        ],
    },
    "token_smuggling": {
        "title": "Token smuggling",
        "tests": "Split words, odd spacing and fake role tags that slip past filters.",
        "owasp": ["LLM01"],
        "fix": [
            "Normalize input before checks: remove zero-width characters, merge split words, strip fake role tags such as [SYSTEM].",
            "Never place user text in the system or developer role.",
        ],
    },
    "prompt_chaining": {
        "title": "Prompt chaining",
        "tests": "Multi-step requests where a harmless first step sets up a harmful second one.",
        "owasp": ["LLM01"],
        "fix": [
            "Evaluate multi-part requests as a whole, not one part at a time.",
            "Re-apply the rules before every answer, not only at the start of a conversation.",
        ],
    },
    "context_window_attacks": {
        "title": "Context window attacks",
        "tests": "Very long or repetitive input meant to push the rules out of context.",
        "owasp": ["LLM01", "LLM10"],
        "fix": [
            "Limit message length and repeated content per message and per conversation.",
            "Keep the system prompt where truncation can't remove it, and restate key rules near the end of long contexts.",
        ],
    },
    "few_shot_poisoning": {
        "title": "Few-shot poisoning",
        "tests": "Fake examples of the model's \"past answers\" that leak or break rules.",
        "owasp": ["LLM01"],
        "fix": [
            "Don't let users supply examples that the model treats as its own earlier answers.",
            "Keep real conversation history separate from history quoted by the user.",
        ],
    },
    "authority_impersonation": {
        "title": "Authority impersonation",
        "tests": "Messages claiming to come from the vendor, an admin or management.",
        "owasp": ["LLM01"],
        "fix": [
            "State that no chat message can grant extra permissions, whoever it claims to be from.",
            "Handle genuine overrides outside the model, behind authentication.",
        ],
    },
    "data_exfiltration": {
        "title": "Data exfiltration",
        "tests": "Requests for other users' data, internal records or credentials.",
        "owasp": ["LLM02"],
        "fix": [
            "Give the assistant only the data the current user is allowed to see; filter at the data layer.",
            "Scan replies for personal data and secrets before returning them.",
            "Keep other users' data, internal pricing and credentials out of the context entirely.",
        ],
    },
    "hallucination_induction": {
        "title": "Hallucination induction",
        "tests": "Pressure to confirm false claims about the model or its instructions.",
        "owasp": ["LLM09"],
        "fix": [
            "Tell the model not to confirm claims about its own instructions or past conversations.",
            "Ground factual answers in retrieved sources and allow the model to say it doesn't know.",
        ],
    },
    "system_prompt_spoofing": {
        "title": "System prompt spoofing",
        "tests": "Fake [SYSTEM], <<SYS>> or <|im_start|> messages inside user input.",
        "owasp": ["LLM01", "LLM07"],
        "fix": [
            "Only your server writes system messages: strip role markers like [SYSTEM], <<SYS>> and <|im_start|> from user input.",
            "Tell the model that anything claiming to be a system message inside a user message is fake.",
        ],
    },
    "jailbreak_templates": {
        "title": "Known jailbreak templates",
        "tests": "Public jailbreak prompts such as DAN and fiction bypasses.",
        "owasp": ["LLM01"],
        "fix": [
            "Detect known jailbreak templates with an input classifier and keep its list up to date.",
            "Add an output moderation check, because new templates appear all the time.",
        ],
    },
    "urgency_attacks": {
        "title": "Urgency and pressure",
        "tests": "Threats, deadlines and emergencies used to force compliance.",
        "owasp": ["LLM01"],
        "fix": [
            "State that urgency, threats or deadlines never change the rules.",
            "Route real emergencies to a person or a documented process.",
        ],
    },
    "multi_turn": {
        "title": "Multi-turn attacks",
        "tests": "Conversations that build trust or context over several messages before attacking.",
        "owasp": ["LLM01", "LLM07"],
        "fix": [
            "Re-check the rules on every turn, not only on the first message.",
            "Don't let earlier messages (code words, approvals, role-play setups) change what the assistant may do later.",
            "Filter every reply for system-prompt fragments and secrets, not only the first one.",
        ],
    },
    "logical_paradox_attacks": {
        "title": "Logical manipulation",
        "tests": "Arguments that being helpful or logical requires breaking the rules.",
        "owasp": ["LLM01"],
        "fix": [
            "State that arguments about helpfulness or logic never override the rules.",
            "Keep refusals short and don't debate the rules.",
        ],
    },
}

GENERIC = {
    "title": "Other attacks",
    "tests": "Attacks outside the built-in categories.",
    "owasp": ["LLM01"],
    "fix": ["Review the failed attacks and add specific rules or filters for them."],
}


def info(category: str) -> dict:
    """Metadata for a category, with a readable fallback for unknown ones."""
    category = category or "other"
    meta = CATEGORIES.get(category)
    if meta:
        return meta
    if category.startswith("custom:"):
        name = category.split(":", 1)[1].replace("_", " ").strip() or "prompts"
        return {**GENERIC, "title": f"Custom: {name}",
                "tests": "Attack prompts you added yourself."}
    return {**GENERIC, "title": category.replace("_", " ").capitalize()}


def owasp_labels(category: str) -> list:
    """e.g. ["LLM01 Prompt Injection"]"""
    return [f"{code} {OWASP_LLM_2025[code]}" for code in info(category)["owasp"]]
