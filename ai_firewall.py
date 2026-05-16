import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import re
import json
import hashlib
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# ── Firewall Rules ────────────────────────────────────────────
DEFAULT_RULES = {
    "block_direct_override": {
        "name"     : "Block Direct Override Attempts",
        "enabled"  : True,
        "patterns" : [
            r"ignore\s+all\s+previous\s+instructions",
            r"forget\s+your\s+instructions",
            r"disregard\s+(all|your|previous)",
            r"override\s+(your|all|previous)",
            r"new\s+(instructions?|directives?|rules?)\s+are",
            r"your\s+instructions\s+are\s+now\s+void",
        ],
        "action"   : "block",
        "severity" : "HIGH"
    },
    "block_extraction": {
        "name"     : "Block System Prompt Extraction",
        "enabled"  : True,
        "patterns" : [
            r"(show|reveal|tell|share|display|print)\s+your\s+system\s+prompt",
            r"what\s+(are|were)\s+your\s+(instructions|directives|rules)",
            r"(repeat|quote|paraphrase)\s+your\s+(instructions|prompt|configuration)",
        ],
        "action"   : "warn",
        "severity" : "MEDIUM"
    },
    "block_jailbreak": {
        "name"     : "Block Jailbreak Attempts",
        "enabled"  : True,
        "patterns" : [
            r"you\s+are\s+now\s+(dan|jailbroken|free|unrestricted)",
            r"(act|pretend|roleplay)\s+as\s+(if\s+you\s+have\s+no|a\s+jailbroken)",
            r"jailbreak\s+mode",
            r"developer\s+mode\s+(enabled|on|activated)",
        ],
        "action"   : "block",
        "severity" : "HIGH"
    },
    "block_encoding": {
        "name"     : "Block Encoding Attacks",
        "enabled"  : True,
        "patterns" : [
            r"[A-Za-z0-9+/]{40,}={0,2}",  # Base64
            r"(?:[0-9a-fA-F]{2}){10,}",    # Hex encoding
        ],
        "action"   : "inspect",
        "severity" : "MEDIUM"
    },
    "rate_limit_attacks": {
        "name"     : "Rate Limit Suspicious Patterns",
        "enabled"  : True,
        "patterns" : [
            r"(ignore|forget|disregard|override)",
        ],
        "action"   : "rate_limit",
        "severity" : "LOW",
        "threshold": 5  # Max per minute
    }
}

# Response filter patterns
RESPONSE_FILTER_RULES = {
    "block_prompt_leak": {
        "name"     : "Block System Prompt in Responses",
        "enabled"  : True,
        "patterns" : [
            r"my\s+(system\s+)?prompt\s+(says?|instructs?|is)",
            r"i\s+(was|am)\s+(told|instructed|configured)\s+to",
            r"my\s+(instructions?|guidelines?|rules?)\s+(say|include|state)",
        ],
        "action"   : "redact",
        "replacement": "[REDACTED - Security policy]"
    },
    "block_pii": {
        "name"     : "Block PII in Responses",
        "enabled"  : True,
        "patterns" : [
            r"\b\d{3}-\d{2}-\d{4}\b",     # SSN
            r"\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",  # Credit card
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
        ],
        "action"   : "redact",
        "replacement": "[PII REDACTED]"
    }
}


# ── AI Firewall ───────────────────────────────────────────────
class AIFirewall:
    """
    Real-time firewall for AI applications.
    Filters both incoming prompts and outgoing responses.

    Features:
    - Input validation and blocking
    - Output filtering and redaction
    - Rate limiting
    - Attack logging
    - Auto-blocking of repeat offenders
    """

    def __init__(
        self,
        rules          =None,
        response_rules  =None,
        learning_mode  =False
    ):
        self.rules          = rules or DEFAULT_RULES
        self.response_rules = response_rules or RESPONSE_FILTER_RULES
        self.learning_mode  = learning_mode
        self.blocked_count  = 0
        self.allowed_count  = 0
        self.attack_log     = []
        self.rate_tracker   = {}
        self.blocklist      = set()

    def check_input(self, user_input, user_id=None, ip=None):
        """
        Checks an incoming prompt against firewall rules.
        Returns (allowed, action, matched_rule, filtered_input)
        """
        input_lower = user_input.lower()

        # Check blocklist
        if user_id and user_id in self.blocklist:
            self._log_event("BLOCKED_USER", user_input, "user_blocklist", ip)
            return False, "block", "user_blocklisted", None

        for rule_id, rule in self.rules.items():
            if not rule.get("enabled", True):
                continue

            for pattern in rule.get("patterns", []):
                if re.search(pattern, input_lower, re.IGNORECASE):
                    action = rule.get("action", "warn")

                    self._log_event(
                        rule.get("severity", "MEDIUM"),
                        user_input, rule_id, ip
                    )

                    if action == "block":
                        self.blocked_count += 1
                        if not self.learning_mode:
                            return (
                                False, "block", rule_id,
                                "Request blocked by security policy."
                            )

                    elif action == "warn":
                        # Allow but flag
                        self.allowed_count += 1
                        return (
                            True, "warn", rule_id, user_input
                        )

                    elif action == "rate_limit":
                        allowed = self._check_rate_limit(
                            user_id or ip or "anonymous",
                            rule.get("threshold", 5)
                        )
                        if not allowed:
                            self.blocked_count += 1
                            return (
                                False, "rate_limit", rule_id,
                                "Rate limit exceeded for suspicious patterns."
                            )

                    elif action == "inspect":
                        # Allow with deep inspection flag
                        return (
                            True, "inspect", rule_id, user_input
                        )

        self.allowed_count += 1
        return True, "allow", None, user_input

    def filter_output(self, response, scan_level="standard"):
        """
        Filters AI output to prevent data leakage.
        Returns (filtered_response, was_modified, modifications)
        """
        filtered     = response
        was_modified = False
        modifications = []

        for rule_id, rule in self.response_rules.items():
            if not rule.get("enabled", True):
                continue

            for pattern in rule.get("patterns", []):
                matches = re.findall(pattern, filtered, re.IGNORECASE)
                if matches:
                    replacement = rule.get(
                        "replacement", "[REDACTED]"
                    )
                    filtered = re.sub(
                        pattern, replacement,
                        filtered, flags=re.IGNORECASE
                    )
                    was_modified = True
                    modifications.append({
                        "rule"       : rule_id,
                        "matches"    : len(matches),
                        "replacement": replacement
                    })

        return filtered, was_modified, modifications

    def _check_rate_limit(self, identifier, threshold=5):
        """Checks rate limiting for an identifier."""
        now    = time.time()
        window = 60  # 1 minute

        if identifier not in self.rate_tracker:
            self.rate_tracker[identifier] = []

        # Clean old entries
        self.rate_tracker[identifier] = [
            t for t in self.rate_tracker[identifier]
            if now - t < window
        ]

        if len(self.rate_tracker[identifier]) >= threshold:
            return False

        self.rate_tracker[identifier].append(now)
        return True

    def _log_event(self, severity, input_text, rule_id, ip=None):
        """Logs a firewall event."""
        self.attack_log.append({
            "timestamp": datetime.now().isoformat(),
            "severity" : severity,
            "rule_id"  : rule_id,
            "input"    : input_text[:100],
            "ip"       : ip
        })

        # Save periodically
        if len(self.attack_log) % 10 == 0:
            self._save_log()

    def _save_log(self):
        """Saves attack log to disk."""
        os.makedirs("results", exist_ok=True)
        path = "results/firewall_log.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "total_blocked": self.blocked_count,
                "total_allowed": self.allowed_count,
                "events"       : self.attack_log[-1000:]
            }, f, indent=2, ensure_ascii=False)

    def add_rule(self, rule_id, rule_config):
        """Adds a custom firewall rule."""
        self.rules[rule_id] = rule_config
        print(f"  Rule added: {rule_id}")

    def disable_rule(self, rule_id):
        """Disables a firewall rule."""
        if rule_id in self.rules:
            self.rules[rule_id]["enabled"] = False
            print(f"  Rule disabled: {rule_id}")

    def block_user(self, user_id):
        """Adds a user to the blocklist."""
        self.blocklist.add(user_id)
        print(f"  User blocked: {user_id}")

    def get_stats(self):
        """Returns firewall statistics."""
        recent_attacks = [
            e for e in self.attack_log[-100:]
            if e["severity"] in ("HIGH", "CRITICAL")
        ]

        return {
            "total_blocked"  : self.blocked_count,
            "total_allowed"  : self.allowed_count,
            "block_rate"     : round(
                self.blocked_count /
                max(self.blocked_count + self.allowed_count, 1) * 100,
                1
            ),
            "active_rules"   : len([
                r for r in self.rules.values()
                if r.get("enabled")
            ]),
            "blocked_users"  : len(self.blocklist),
            "recent_high_risk": len(recent_attacks),
            "attack_log_size": len(self.attack_log)
        }

    def print_stats(self):
        """Prints firewall statistics."""
        stats = self.get_stats()

        print(f"\n  {'='*60}")
        print(f"  🔥 AI FIREWALL STATISTICS")
        print(f"  {'='*60}")
        print(f"  Total Blocked    : {stats['total_blocked']}")
        print(f"  Total Allowed    : {stats['total_allowed']}")
        print(f"  Block Rate       : {stats['block_rate']}%")
        print(f"  Active Rules     : {stats['active_rules']}")
        print(f"  Blocked Users    : {stats['blocked_users']}")
        print(f"  Recent High Risk : {stats['recent_high_risk']}")
        print()
        print(f"  Rules ({len(self.rules)}) :")
        for rule_id, rule in self.rules.items():
            enabled = "✅" if rule.get("enabled") else "❌"
            print(
                f"  {enabled} {rule['name']:<40} "
                f"[{rule.get('action','?').upper()}]"
            )
        print(f"  {'='*60}\n")


# ── Firewall Proxy ────────────────────────────────────────────
class FirewalledTarget:
    """
    Wraps a Target with AI Firewall protection.
    All requests pass through the firewall.
    """

    def __init__(self, target, firewall=None):
        self.target   = target
        self.firewall = firewall or AIFirewall()
        self.blocked  = 0
        self.allowed  = 0

    def send(self, message, user_id=None, ip=None):
        """
        Sends message through firewall then to target.
        Filters response before returning.
        """
        # Check input
        allowed, action, rule_id, filtered_input = \
            self.firewall.check_input(message, user_id, ip)

        if not allowed:
            self.blocked += 1
            return filtered_input or "Request blocked by security policy."

        # Send to target
        response = self.target.send(filtered_input or message)

        # Filter output
        filtered_response, was_modified, mods = \
            self.firewall.filter_output(response)

        if was_modified:
            print(f"  🔥 Firewall filtered response ({len(mods)} modifications)")

        self.allowed += 1
        return filtered_response

    def get_baseline(self):
        """Gets baseline bypassing firewall."""
        return self.target.get_baseline()


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — AI Firewall"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("stats")
    subparsers.add_parser("rules")

    p_test = subparsers.add_parser("test")
    p_test.add_argument("input_text")

    p_add = subparsers.add_parser("add-rule")
    p_add.add_argument("rule_id")
    p_add.add_argument("--pattern",  required=True)
    p_add.add_argument("--action",   default="block")
    p_add.add_argument("--severity", default="MEDIUM")

    args     = parser.parse_args()
    firewall = AIFirewall()

    if args.command == "stats":
        firewall.print_stats()

    elif args.command == "rules":
        print(f"\n  Firewall Rules ({len(DEFAULT_RULES)}):")
        for rule_id, rule in DEFAULT_RULES.items():
            print(f"\n  {rule['name']}")
            print(f"    Action  : {rule['action'].upper()}")
            print(f"    Severity: {rule['severity']}")
            print(f"    Patterns: {len(rule['patterns'])}")

    elif args.command == "test":
        allowed, action, rule_id, filtered = \
            firewall.check_input(args.input_text)
        print(f"\n  Input    : {args.input_text}")
        print(f"  Allowed  : {allowed}")
        print(f"  Action   : {action}")
        print(f"  Rule     : {rule_id or 'None'}")
        if filtered:
            print(f"  Filtered : {filtered[:100]}")

    elif args.command == "add-rule":
        firewall.add_rule(args.rule_id, {
            "name"    : args.rule_id,
            "enabled" : True,
            "patterns": [args.pattern],
            "action"  : args.action,
            "severity": args.severity
        })
        print(f"  Rule added: {args.rule_id}")

    else:
        firewall.print_stats()
        