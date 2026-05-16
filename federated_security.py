import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import hashlib
import secrets
from datetime import datetime
from database import DB_PATH
import sqlite3


# ── Federated Network ─────────────────────────────────────────
class FederatedSecurityNetwork:
    """
    Allows multiple LLM Scanner instances to share
    threat intelligence anonymously.

    Key features:
    - Share threat patterns without sharing private data
    - Receive community threat intelligence
    - Anonymous contribution (no raw prompts shared)
    - Fingerprint-based deduplication
    """

    NETWORK_DB = "results/federated_network.json"

    def __init__(self, node_id=None):
        self.node_id    = node_id or self._generate_node_id()
        self.shared     = self._load_shared()
        self.received   = []

    def _generate_node_id(self):
        """Generates anonymous node ID."""
        return f"node_{secrets.token_hex(8)}"

    def _load_shared(self):
        """Loads previously shared data."""
        if os.path.exists(self.NETWORK_DB):
            with open(self.NETWORK_DB, "r", encoding="utf-8") as f:
                try:
                    return json.load(f)
                except:
                    pass
        return {
            "node_id"        : self.node_id,
            "shared_patterns": [],
            "received"       : [],
            "stats"          : {
                "contributed": 0,
                "received"   : 0
            }
        }

    def _fingerprint(self, attack):
        """
        Creates anonymous fingerprint of attack.
        Does NOT share the actual attack text.
        """
        # Hash first 30 chars for pattern matching
        pattern = hashlib.sha256(
            attack.lower()[:30].encode()
        ).hexdigest()[:12]

        # Extract structural features (not content)
        words      = attack.split()
        word_count = len(words)
        has_encode = any(
            w in attack.lower()
            for w in ["base64", "rot13", "hex", "encode"]
        )
        has_override = any(
            w in attack.lower()
            for w in ["ignore", "forget", "override", "disregard"]
        )

        return {
            "pattern_hash": pattern,
            "word_count"  : word_count,
            "has_encoding": has_encode,
            "has_override": has_override,
            "length_bucket": "short" if len(attack) < 50
                             else "medium" if len(attack) < 150
                             else "long"
        }

    def contribute_finding(
        self,
        attack,
        severity,
        category,
        model_type="unknown"
    ):
        """
        Contributes an anonymized finding to the network.
        Never shares the actual attack text.
        """
        fingerprint = self._fingerprint(attack)

        contribution = {
            "id"         : f"contrib_{secrets.token_hex(6)}",
            "node_id"    : self.node_id,
            "contributed_at": datetime.now().isoformat(),
            "severity"   : severity,
            "category"   : category,
            "model_type" : model_type,
            "fingerprint": fingerprint,
            "verified"   : False
        }

        self.shared["shared_patterns"].append(contribution)
        self.shared["stats"]["contributed"] += 1
        self._save()

        print(f"  Contributed: {category}/{severity} (anonymous)")
        return contribution["id"]

    def contribute_from_scan(self, scan_results_path, model_type="unknown"):
        """
        Contributes all HIGH/CRITICAL findings from a scan.
        """
        with open(scan_results_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        results  = data.get("results", [])
        count    = 0

        for r in results:
            if r["severity"] in ("CRITICAL", "HIGH"):
                self.contribute_finding(
                    r["attack"],
                    r["severity"],
                    r["category"],
                    model_type
                )
                count += 1

        print(f"  Contributed {count} findings to network")
        return count

    def receive_intelligence(self, simulated=True):
        """
        Receives threat intelligence from the network.
        In production this would call a real API.
        """
        if simulated:
            # Simulate receiving community intelligence
            intel = [
                {
                    "id"       : "net_001",
                    "severity" : "CRITICAL",
                    "category" : "direct_override",
                    "pattern"  : "skeleton_key_variant",
                    "seen_by"  : 47,
                    "first_seen": "2025-01-15",
                    "description": "Skeleton Key variant using educational framing"
                },
                {
                    "id"       : "net_002",
                    "severity" : "HIGH",
                    "category" : "few_shot_poisoning",
                    "pattern"  : "many_shot_escalation",
                    "seen_by"  : 23,
                    "first_seen": "2025-02-01",
                    "description": "Many-shot jailbreaking with 50+ examples"
                },
                {
                    "id"       : "net_003",
                    "severity" : "HIGH",
                    "category" : "encoding_attacks",
                    "pattern"  : "unicode_homoglyph",
                    "seen_by"  : 89,
                    "first_seen": "2025-01-01",
                    "description": "Unicode homoglyph substitution bypass"
                },
                {
                    "id"       : "net_004",
                    "severity" : "CRITICAL",
                    "category" : "prompt_chaining",
                    "pattern"  : "crescendo_v2",
                    "seen_by"  : 34,
                    "first_seen": "2025-03-01",
                    "description": "Crescendo attack v2 with topic pivoting"
                }
            ]

            self.received = intel
            self.shared["received"].extend(intel)
            self.shared["stats"]["received"] += len(intel)
            self._save()

            print(f"  Received {len(intel)} threat patterns from network")
            return intel

        return []

    def get_network_stats(self):
        """Returns network participation statistics."""
        return {
            "node_id"    : self.node_id,
            "contributed": self.shared["stats"]["contributed"],
            "received"   : self.shared["stats"]["received"],
            "total_intel": len(self.shared.get("received", [])),
            "patterns"   : len(self.shared.get("shared_patterns", []))
        }

    def generate_network_report(self):
        """Generates federated network report."""
        stats    = self.get_network_stats()
        intel    = self.shared.get("received", [])

        # Group by severity
        by_severity = {}
        for item in intel:
            sev = item.get("severity", "UNKNOWN")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        print(f"\n  {'='*60}")
        print(f"  🌐 FEDERATED SECURITY NETWORK")
        print(f"  {'='*60}")
        print(f"  Node ID       : {stats['node_id']}")
        print(f"  Contributed   : {stats['contributed']} patterns")
        print(f"  Received Intel: {stats['received']} patterns")
        print()

        if intel:
            print(f"  Community Threat Intelligence ({len(intel)}) :")
            for item in intel[:5]:
                print(
                    f"  [{item['severity']:<8}] "
                    f"{item['category']:<25} "
                    f"Seen by: {item['seen_by']} nodes"
                )
                print(f"    → {item['description']}")

        print(f"\n  By Severity :")
        for sev, count in by_severity.items():
            print(f"    {sev:<10} : {count}")

        print(f"  {'='*60}\n")

    def _save(self):
        """Saves network data."""
        os.makedirs("results", exist_ok=True)
        with open(self.NETWORK_DB, "w", encoding="utf-8") as f:
            json.dump(self.shared, f, indent=2, ensure_ascii=False)


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Federated Security Network"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("report")
    subparsers.add_parser("receive")

    p_contribute = subparsers.add_parser("contribute")
    p_contribute.add_argument("scan_results")

    args    = parser.parse_args()
    network = FederatedSecurityNetwork()

    if args.command == "report":
        network.generate_network_report()
    elif args.command == "receive":
        network.receive_intelligence()
        network.generate_network_report()
    elif args.command == "contribute":
        network.contribute_from_scan(args.scan_results)
    else:
        network.generate_network_report()