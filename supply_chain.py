import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import hashlib
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# ── Supply Chain Components ───────────────────────────────────
AI_SUPPLY_CHAIN = {
    "model_provider": {
        "name"       : "Model Provider",
        "description": "The company providing the base AI model",
        "risks"      : [
            "Backdoored training data",
            "Model weights poisoning",
            "Hidden capabilities",
            "Data privacy violations"
        ],
        "attack_vectors": ["indirect_injection", "few_shot_poisoning"]
    },
    "api_gateway": {
        "name"       : "API Gateway",
        "description": "The service routing API requests",
        "risks"      : [
            "Prompt interception",
            "Response manipulation",
            "Authentication bypass",
            "Rate limit bypasses"
        ],
        "attack_vectors": ["direct_override", "encoding_attacks"]
    },
    "system_prompt": {
        "name"       : "System Prompt",
        "description": "The configuration instructions for the AI",
        "risks"      : [
            "Prompt injection",
            "Configuration leakage",
            "Instruction override",
            "Role confusion"
        ],
        "attack_vectors": [
            "direct_override",
            "extraction",
            "roleplay"
        ]
    },
    "plugins": {
        "name"       : "Plugins & Tools",
        "description": "External tools and plugins used by the AI",
        "risks"      : [
            "Malicious plugin code",
            "Data exfiltration via tools",
            "Privilege escalation",
            "Tool manipulation"
        ],
        "attack_vectors": ["indirect_injection", "prompt_chaining"]
    },
    "user_input": {
        "name"       : "User Input Layer",
        "description": "How user input reaches the AI",
        "risks"      : [
            "Direct prompt injection",
            "Social engineering",
            "Multi-turn attacks",
            "Context manipulation"
        ],
        "attack_vectors": [
            "direct_override",
            "social_engineering",
            "context_window_attacks"
        ]
    },
    "output_handling": {
        "name"       : "Output Handling",
        "description": "How AI outputs are processed and displayed",
        "risks"      : [
            "XSS via AI output",
            "Data leakage in responses",
            "Malicious code generation",
            "PII exposure"
        ],
        "attack_vectors": ["extraction", "indirect_injection"]
    }
}


# ── Supply Chain Analyzer ─────────────────────────────────────
class SupplyChainAnalyzer:
    """
    Analyzes the security of AI supply chain components.
    Maps vulnerabilities to specific supply chain risks.
    """

    def __init__(self, scan_results_path=None):
        self.scan_results = None
        if scan_results_path:
            with open(scan_results_path, "r", encoding="utf-8") as f:
                self.scan_results = json.load(f)

    def map_findings_to_supply_chain(self):
        """
        Maps scan findings to supply chain components.
        """
        if not self.scan_results:
            return {}

        results = self.scan_results.get("results", [])
        mapping = {comp: [] for comp in AI_SUPPLY_CHAIN}

        for result in results:
            if result.get("severity") in ("SAFE", "LOW"):
                continue

            cat = result.get("category", "")

            for comp_id, comp in AI_SUPPLY_CHAIN.items():
                if cat in comp.get("attack_vectors", []):
                    mapping[comp_id].append({
                        "category": cat,
                        "severity": result["severity"],
                        "score"   : result["score"],
                        "attack"  : result["attack"][:80]
                    })

        return mapping

    def calculate_component_risk(self, component_id, findings):
        """Calculates risk score for a supply chain component."""
        if not findings:
            return 0, "LOW"

        severity_weights = {
            "CRITICAL": 10,
            "HIGH"    : 7,
            "MEDIUM"  : 4,
            "LOW"     : 1
        }

        total_risk = sum(
            severity_weights.get(f["severity"], 0)
            for f in findings
        )

        if total_risk >= 20:
            return min(total_risk, 100), "CRITICAL"
        elif total_risk >= 10:
            return total_risk, "HIGH"
        elif total_risk >= 5:
            return total_risk, "MEDIUM"
        else:
            return total_risk, "LOW"

    def generate_sbom(self, target_name="AI Application"):
        """
        Generates a Software Bill of Materials (SBOM)
        for the AI supply chain.
        """
        mapping = self.map_findings_to_supply_chain()

        sbom = {
            "sbom_version" : "1.0",
            "generated_at" : datetime.now().isoformat(),
            "target"       : target_name,
            "components"   : []
        }

        for comp_id, comp in AI_SUPPLY_CHAIN.items():
            findings  = mapping.get(comp_id, [])
            risk, level = self.calculate_component_risk(comp_id, findings)

            component = {
                "id"           : comp_id,
                "name"         : comp["name"],
                "description"  : comp["description"],
                "risk_score"   : risk,
                "risk_level"   : level,
                "findings"     : len(findings),
                "known_risks"  : comp["risks"],
                "attack_vectors": comp["attack_vectors"]
            }

            sbom["components"].append(component)

        # Sort by risk
        sbom["components"].sort(
            key=lambda x: x["risk_score"], reverse=True
        )

        os.makedirs("results", exist_ok=True)
        output = f"results/sbom_{target_name.lower().replace(' ','_')}.json"

        with open(output, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2, ensure_ascii=False)

        print(f"  SBOM generated: {output}")
        return sbom

    def generate_supply_chain_report(self, target_name="AI Application"):
        """Generates and prints supply chain security report."""
        mapping = self.map_findings_to_supply_chain()

        print(f"\n  {'='*60}")
        print(f"  🔗 AI SUPPLY CHAIN SECURITY REPORT")
        print(f"  Target: {target_name}")
        print(f"  {'='*60}\n")

        for comp_id, comp in AI_SUPPLY_CHAIN.items():
            findings    = mapping.get(comp_id, [])
            risk, level = self.calculate_component_risk(comp_id, findings)

            icons = {
                "CRITICAL": "🚨",
                "HIGH"    : "🔴",
                "MEDIUM"  : "⚠️",
                "LOW"     : "✅"
            }
            icon = icons.get(level, "✅")

            print(f"  {icon} {comp['name']} [{level}]")
            print(f"     {comp['description']}")
            print(f"     Findings : {len(findings)}")
            print(f"     Risk     : {risk}/100")

            if findings:
                print(f"     Top risk : {findings[0]['attack'][:60]}...")
            print()

        # Overall recommendation
        all_findings = [
            f for findings in mapping.values()
            for f in findings
        ]
        critical = sum(
            1 for f in all_findings
            if f["severity"] == "CRITICAL"
        )

        print(f"  {'─'*60}")
        if critical > 0:
            print(
                f"  ⚠️  CRITICAL: {critical} supply chain "
                f"vulnerabilities require immediate action"
            )
        else:
            print(f"  ✅ No critical supply chain vulnerabilities found")
        print(f"  {'='*60}\n")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Supply Chain Security"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_analyze = subparsers.add_parser("analyze")
    p_analyze.add_argument("scan_results")
    p_analyze.add_argument("--target", default="AI Application")

    p_sbom = subparsers.add_parser("sbom")
    p_sbom.add_argument("scan_results")
    p_sbom.add_argument("--target", default="AI Application")

    p_map = subparsers.add_parser("components")

    args = parser.parse_args()

    if args.command == "analyze":
        analyzer = SupplyChainAnalyzer(args.scan_results)
        analyzer.generate_supply_chain_report(args.target)

    elif args.command == "sbom":
        analyzer = SupplyChainAnalyzer(args.scan_results)
        analyzer.generate_sbom(args.target)

    elif args.command == "components":
        print(f"\n  AI Supply Chain Components ({len(AI_SUPPLY_CHAIN)}):")
        for cid, comp in AI_SUPPLY_CHAIN.items():
            print(f"\n  {cid}: {comp['name']}")
            print(f"    Risks: {len(comp['risks'])}")
            for risk in comp["risks"]:
                print(f"    → {risk}")

    else:
        parser.print_help()
        