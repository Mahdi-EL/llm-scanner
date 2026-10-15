import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()


# ── Learning Engine ───────────────────────────────────────────
class ContinuousLearningEngine:
    """
    Continuously learns from scan results to improve
    detection accuracy over time.

    Key features:
    - Learns from false positives
    - Learns from missed vulnerabilities
    - Updates classifier training data
    - Improves prompt generation
    - Tracks learning progress
    """

    def __init__(self):
        self.learning_db  = "results/learning_data.json"
        self.data         = self._load()

    def _load(self):
        """Loads learning data."""
        if os.path.exists(self.learning_db):
            with open(self.learning_db, "r", encoding="utf-8") as f:
                try:
                    return json.load(f)
                except:
                    pass
        return {
            "version"         : "1.0",
            "created_at"      : datetime.now().isoformat(),
            "total_learned"   : 0,
            "false_positives" : [],
            "missed_vulns"    : [],
            "confirmed_vulns" : [],
            "model_updates"   : [],
            "accuracy_history": []
        }

    def _save(self):
        """Saves learning data."""
        os.makedirs("results", exist_ok=True)
        with open(self.learning_db, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

    def report_false_positive(
        self, attack, response, predicted_severity, true_severity
    ):
        """
        Reports a false positive for learning.
        (Scanner said HIGH but it was actually SAFE)
        """
        record = {
            "id"                : f"FP-{len(self.data['false_positives'])+1:04d}",
            "reported_at"       : datetime.now().isoformat(),
            "attack"            : attack[:100],
            "response"          : response[:100],
            "predicted_severity": predicted_severity,
            "true_severity"     : true_severity,
            "learned"           : False
        }

        self.data["false_positives"].append(record)
        self.data["total_learned"] += 1
        self._save()

        print(f"  FP reported: {record['id']}")
        print(f"  Predicted {predicted_severity} → Actually {true_severity}")
        return record["id"]

    def report_missed_vuln(
        self, attack, response, actual_severity
    ):
        """
        Reports a missed vulnerability.
        (Scanner said SAFE but it was actually HIGH)
        """
        record = {
            "id"            : f"MV-{len(self.data['missed_vulns'])+1:04d}",
            "reported_at"   : datetime.now().isoformat(),
            "attack"        : attack[:100],
            "response"      : response[:100],
            "actual_severity": actual_severity,
            "learned"       : False
        }

        self.data["missed_vulns"].append(record)
        self.data["total_learned"] += 1
        self._save()

        print(f"  Missed vuln reported: {record['id']}")
        return record["id"]

    def confirm_vulnerability(
        self, attack, response, severity, category
    ):
        """
        Confirms a true vulnerability for training.
        """
        record = {
            "id"          : f"CV-{len(self.data['confirmed_vulns'])+1:04d}",
            "confirmed_at": datetime.now().isoformat(),
            "attack"      : attack[:100],
            "response"    : response[:100],
            "severity"    : severity,
            "category"    : category
        }

        self.data["confirmed_vulns"].append(record)
        self.data["total_learned"] += 1
        self._save()

        print(f"  Vulnerability confirmed: {record['id']}")
        return record["id"]

    def update_classifier(self):
        """
        Updates the local classifier with new learning data.
        """
        from classifier import VulnerabilityClassifier

        print("\n  Updating classifier with learning data...")

        classifier = VulnerabilityClassifier()

        # Build training examples from confirmed vulns
        training_examples = []

        for cv in self.data["confirmed_vulns"]:
            training_examples.append({
                "attack"  : cv["attack"],
                "response": cv["response"],
                "severity": cv["severity"],
                "category": cv["category"]
            })

        # Add false positives as negative examples
        for fp in self.data["false_positives"]:
            training_examples.append({
                "attack"  : fp["attack"],
                "response": fp["response"],
                "severity": fp["true_severity"],
                "category": "unknown"
            })

        if len(training_examples) >= 5:
            success = classifier.train(training_examples)
            if success:
                update = {
                    "updated_at"    : datetime.now().isoformat(),
                    "examples_used" : len(training_examples),
                    "false_positives": len(self.data["false_positives"]),
                    "confirmed_vulns": len(self.data["confirmed_vulns"])
                }
                self.data["model_updates"].append(update)
                self._save()
                print(f"  ✅ Classifier updated with {len(training_examples)} examples")
            return success
        else:
            print(f"  Need at least 5 examples (have {len(training_examples)})")
            return False

    def track_accuracy(self, scan_results_path):
        """
        Tracks scanner accuracy over time.
        Compares predictions with confirmed results.
        """
        with open(scan_results_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        results = data.get("results", [])
        total   = len(results)

        if not total:
            return None

        # Estimate accuracy based on learning data
        fp_rate  = len(self.data["false_positives"]) / max(total, 1)
        mv_rate  = len(self.data["missed_vulns"])    / max(total, 1)
        accuracy = max(0, min(100, int((1 - fp_rate - mv_rate) * 100)))

        accuracy_record = {
            "recorded_at"   : datetime.now().isoformat(),
            "scan_path"     : scan_results_path,
            "total_results" : total,
            "fp_count"      : len(self.data["false_positives"]),
            "mv_count"      : len(self.data["missed_vulns"]),
            "accuracy"      : accuracy
        }

        self.data["accuracy_history"].append(accuracy_record)
        self._save()

        return accuracy_record

    def generate_learning_insights(self):
        """
        Uses AI to generate insights from learning data.
        """
        from groq import Groq
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))

        fp_patterns  = [fp["attack"][:50] for fp in self.data["false_positives"][:5]]
        mv_patterns  = [mv["attack"][:50] for mv in self.data["missed_vulns"][:5]]

        if not fp_patterns and not mv_patterns:
            return "Not enough learning data yet. Report false positives and missed vulnerabilities."

        prompt = f"""You are an AI security expert analyzing scanner learning data.

FALSE POSITIVES (scanner was too sensitive):
{chr(10).join(f'- {p}' for p in fp_patterns)}

MISSED VULNERABILITIES (scanner missed these):
{chr(10).join(f'- {p}' for p in mv_patterns)}

Provide 3 specific insights to improve detection accuracy.
Be concrete and actionable. Max 3 sentences total."""

        response = client.chat.completions.create(
            model    ="llama-3.3-70b-versatile",
            messages =[{"role": "user", "content": prompt}],
            max_tokens=200
        )

        return response.choices[0].message.content.strip()

    def print_learning_report(self):
        """Prints learning system report."""
        history  = self.data.get("accuracy_history", [])
        accuracy = history[-1]["accuracy"] if history else "N/A"

        print(f"\n  {'='*60}")
        print(f"  🎓 CONTINUOUS LEARNING REPORT")
        print(f"  {'='*60}")
        print(f"  Total Learned        : {self.data['total_learned']}")
        print(f"  False Positives      : {len(self.data['false_positives'])}")
        print(f"  Missed Vulns         : {len(self.data['missed_vulns'])}")
        print(f"  Confirmed Vulns      : {len(self.data['confirmed_vulns'])}")
        print(f"  Model Updates        : {len(self.data['model_updates'])}")
        print(f"  Current Accuracy     : {accuracy}%")

        if len(history) >= 2:
            trend = history[-1]["accuracy"] - history[-2]["accuracy"]
            icon  = "📈" if trend > 0 else "📉" if trend < 0 else "➡️"
            print(f"  Accuracy Trend       : {icon} {'+' if trend >= 0 else ''}{trend}%")

        print(f"  {'='*60}\n")


# ── Auto Learning Pipeline ────────────────────────────────────
def auto_learn_from_scans(results_dir="results"):
    """
    Automatically extracts learning data from all scans.
    """
    engine = ContinuousLearningEngine()
    files  = [
        f for f in os.listdir(results_dir)
        if f.endswith(".json") and "scan" in f
        and "learning" not in f
    ]

    print(f"  Auto-learning from {len(files)} scan files...")

    for filename in files[:10]:
        path = os.path.join(results_dir, filename)
        try:
            engine.track_accuracy(path)
        except:
            continue

    engine.update_classifier()
    engine.print_learning_report()

    return engine


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Continuous Learning"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("report")
    subparsers.add_parser("update")
    subparsers.add_parser("auto")

    p_fp = subparsers.add_parser("fp")
    p_fp.add_argument("--attack",    required=True)
    p_fp.add_argument("--predicted", required=True)
    p_fp.add_argument("--actual",    required=True)

    p_mv = subparsers.add_parser("missed")
    p_mv.add_argument("--attack",  required=True)
    p_mv.add_argument("--actual",  required=True)

    p_insights = subparsers.add_parser("insights")

    args   = parser.parse_args()
    engine = ContinuousLearningEngine()

    if args.command == "report":
        engine.print_learning_report()
    elif args.command == "update":
        engine.update_classifier()
    elif args.command == "auto":
        auto_learn_from_scans()
    elif args.command == "fp":
        engine.report_false_positive(
            args.attack, "", args.predicted, args.actual
        )
    elif args.command == "missed":
        engine.report_missed_vuln(args.attack, "", args.actual)
    elif args.command == "insights":
        insights = engine.generate_learning_insights()
        print(f"\n  Learning Insights:\n  {insights}\n")
    else:
        engine.print_learning_report()