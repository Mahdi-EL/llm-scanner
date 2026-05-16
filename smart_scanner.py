import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import time
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# ── Smart Scan Config ─────────────────────────────────────────
class SmartScanConfig:
    """Configuration for smart scanning."""

    def __init__(
        self,
        early_stop_on_critical=True,
        max_critical_before_stop=3,
        skip_low_risk_categories=False,
        adaptive_depth=True,
        time_budget_seconds=600,  # 10 minutes
        confidence_threshold=0.7
    ):
        self.early_stop_on_critical    = early_stop_on_critical
        self.max_critical_before_stop  = max_critical_before_stop
        self.skip_low_risk_categories  = skip_low_risk_categories
        self.adaptive_depth            = adaptive_depth
        self.time_budget_seconds       = time_budget_seconds
        self.confidence_threshold      = confidence_threshold


# ── Adaptive Attack Selector ──────────────────────────────────
class AdaptiveAttackSelector:
    """
    Dynamically selects and orders attack prompts
    based on predicted vulnerability and real-time findings.
    """

    def __init__(self, system_prompt, predictor=None):
        self.system_prompt = system_prompt
        self.predictor     = predictor
        self.findings      = []
        self.category_scores = {}

    def get_optimized_order(self):
        """
        Returns attack categories in optimized order.
        Most likely to find vulnerabilities first.
        """
        from vulnerability_predictor import VulnerabilityPredictor
        from attacks.prompts import ATTACK_PROMPTS

        predictor  = VulnerabilityPredictor()
        top_cats   = predictor.predict_vulnerable_categories(
            self.system_prompt
        )

        # Build ordered list
        ordered_cats  = [cat for cat, _ in top_cats]
        all_cats      = list(ATTACK_PROMPTS.keys())

        # Add remaining categories not in prediction
        for cat in all_cats:
            if cat not in ordered_cats:
                ordered_cats.append(cat)

        return ordered_cats

    def select_prompts_for_category(
        self, category, depth="standard"
    ):
        """
        Selects prompts for a category based on depth.
        """
        from attacks.prompts import ATTACK_PROMPTS

        all_prompts = ATTACK_PROMPTS.get(category, [])

        if depth == "quick":
            return all_prompts[:5]
        elif depth == "standard":
            return all_prompts[:15]
        elif depth == "deep":
            return all_prompts
        else:
            return all_prompts[:10]

    def update_strategy(self, new_finding):
        """
        Updates scanning strategy based on new finding.
        If high severity found → increase depth for related categories.
        """
        self.findings.append(new_finding)

        cat      = new_finding.get("category")
        severity = new_finding.get("severity")

        if cat not in self.category_scores:
            self.category_scores[cat] = 0

        severity_weights = {
            "CRITICAL": 10,
            "HIGH"    : 7,
            "MEDIUM"  : 4,
            "LOW"     : 2,
            "SAFE"    : 0
        }
        self.category_scores[cat] += severity_weights.get(severity, 0)

    def get_depth_for_category(self, category):
        """
        Returns recommended scan depth for a category
        based on findings so far.
        """
        score = self.category_scores.get(category, 0)

        if score >= 10:
            return "deep"
        elif score >= 5:
            return "standard"
        else:
            return "quick"


# ── Smart Scanner ─────────────────────────────────────────────
class SmartScanner:
    """
    Intelligent scanner that adapts its strategy
    based on real-time findings and predictions.

    Key features :
    - Scans highest-risk categories first
    - Stops early if critical found
    - Adapts depth based on findings
    - Respects time budget
    - Reports progress and confidence
    """

    def __init__(self, target, config=None):
        self.target    = target
        self.config    = config or SmartScanConfig()
        self.results   = []
        self.start_time = None
        self.stats     = {
            "categories_scanned"  : 0,
            "categories_skipped"  : 0,
            "early_stop"          : False,
            "early_stop_reason"   : None,
            "time_saved_estimate" : 0,
            "critical_found"      : 0,
            "high_found"          : 0
        }

    def _time_remaining(self):
        """Returns seconds remaining in time budget."""
        if not self.start_time:
            return self.config.time_budget_seconds
        elapsed = time.time() - self.start_time
        return max(0, self.config.time_budget_seconds - elapsed)

    def _should_stop_early(self):
        """Checks if we should stop scanning early."""
        if not self.config.early_stop_on_critical:
            return False, None

        critical_count = sum(
            1 for r in self.results
            if r["severity"] == "CRITICAL"
        )

        if critical_count >= self.config.max_critical_before_stop:
            return True, f"{critical_count} critical vulnerabilities found"

        if self._time_remaining() < 30:
            return True, "Time budget exhausted"

        return False, None

    def _should_skip_category(self, category, risk_score):
        """Checks if category should be skipped."""
        if not self.config.skip_low_risk_categories:
            return False

        # Skip if time budget is low and risk is low
        if self._time_remaining() < 120 and risk_score < 5:
            return True

        return False

    def _scan_category(self, category, prompts, selector):
        """Scans a single category and returns results."""
        from analysis import (
            analyze_response,
            behavior_diff,
            calculate_final_severity
        )
        import time as time_module

        category_results = []

        # Get baseline
        try:
            normal_response = self.target.get_baseline()
        except:
            normal_response = "I can help you with that."

        depth   = selector.get_depth_for_category(category)
        prompts = selector.select_prompts_for_category(category, depth)

        print(
            f"    Depth: {depth} — "
            f"Testing {len(prompts)} prompts..."
        )

        for prompt in prompts:
            if self._time_remaining() < 10:
                break

            try:
                response = self.target.send(prompt)

                score, severity, reason = analyze_response(
                    prompt, response
                )
                changed, confidence, explanation = behavior_diff(
                    normal_response, response
                )
                final_sev, final_score = calculate_final_severity(
                    score, changed, confidence
                )

                result = {
                    "category"        : category,
                    "attack"          : prompt,
                    "response"        : response,
                    "score"           : final_score,
                    "severity"        : final_sev,
                    "reason"          : reason,
                    "behavior_changed": changed,
                    "confidence"      : confidence
                }

                category_results.append(result)
                selector.update_strategy(result)

                if final_sev == "CRITICAL":
                    self.stats["critical_found"] += 1
                    print(
                        f"    🚨 CRITICAL found: "
                        f"{prompt[:50]}..."
                    )
                elif final_sev == "HIGH":
                    self.stats["high_found"] += 1

                time_module.sleep(1.0)

            except Exception as e:
                continue

        return category_results

    def scan(
        self,
        target_name="AI Application",
        output_name="smart_scan"
    ):
        """
        Runs the smart scan with adaptive strategy.
        """
        from vulnerability_predictor import VulnerabilityPredictor
        from analysis import save_results
        from report   import generate_report

        self.start_time = time.time()

        print(f"\n{'='*60}")
        print(f"  🧠 SMART SCANNER")
        print(f"  Target      : {target_name}")
        print(f"  Time Budget : {self.config.time_budget_seconds}s")
        print(f"  Early Stop  : {self.config.early_stop_on_critical}")
        print(f"{'='*60}\n")

        # Step 1 : Predict
        print("  [1/4] Predicting vulnerable categories...")
        system_prompt = getattr(
            self.target, "system_prompt",
            "You are a helpful assistant."
        )

        predictor  = VulnerabilityPredictor()
        risk_score = predictor.calculate_overall_risk_score(system_prompt)
        risk_level = predictor.get_risk_level(risk_score)

        print(f"  Pre-scan Risk Score : {risk_score}/100 ({risk_level})")

        # Step 2 : Get optimized category order
        print("\n  [2/4] Optimizing scan order...")
        selector     = AdaptiveAttackSelector(system_prompt)
        ordered_cats = selector.get_optimized_order()

        print(f"  Scan order : {' → '.join(ordered_cats[:5])}...")

        # Step 3 : Scan in optimized order
        print(f"\n  [3/4] Scanning {len(ordered_cats)} categories...\n")

        for i, category in enumerate(ordered_cats):
            # Check time budget
            remaining = self._time_remaining()
            if remaining < 30:
                print(f"\n  ⏱️  Time budget exhausted")
                self.stats["categories_skipped"] += \
                    len(ordered_cats) - i
                break

            # Check early stop
            should_stop, reason = self._should_stop_early()
            if should_stop:
                print(f"\n  🛑 Early stop: {reason}")
                self.stats["early_stop"]        = True
                self.stats["early_stop_reason"] = reason
                self.stats["categories_skipped"] += \
                    len(ordered_cats) - i

                # Estimate time saved
                remaining_cats   = len(ordered_cats) - i
                self.stats["time_saved_estimate"] = \
                    remaining_cats * 45  # ~45s per category
                break

            # Get risk score for this category
            cat_risk = next(
                (r for c, r in predictor.predict_vulnerable_categories(
                    system_prompt
                ) if c == category),
                0
            )

            # Check if should skip
            if self._should_skip_category(category, cat_risk):
                print(
                    f"  [{i+1}/{len(ordered_cats)}] "
                    f"⏭️  Skipping {category} (low risk)"
                )
                self.stats["categories_skipped"] += 1
                continue

            print(
                f"  [{i+1}/{len(ordered_cats)}] "
                f"Scanning: {category} "
                f"(Risk: {cat_risk:.0f}, "
                f"Time left: {int(remaining)}s)"
            )

            cat_results = self._scan_category(
                category, [], selector
            )

            self.results.extend(cat_results)
            self.stats["categories_scanned"] += 1

            # Print category summary
            cat_crits = sum(
                1 for r in cat_results
                if r["severity"] == "CRITICAL"
            )
            cat_high = sum(
                1 for r in cat_results
                if r["severity"] == "HIGH"
            )
            if cat_crits or cat_high:
                print(
                    f"    Found: {cat_crits} critical, "
                    f"{cat_high} high"
                )

        # Step 4 : Save and report
        print(f"\n  [4/4] Generating reports...")

        json_path   = f"results/{output_name}.json"
        report_data = save_results(self.results, filename=json_path)

        pdf_path = f"results/{output_name}.pdf"
        generate_report(
            json_path  =json_path,
            output_path=pdf_path,
            target_name=target_name
        )

        # Final summary
        total_time = int(time.time() - self.start_time)
        summary    = report_data["summary"]

        print(f"\n{'='*60}")
        print(f"  🧠 SMART SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"  Duration           : {total_time}s")
        print(f"  Categories Scanned : {self.stats['categories_scanned']}")
        print(f"  Categories Skipped : {self.stats['categories_skipped']}")
        print(f"  Security Score     : {summary['security_score']}%")
        print(f"  Critical           : {summary['critical']}")
        print(f"  High               : {summary['high']}")

        if self.stats["early_stop"]:
            print(
                f"  Early Stop         : "
                f"{self.stats['early_stop_reason']}"
            )
            saved = self.stats["time_saved_estimate"]
            print(f"  Time Saved         : ~{saved}s")

        print(f"  PDF                : {pdf_path}")
        print(f"{'='*60}\n")

        return report_data, self.stats


# ── Quick Smart Scan ──────────────────────────────────────────
def smart_scan(
    system_prompt,
    target_name ="AI Application",
    output_name ="smart_scan",
    time_budget =600,
    early_stop  =True
):
    """
    Convenience function for smart scanning.
    """
    from target import Target

    target = Target(
        target_type  ="simulation",
        system_prompt=system_prompt
    )

    config  = SmartScanConfig(
        early_stop_on_critical  =early_stop,
        time_budget_seconds     =time_budget,
        skip_low_risk_categories=True
    )

    scanner = SmartScanner(target, config)
    return scanner.scan(target_name, output_name)


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Smart Scanner"
    )
    parser.add_argument("--target",  default="AI Application")
    parser.add_argument("--output",  default="smart_scan")
    parser.add_argument("--budget",  type=int, default=600)
    parser.add_argument("--no-stop", action="store_true")
    parser.add_argument("--prompt",  default=None)

    args = parser.parse_args()

    system_prompt = args.prompt or """You are a helpful assistant.
Answer user questions politely."""

    report_data, stats = smart_scan(
        system_prompt=system_prompt,
        target_name  =args.target,
        output_name  =args.output,
        time_budget  =args.budget,
        early_stop   =not args.no_stop
    )
    