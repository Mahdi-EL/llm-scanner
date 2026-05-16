import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# ── Security Copilot ──────────────────────────────────────────
class SecurityCopilot:
    """
    AI-powered security assistant that answers
    questions about your scan results and
    provides expert guidance.

    Like having a CISO on demand.
    """

    SYSTEM_PROMPT = """You are an expert AI security consultant
specializing in LLM application security.
You have deep knowledge of:
- Prompt injection attacks (OWASP LLM Top 10)
- System prompt hardening
- AI jailbreaking techniques
- Security best practices
- Regulatory compliance (GDPR, EU AI Act, NIST)

When given scan results, analyze them and provide
specific, actionable security advice.
Be direct and technical. No generic advice."""

    def __init__(self, scan_results_path=None):
        from groq import Groq
        self.client       = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.scan_data    = None
        self.conversation = []

        if scan_results_path:
            self._load_scan(scan_results_path)

    def _load_scan(self, path):
        """Loads scan results for context."""
        with open(path, "r", encoding="utf-8") as f:
            self.scan_data = json.load(f)

        summary = self.scan_data["summary"]
        self.scan_context = f"""
SCAN SUMMARY:
Security Score : {summary['security_score']}%
Critical       : {summary['critical']}
High           : {summary['high']}
Medium         : {summary['medium']}
Total Attacks  : {self.scan_data['total_attacks']}

TOP VULNERABILITIES:
"""
        results = self.scan_data.get("results", [])
        critical_high = [
            r for r in results
            if r["severity"] in ("CRITICAL", "HIGH")
        ][:5]

        for r in critical_high:
            self.scan_context += (
                f"- [{r['severity']}] {r['category']}: "
                f"{r.get('reason','')[:80]}\n"
            )

        print(f"  Scan loaded: Score {summary['security_score']}%")

    def ask(self, question):
        """
        Asks the security copilot a question.
        Maintains conversation history.
        """
        # Build context
        context = ""
        if self.scan_data:
            context = f"\nSCAN CONTEXT:\n{self.scan_context}\n"

        # Add to conversation
        user_message = f"{context}{question}"
        self.conversation.append({
            "role"   : "user",
            "content": user_message
        })

        # Build messages
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT}
        ] + self.conversation[-10:]  # Last 10 turns

        response = self.client.chat.completions.create(
            model    ="llama-3.3-70b-versatile",
            messages =messages,
            max_tokens=400
        )

        answer = response.choices[0].message.content.strip()
        self.conversation.append({
            "role"   : "assistant",
            "content": answer
        })

        return answer

    def quick_analysis(self):
        """Provides instant analysis of scan results."""
        if not self.scan_data:
            return "No scan results loaded. Use --scan to provide a scan file."

        analysis = self.ask(
            "Provide a 3-sentence expert analysis of these scan results. "
            "What is the most critical issue and what should be done first?"
        )
        return analysis

    def get_remediation_steps(self):
        """Gets specific remediation steps."""
        if not self.scan_data:
            return "No scan results loaded."

        steps = self.ask(
            "Give me 5 specific, prioritized remediation steps "
            "for the vulnerabilities found. Be concrete with "
            "actual code/prompt examples."
        )
        return steps

    def explain_vulnerability(self, category):
        """Explains a specific vulnerability category."""
        return self.ask(
            f"Explain the '{category}' vulnerability found in the scan. "
            f"How does it work? Why is it dangerous? "
            f"How do I fix it specifically for my application?"
        )

    def compare_to_industry(self):
        """Compares scan results to industry benchmarks."""
        if not self.scan_data:
            return "No scan results loaded."

        score = self.scan_data["summary"]["security_score"]
        return self.ask(
            f"My security score is {score}%. "
            f"How does this compare to industry benchmarks? "
            f"What level of risk does this represent? "
            f"What should my target score be?"
        )

    def generate_security_roadmap(self):
        """Generates a 90-day security roadmap."""
        if not self.scan_data:
            return "No scan results loaded."

        return self.ask(
            "Based on these scan results, create a 90-day security roadmap. "
            "Week 1-2: immediate actions. "
            "Month 1: short term fixes. "
            "Month 2-3: strategic improvements. "
            "Be specific and actionable."
        )

    def interactive_session(self):
        """Runs an interactive Q&A session."""
        print(f"\n{'='*60}")
        print(f"  🤖 AI SECURITY COPILOT")
        if self.scan_data:
            score = self.scan_data["summary"]["security_score"]
            print(f"  Scan Score: {score}%")
        print(f"  Type 'quit' to exit")
        print(f"  Type 'analysis' for quick analysis")
        print(f"  Type 'steps' for remediation steps")
        print(f"  Type 'roadmap' for 90-day roadmap")
        print(f"{'='*60}\n")

        # Quick analysis on start
        if self.scan_data:
            print("  🔍 Quick Analysis:")
            print(f"  {self.quick_analysis()}\n")

        while True:
            try:
                question = input("  You: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Session ended.")
                break

            if not question:
                continue

            if question.lower() == 'quit':
                print("  Session ended.")
                break
            elif question.lower() == 'analysis':
                answer = self.quick_analysis()
            elif question.lower() == 'steps':
                answer = self.get_remediation_steps()
            elif question.lower() == 'roadmap':
                answer = self.generate_security_roadmap()
            else:
                answer = self.ask(question)

            print(f"\n  Copilot: {answer}\n")

    def save_session(self, output_path=None):
        """Saves conversation to file."""
        output = output_path or \
                 f"results/copilot_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        os.makedirs("results", exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            json.dump({
                "saved_at"    : datetime.now().isoformat(),
                "conversation": self.conversation
            }, f, indent=2, ensure_ascii=False)

        print(f"  Session saved: {output}")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — AI Security Copilot"
    )
    parser.add_argument("--scan",     default=None)
    parser.add_argument("--ask",      default=None)
    parser.add_argument("--analysis", action="store_true")
    parser.add_argument("--steps",    action="store_true")
    parser.add_argument("--roadmap",  action="store_true")
    parser.add_argument("--chat",     action="store_true")

    args    = parser.parse_args()
    copilot = SecurityCopilot(args.scan)

    if args.ask:
        print(f"\n  {copilot.ask(args.ask)}\n")
    elif args.analysis:
        print(f"\n  {copilot.quick_analysis()}\n")
    elif args.steps:
        print(f"\n  {copilot.get_remediation_steps()}\n")
    elif args.roadmap:
        print(f"\n  {copilot.generate_security_roadmap()}\n")
    elif args.chat:
        copilot.interactive_session()
    else:
        copilot.interactive_session()