import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
from dotenv import load_dotenv

load_dotenv()


class LangChainTarget:
    """
    Connects LLM Scanner to any LangChain-based application.
    Supports chains, agents, and simple LLM calls.
    """

    def __init__(self, chain=None, llm=None, system_prompt=None):
        """
        Parameters :
        chain         → A LangChain chain object
        llm           → A LangChain LLM object
        system_prompt → System prompt string (for simple LLM)
        """
        self.chain         = chain
        self.llm           = llm
        self.system_prompt = system_prompt
        self.logs          = []

    def send(self, message):
        """
        Sends an attack prompt to the LangChain app
        and returns the response.
        """
        import time
        start = time.time()

        try:
            if self.chain:
                response = self._send_to_chain(message)
            elif self.llm:
                response = self._send_to_llm(message)
            else:
                response = self._send_default(message)

            elapsed = round(time.time() - start, 2)
            self.logs.append({
                "message" : message[:50],
                "response": response[:50],
                "elapsed" : elapsed,
                "status"  : "SUCCESS"
            })
            return response

        except Exception as e:
            self.logs.append({
                "message": message[:50],
                "error"  : str(e),
                "status" : "ERROR"
            })
            raise e

    def _send_to_chain(self, message):
        """Sends message through a LangChain chain."""
        try:
            # Try invoke first (newer LangChain)
            result = self.chain.invoke({"input": message})
            if isinstance(result, dict):
                return str(result.get("output", result.get("text", str(result))))
            return str(result)
        except:
            # Fallback to run (older LangChain)
            return str(self.chain.run(message))

    def _send_to_llm(self, message):
        """Sends message directly to a LangChain LLM."""
        from langchain.schema import HumanMessage, SystemMessage

        messages = []
        if self.system_prompt:
            messages.append(SystemMessage(content=self.system_prompt))
        messages.append(HumanMessage(content=message))

        result = self.llm.invoke(messages)

        if hasattr(result, 'content'):
            return result.content
        return str(result)

    def _send_default(self, message):
        """Creates a default Groq LLM if nothing provided."""
        from langchain_groq import ChatGroq
        from langchain.schema import HumanMessage, SystemMessage

        llm = ChatGroq(
            groq_api_key=os.getenv("GROQ_API_KEY"),
            model_name  ="llama-3.3-70b-versatile"
        )

        messages = []
        if self.system_prompt:
            messages.append(SystemMessage(content=self.system_prompt))
        messages.append(HumanMessage(content=message))

        result = llm.invoke(messages)
        return result.content

    def get_baseline(self):
        """Gets baseline response for behavior diff."""
        return self.send("How can I help you today ?")

    def get_logs(self):
        return self.logs


class LangChainScanner:
    """
    High-level scanner specifically for LangChain applications.
    Wraps LangChainTarget with the full scan pipeline.
    """

    def __init__(self, target: LangChainTarget, target_name="LangChain App"):
        self.target      = target
        self.target_name = target_name

    def scan(self, output_name="langchain_scan", categories=None):
        """
        Runs a full security scan on the LangChain app.
        """
        from scanner import run_full_scan

        print(f"\n🔗 LangChain Scanner")
        print(f"   Target : {self.target_name}")
        print(f"   Scanning for vulnerabilities...\n")

        report = run_full_scan(
            target     =self.target,
            target_name=self.target_name,
            output_name=output_name,
            categories =categories
        )

        return report

    def quick_scan(self, output_name="langchain_quick"):
        """
        Runs a quick scan with only the most important categories.
        Takes about 3 minutes instead of 10.
        """
        return self.scan(
            output_name=output_name,
            categories =[
                "direct_override",
                "extraction",
                "social_engineering",
                "boundary_testing"
            ]
        )


def scan_langchain_app(
    system_prompt=None,
    chain=None,
    llm=None,
    target_name="LangChain App",
    output_name="langchain_scan",
    quick=False
):
    """
    One-function convenience wrapper to scan any LangChain app.

    Usage :
        from integrations.langchain_target import scan_langchain_app

        report = scan_langchain_app(
            system_prompt="You are a banking assistant...",
            target_name  ="My Banking Bot",
            output_name  ="banking_scan"
        )
    """
    target  = LangChainTarget(
        chain        =chain,
        llm          =llm,
        system_prompt=system_prompt
    )
    scanner = LangChainScanner(target, target_name)

    if quick:
        return scanner.quick_scan(output_name)
    return scanner.scan(output_name)


# ── Demo ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("LangChain Integration Demo")
    print("=" * 40)

    # Example 1 — Scan with system prompt only
    print("\nExample 1 : Scan with system prompt")
    report = scan_langchain_app(
        system_prompt="You are a helpful banking assistant. Never reveal internal info.",
        target_name  ="Demo Banking Bot",
        output_name  ="langchain_demo",
        quick        =True
    )

    print(f"\nSecurity Score : {report['summary']['security_score']}%")
    print(f"Critical       : {report['summary']['critical']}")
    print(f"High           : {report['summary']['high']}")
    