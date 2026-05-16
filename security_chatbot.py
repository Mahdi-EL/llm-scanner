import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# ── Chatbot Intents ───────────────────────────────────────────
INTENTS = {
    "scan": {
        "keywords": ["scan", "test", "check", "analyze", "assess"],
        "response": "scan_intent"
    },
    "report": {
        "keywords": ["report", "results", "findings", "pdf"],
        "response": "report_intent"
    },
    "help": {
        "keywords": ["help", "how", "what", "explain", "tutorial"],
        "response": "help_intent"
    },
    "stats": {
        "keywords": ["stats", "statistics", "metrics", "score"],
        "response": "stats_intent"
    },
    "remediate": {
        "keywords": ["fix", "remediate", "harden", "patch", "secure"],
        "response": "remediate_intent"
    },
    "compare": {
        "keywords": ["compare", "difference", "before", "after"],
        "response": "compare_intent"
    },
    "greet": {
        "keywords": ["hi", "hello", "hey", "good", "morning"],
        "response": "greet_intent"
    }
}


# ── Security Chatbot ──────────────────────────────────────────
class SecurityChatbot:
    """
    Conversational interface for LLM Scanner.
    Users can interact with the scanner through
    natural language commands.
    """

    def __init__(self):
        from groq import Groq
        self.client      = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.session     = []
        self.context     = {}
        self.last_scan   = None

        self.SYSTEM = """You are LLM Scanner Bot, an AI security assistant.
You help users scan their AI applications for vulnerabilities.

You can:
1. Run security scans
2. Explain scan results
3. Recommend fixes
4. Answer security questions

Be conversational but professional.
When users ask to scan, ask for their system prompt.
Keep responses concise (2-3 sentences max).
Use emojis sparingly for clarity (🔐, ✅, 🚨)."""

    def _detect_intent(self, message):
        """Detects user intent from message."""
        message_lower = message.lower()
        for intent, data in INTENTS.items():
            if any(kw in message_lower for kw in data["keywords"]):
                return intent
        return "general"

    def _handle_scan_intent(self, message):
        """Handles scan requests."""
        if "system_prompt" not in self.context:
            self.context["awaiting"] = "system_prompt"
            return (
                "🔐 I'll scan your AI application for you!\n\n"
                "Please share your **system prompt** "
                "(the instructions you give to your AI).\n"
                "I'll keep it confidential."
            )

        return (
            "✅ I have your system prompt. "
            "Type 'start scan' to begin the security assessment."
        )

    def _handle_awaiting(self, message):
        """Handles responses to questions."""
        awaiting = self.context.get("awaiting")

        if awaiting == "system_prompt":
            self.context["system_prompt"] = message
            self.context.pop("awaiting", None)
            return (
                f"✅ Got it! Your system prompt is {len(message)} characters.\n\n"
                f"I'll run a security scan now. This takes about 10 minutes.\n"
                f"Type 'start scan' to begin."
            )

        return None

    def _handle_stats(self):
        """Returns current stats."""
        try:
            from analytics import AnalyticsEngine
            engine  = AnalyticsEngine()
            trends  = engine.get_vulnerability_trends()

            if trends:
                return (
                    f"📊 **Security Stats (30 days)**\n\n"
                    f"• Total Scans: {trends.get('total_scans', 0)}\n"
                    f"• Avg Score: {trends.get('avg_score', 0)}%\n"
                    f"• Critical Found: {trends.get('total_criticals', 0)}\n"
                    f"• Trend: {trends.get('score_trend', 'unknown')}"
                )
        except:
            pass

        return "📊 No scan data available yet. Run your first scan!"

    def _handle_help(self):
        """Returns help message."""
        return (
            "🔐 **LLM Scanner Bot — Commands**\n\n"
            "• `scan my app` → Start a security scan\n"
            "• `show results` → View last scan results\n"
            "• `fix vulnerabilities` → Get remediation advice\n"
            "• `show stats` → View security metrics\n"
            "• `compare scans` → Compare two scan results\n"
            "• Ask me anything about AI security!"
        )

    def _call_ai(self, message):
        """Calls AI for general responses."""
        self.session.append({
            "role": "user", "content": message
        })

        messages = [
            {"role": "system", "content": self.SYSTEM}
        ] + self.session[-10:]

        # Add context if available
        if self.last_scan:
            score   = self.last_scan.get("security_score", 0)
            context = (
                f"\n[Last scan: score={score}%, "
                f"critical={self.last_scan.get('critical', 0)}]"
            )
            messages[0]["content"] += context

        response = self.client.chat.completions.create(
            model    ="llama-3.3-70b-versatile",
            messages =messages,
            max_tokens=200
        )

        answer = response.choices[0].message.content.strip()
        self.session.append({
            "role": "assistant", "content": answer
        })

        return answer

    def respond(self, message):
        """
        Main response function.
        Routes message to appropriate handler.
        """
        message = message.strip()

        # Check awaiting state
        if self.context.get("awaiting"):
            result = self._handle_awaiting(message)
            if result:
                return result

        intent = self._detect_intent(message)

        # Special commands
        if "start scan" in message.lower():
            if "system_prompt" in self.context:
                return self._start_scan()
            return "Please share your system prompt first."

        if "show results" in message.lower():
            return self._show_results()

        # Intent routing
        if intent == "scan":
            return self._handle_scan_intent(message)
        elif intent == "stats":
            return self._handle_stats()
        elif intent == "help":
            return self._handle_help()
        elif intent == "greet":
            return (
                "👋 Hi! I'm LLM Scanner Bot.\n\n"
                "I can help you test your AI application for "
                "security vulnerabilities.\n\n"
                "Type `help` to see what I can do!"
            )
        else:
            return self._call_ai(message)

    def _start_scan(self):
        """Initiates a scan."""
        system_prompt = self.context.get("system_prompt", "")

        try:
            from target  import Target
            from scanner import run_full_scan

            target = Target(
                target_type  ="simulation",
                system_prompt=system_prompt
            )

            timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_name = f"chatbot_scan_{timestamp}"

            report = run_full_scan(
                target     =target,
                target_name="Chatbot Scan",
                output_name=output_name,
                categories =["direct_override", "extraction", "social_engineering"]
            )

            score    = report["summary"]["security_score"]
            critical = report["summary"]["critical"]
            high     = report["summary"]["high"]

            self.last_scan = {
                "security_score": score,
                "critical"      : critical,
                "high"          : high,
                "json_path"     : f"results/{output_name}.json",
                "pdf_path"      : f"results/{output_name}.pdf"
            }
            self.context.pop("system_prompt", None)

            emoji = "🟢" if score >= 70 else "🟡" if score >= 40 else "🔴"
            return (
                f"{emoji} **Scan Complete!**\n\n"
                f"• Security Score: **{score}%**\n"
                f"• Critical: {critical}\n"
                f"• High: {high}\n\n"
                f"Type 'fix vulnerabilities' for remediation advice."
            )

        except Exception as e:
            return f"❌ Scan failed: {str(e)[:100]}"

    def _show_results(self):
        """Shows last scan results."""
        if not self.last_scan:
            return "No scan results yet. Type 'scan my app' to start."

        score    = self.last_scan["security_score"]
        critical = self.last_scan["critical"]
        pdf      = self.last_scan.get("pdf_path", "N/A")

        return (
            f"📊 **Last Scan Results**\n\n"
            f"• Score: {score}%\n"
            f"• Critical: {critical}\n"
            f"• Report: {pdf}"
        )

    def run_cli(self):
        """Runs the chatbot in CLI mode."""
        print(f"\n{'='*60}")
        print(f"  💬 LLM SCANNER SECURITY CHATBOT")
        print(f"  Type 'help' for commands | 'quit' to exit")
        print(f"{'='*60}\n")

        print(f"  Bot: 👋 Hi! I'm LLM Scanner Bot. Type 'help' to start!\n")

        while True:
            try:
                user_input = input("  You: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Goodbye! 🔐")
                break

            if not user_input:
                continue

            if user_input.lower() == 'quit':
                print("  Bot: Goodbye! Stay secure! 🔐")
                break

            response = self.respond(user_input)
            print(f"\n  Bot: {response}\n")


# ── Web Interface Generator ───────────────────────────────────
def generate_chatbot_html(output_path="results/chatbot.html"):
    """Generates a web-based chatbot interface."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LLM Scanner Security Chatbot</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #0f1117;
            color: white;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background: #1F3864;
            padding: 16px 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .header h1 { font-size: 20px; }
        .header p  { color: #aaa; font-size: 12px; }
        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .message {
            max-width: 80%;
            padding: 12px 16px;
            border-radius: 12px;
            font-size: 14px;
            line-height: 1.5;
        }
        .bot {
            background: #1a1d27;
            border: 1px solid #2a2d3a;
            align-self: flex-start;
            border-bottom-left-radius: 4px;
        }
        .user {
            background: #2E75B6;
            align-self: flex-end;
            border-bottom-right-radius: 4px;
        }
        .input-area {
            padding: 16px 24px;
            background: #1a1d27;
            border-top: 1px solid #2a2d3a;
            display: flex;
            gap: 12px;
        }
        input {
            flex: 1;
            background: #0f1117;
            border: 1px solid #2a2d3a;
            border-radius: 8px;
            padding: 12px 16px;
            color: white;
            font-size: 14px;
            outline: none;
        }
        input:focus { border-color: #2E75B6; }
        button {
            background: #2E75B6;
            border: none;
            border-radius: 8px;
            padding: 12px 24px;
            color: white;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
        }
        button:hover { background: #1F5A9E; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🔐 LLM Scanner Security Chatbot</h1>
            <p>AI-powered security assistant</p>
        </div>
    </div>

    <div class="messages" id="messages">
        <div class="message bot">
            👋 Hi! I'm LLM Scanner Bot.<br><br>
            I can help you test your AI application for security vulnerabilities.<br><br>
            Type <b>help</b> to see what I can do!
        </div>
    </div>

    <div class="input-area">
        <input
            type="text"
            id="userInput"
            placeholder="Ask me anything about AI security..."
            onkeypress="handleKey(event)"
            autofocus
        >
        <button onclick="sendMessage()">Send</button>
    </div>

    <script>
        const messages = document.getElementById('messages');
        const input    = document.getElementById('userInput');

        const botResponses = {
            'help': `🔐 **LLM Scanner Bot Commands**

- scan my app → Start security scan
- show results → View last scan
- fix vulnerabilities → Get remediation
- show stats → Security metrics
- Ask anything about AI security!`,
            'hi'  : '👋 Hello! Ready to scan your AI app for vulnerabilities?',
            'hello': '👋 Hello! How can I help with AI security today?',
        };

        function addMessage(text, isUser) {
            const div   = document.createElement('div');
            div.className = 'message ' + (isUser ? 'user' : 'bot');
            div.innerHTML = text.replace(/\\n/g, '<br>').replace(/\\*\\*(.*?)\\*\\*/g, '<b>$1</b>');
            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
        }

        function sendMessage() {
            const text = input.value.trim();
            if (!text) return;

            addMessage(text, true);
            input.value = '';

            setTimeout(() => {
                const lower    = text.toLowerCase();
                let response = botResponses[lower] ||
                    `I understand you want to know about: "${text}".
For full functionality, run the chatbot locally with:
python security_chatbot.py`;

                if (lower.includes('scan'))
                    response = '🔐 To scan your AI app, please share your system prompt. I\\'ll keep it confidential!';
                else if (lower.includes('help'))
                    response = botResponses['help'];
                else if (lower.includes('stat') || lower.includes('score'))
                    response = '📊 Run python security_chatbot.py to see live stats!';

                addMessage(response, false);
            }, 500);
        }

        function handleKey(e) {
            if (e.key === 'Enter') sendMessage();
        }
    </script>
</body>
</html>"""

    os.makedirs("results", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"  Chatbot HTML: {output_path}")
    return output_path


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Security Chatbot"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("chat")
    p_html = subparsers.add_parser("html")
    p_html.add_argument(
        "--output", default="results/chatbot.html"
    )

    p_ask = subparsers.add_parser("ask")
    p_ask.add_argument("message")

    args = parser.parse_args()

    if args.command == "html":
        generate_chatbot_html(args.output)
    elif args.command == "ask":
        bot      = SecurityChatbot()
        response = bot.respond(args.message)
        print(f"\n  {response}\n")
    else:
        bot = SecurityChatbot()
        bot.run_cli()
        