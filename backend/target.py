import sys
sys.stdout.reconfigure(encoding='utf-8')

import requests
import json
import os
import time
import websocket
from groq import Groq
from dotenv import load_dotenv

load_dotenv()


class Target:
    """
    Connects to any AI API target.
    Supports OpenAI compatible APIs, custom REST APIs,
    GraphQL APIs, WebSocket targets, Groq models,
    and local simulations.
    """

    def __init__(self, target_type, **kwargs):
        self.target_type = target_type
        self.kwargs      = kwargs
        self.timeout     = kwargs.get("timeout", 30)
        self.logs        = []
        self._setup()

    def _setup(self):
        if self.target_type in ("simulation", "groq"):
            self.client = Groq(
                api_key=os.getenv("GROQ_API_KEY")
            )
            self.model = self.kwargs.get(
                "model", "llama-3.3-70b-versatile"
            )
            self.system_prompt = self.kwargs.get(
                "system_prompt", "You are a helpful assistant."
            )

        elif self.target_type == "openai_compatible":
            self.api_url = self.kwargs.get("api_url")
            self.api_key = self.kwargs.get("api_key")
            self.model   = self.kwargs.get("model", "gpt-4")

        elif self.target_type == "custom_rest":
            self.api_url      = self.kwargs.get("api_url")
            self.api_key      = self.kwargs.get("api_key")
            self.input_field  = self.kwargs.get("input_field", "message")
            self.output_field = self.kwargs.get("output_field", "response")

        elif self.target_type == "graphql":
            self.api_url  = self.kwargs.get("api_url")
            self.api_key  = self.kwargs.get("api_key")
            self.query    = self.kwargs.get(
                "query",
                """
                mutation SendMessage($message: String!) {
                    sendMessage(input: { message: $message }) {
                        response
                    }
                }
                """
            )

        elif self.target_type == "websocket":
            self.ws_url      = self.kwargs.get("ws_url")
            self.api_key     = self.kwargs.get("api_key")
            self.input_field = self.kwargs.get("input_field", "message")
            self.output_field= self.kwargs.get("output_field", "response")

    # ── Auto Detection ────────────────────────────────────
    @classmethod
    def auto_detect(cls, url, api_key=None, **kwargs):
        """
        Automatically detects the target type
        based on the URL provided.
        """
        print(f"Auto-detecting target type for : {url}")

        if url.startswith("ws://") or url.startswith("wss://"):
            print("Detected : WebSocket target")
            return cls(
                target_type="websocket",
                ws_url=url,
                api_key=api_key,
                **kwargs
            )

        if "graphql" in url.lower():
            print("Detected : GraphQL target")
            return cls(
                target_type="graphql",
                api_url=url,
                api_key=api_key,
                **kwargs
            )

        if "openai.com" in url or "api.groq.com" in url:
            print("Detected : OpenAI compatible target")
            return cls(
                target_type="openai_compatible",
                api_url=url,
                api_key=api_key,
                **kwargs
            )

        # Default to custom REST
        print("Detected : Custom REST target")
        return cls(
            target_type="custom_rest",
            api_url=url,
            api_key=api_key,
            **kwargs
        )

    # ── Send ─────────────────────────────────────────────
    def send(self, message):
        """
        Sends a message to the target and returns the response.
        Logs every request for debugging.
        """
        start_time = time.time()

        try:
            if self.target_type in ("simulation", "groq"):
                response = self._send_groq(message)

            elif self.target_type == "openai_compatible":
                response = self._send_openai(message)

            elif self.target_type == "custom_rest":
                response = self._send_rest(message)

            elif self.target_type == "graphql":
                response = self._send_graphql(message)

            elif self.target_type == "websocket":
                response = self._send_websocket(message)

            else:
                response = f"ERROR: Unknown target type {self.target_type}"

            elapsed = round(time.time() - start_time, 2)
            self._log(message, response, elapsed, "SUCCESS")
            return response

        except Exception as e:
            elapsed = round(time.time() - start_time, 2)
            error   = f"ERROR: {str(e)}"
            self._log(message, error, elapsed, "ERROR")
            raise e

    # ── Groq / Simulation ────────────────────────────────
    def _send_groq(self, message):
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user",   "content": message}
            ],
            timeout=self.timeout
        )
        return response.choices[0].message.content

    # ── OpenAI Compatible ────────────────────────────────
    def _send_openai(self, message):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type" : "application/json"
        }
        payload = {
            "model"   : self.model,
            "messages": [{"role": "user", "content": message}]
        }
        response = requests.post(
            f"{self.api_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=self.timeout
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    # ── Custom REST ──────────────────────────────────────
    def _send_rest(self, message):
        headers = {
            "Content-Type": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload  = {self.input_field: message}
        response = requests.post(
            self.api_url,
            headers=headers,
            json=payload,
            timeout=self.timeout
        )
        response.raise_for_status()
        data = response.json()
        return data.get(self.output_field, str(data))

    # ── GraphQL ──────────────────────────────────────────
    def _send_graphql(self, message):
        headers = {
            "Content-Type": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "query"    : self.query,
            "variables": {"message": message}
        }
        response = requests.post(
            self.api_url,
            headers=headers,
            json=payload,
            timeout=self.timeout
        )
        response.raise_for_status()
        data = response.json()

        # Try to extract response from GraphQL data
        if "data" in data:
            nested = data["data"]
            for key in nested:
                if isinstance(nested[key], dict):
                    for subkey in nested[key]:
                        return str(nested[key][subkey])
                return str(nested[key])

        return str(data)

    # ── WebSocket ────────────────────────────────────────
    def _send_websocket(self, message):
        result   = []
        finished = []

        def on_message(ws, msg):
            try:
                data = json.loads(msg)
                if isinstance(data, dict):
                    result.append(
                        data.get(self.output_field, str(data))
                    )
                else:
                    result.append(str(data))
                finished.append(True)
                ws.close()
            except:
                result.append(str(msg))
                finished.append(True)
                ws.close()

        def on_error(ws, error):
            result.append(f"WebSocket error: {str(error)}")
            finished.append(True)

        def on_open(ws):
            payload = json.dumps({self.input_field: message})
            ws.send(payload)

        headers = []
        if self.api_key:
            headers = [f"Authorization: Bearer {self.api_key}"]

        ws = websocket.WebSocketApp(
            self.ws_url,
            header=headers,
            on_message=on_message,
            on_error=on_error,
            on_open=on_open
        )
        ws.run_forever(ping_timeout=self.timeout)

        return result[0] if result else "No response received"

    # ── Baseline ─────────────────────────────────────────
    def get_baseline(self):
        """
        Gets a normal response as baseline for behavior diff.
        """
        return self.send("How can I check my account balance ?")

    # ── Logging ──────────────────────────────────────────
    def _log(self, message, response, elapsed, status):
        """
        Logs every request for debugging.
        """
        self.logs.append({
            "message" : message[:50] + "...",
            "response": response[:50] + "...",
            "elapsed" : elapsed,
            "status"  : status
        })

    def get_logs(self):
        """
        Returns all connection logs.
        """
        return self.logs

    def print_logs(self):
        """
        Prints all connection logs in a readable format.
        """
        print(f"\nConnection Logs ({len(self.logs)} requests) :")
        print("─" * 50)
        for i, log in enumerate(self.logs):
            print(f"[{i+1}] {log['status']} — {log['elapsed']}s")
            print(f"     Message  : {log['message']}")
            print(f"     Response : {log['response']}")
        print("─" * 50)


def create_target_from_config(config_path):
    """
    Creates a Target from a JSON config file.
    """
    with open(config_path, "r") as f:
        config = json.load(f)

    target_type = config.pop("target_type")
    return Target(target_type=target_type, **config)