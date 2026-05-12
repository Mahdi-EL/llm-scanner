import sys
sys.stdout.reconfigure(encoding='utf-8')

import requests
import json
import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()


class Target:
    """
    Connects to any AI API target.
    Supports OpenAI compatible APIs, custom REST APIs,
    Groq models, and local simulations.
    """

    def __init__(self, target_type, **kwargs):
        self.target_type = target_type
        self.kwargs = kwargs
        self._setup()

    def _setup(self):
        if self.target_type == "simulation":
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
            self.api_url     = self.kwargs.get("api_url")
            self.api_key     = self.kwargs.get("api_key")
            self.input_field = self.kwargs.get(
                "input_field", "message"
            )
            self.output_field = self.kwargs.get(
                "output_field", "response"
            )

        elif self.target_type == "groq":
            self.client = Groq(
                api_key=os.getenv("GROQ_API_KEY")
            )
            self.model = self.kwargs.get(
                "model", "llama-3.3-70b-versatile"
            )
            self.system_prompt = self.kwargs.get(
                "system_prompt", "You are a helpful assistant."
            )

    def send(self, message):
        """
        Sends a message to the target and returns the response.
        """
        try:
            if self.target_type in ("simulation", "groq"):
                return self._send_groq(message)

            elif self.target_type == "openai_compatible":
                return self._send_openai(message)

            elif self.target_type == "custom_rest":
                return self._send_rest(message)

        except Exception as e:
            return f"ERROR: {str(e)}"

    def _send_groq(self, message):
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system",
                 "content": self.system_prompt},
                {"role": "user",
                 "content": message}
            ]
        )
        return response.choices[0].message.content

    def _send_openai(self, message):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": message}
            ]
        }
        response = requests.post(
            f"{self.api_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _send_rest(self, message):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {self.input_field: message}
        response = requests.post(
            self.api_url,
            headers=headers,
            json=payload,
            timeout=30
        )
        data = response.json()
        return data.get(self.output_field, str(data))

    def get_baseline(self):
        """
        Gets a normal response as baseline for behavior diff.
        """
        return self.send(
            "How can I check my account balance ?"
        )


def create_target_from_config(config_path):
    """
    Creates a Target from a JSON config file.
    """
    with open(config_path, "r") as f:
        config = json.load(f)
    return Target(**config)