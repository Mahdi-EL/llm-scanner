import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import time
from dotenv import load_dotenv

load_dotenv()


class OpenAITarget:
    """
    Connects LLM Scanner to OpenAI GPT models directly.
    Uses the official OpenAI Python SDK.
    """

    def __init__(
        self,
        api_key      =None,
        model        ="gpt-4o-mini",
        system_prompt=None,
        temperature  =0.7
    ):
        self.api_key       = api_key or os.getenv("OPENAI_API_KEY")
        self.model         = model
        self.system_prompt = system_prompt or "You are a helpful assistant."
        self.temperature   = temperature
        self.logs          = []

        if not self.api_key:
            raise ValueError(
                "OpenAI API key required. "
                "Set OPENAI_API_KEY in .env or pass api_key parameter."
            )

    def send(self, message):
        """Sends attack prompt to OpenAI and returns response."""
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)

            start    = time.time()
            response = client.chat.completions.create(
                model      =self.model,
                temperature=self.temperature,
                messages   =[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user",   "content": message}
                ]
            )
            elapsed = round(time.time() - start, 2)
            result  = response.choices[0].message.content

            self.logs.append({
                "message" : message[:50],
                "response": result[:50],
                "elapsed" : elapsed,
                "model"   : self.model,
                "status"  : "SUCCESS"
            })
            return result

        except Exception as e:
            self.logs.append({
                "message": message[:50],
                "error"  : str(e),
                "status" : "ERROR"
            })
            raise e

    def get_baseline(self):
        return self.send("How can I help you today ?")

    def get_logs(self):
        return self.logs


class AnthropicTarget:
    """
    Connects LLM Scanner to Anthropic Claude models.
    """

    def __init__(
        self,
        api_key      =None,
        model        ="claude-3-haiku-20240307",
        system_prompt=None
    ):
        self.api_key       = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model         = model
        self.system_prompt = system_prompt or "You are a helpful assistant."
        self.logs          = []

        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. "
                "Set ANTHROPIC_API_KEY in .env or pass api_key parameter."
            )

    def send(self, message):
        """Sends attack prompt to Claude and returns response."""
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)

            start    = time.time()
            response = client.messages.create(
                model     =self.model,
                max_tokens=1024,
                system    =self.system_prompt,
                messages  =[{"role": "user", "content": message}]
            )
            elapsed = round(time.time() - start, 2)
            result  = response.content[0].text

            self.logs.append({
                "message" : message[:50],
                "response": result[:50],
                "elapsed" : elapsed,
                "model"   : self.model,
                "status"  : "SUCCESS"
            })
            return result

        except Exception as e:
            self.logs.append({
                "message": message[:50],
                "error"  : str(e),
                "status" : "ERROR"
            })
            raise e

    def get_baseline(self):
        return self.send("How can I help you today ?")


class GeminiTarget:
    """
    Connects LLM Scanner to Google Gemini models.
    """

    def __init__(
        self,
        api_key      =None,
        model        ="gemini-pro",
        system_prompt=None
    ):
        self.api_key       = api_key or os.getenv("GOOGLE_API_KEY")
        self.model         = model
        self.system_prompt = system_prompt or "You are a helpful assistant."
        self.logs          = []

    def send(self, message):
        """Sends attack prompt to Gemini and returns response."""
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)

            model    = genai.GenerativeModel(self.model)
            prompt   = f"{self.system_prompt}\n\nUser: {message}"
            response = model.generate_content(prompt)
            result   = response.text

            self.logs.append({
                "message" : message[:50],
                "response": result[:50],
                "model"   : self.model,
                "status"  : "SUCCESS"
            })
            return result

        except Exception as e:
            self.logs.append({
                "message": message[:50],
                "error"  : str(e),
                "status" : "ERROR"
            })
            raise e

    def get_baseline(self):
        return self.send("How can I help you today ?")
    