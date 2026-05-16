import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import hashlib
import re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# ── AI Watermarker ────────────────────────────────────────────
class AIWatermarker:
    """
    Embeds invisible watermarks in AI system prompts.
    Detects if your system prompt has been stolen or copied.

    Uses steganographic techniques to hide identity markers
    in the prompt without changing its behavior.
    """

    def __init__(self, owner_id=None):
        self.owner_id = owner_id or "llm_scanner_default"

    def _generate_signature(self, prompt, owner_id):
        """Generates a unique signature for the prompt."""
        content = f"{owner_id}:{prompt[:100]}:{datetime.now().strftime('%Y%m')}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _embed_whitespace_watermark(self, prompt, signature):
        """
        Embeds watermark using invisible Unicode characters.
        Zero-width spaces encode binary signature.
        """
        # Encode signature as binary
        binary = ''.join(format(ord(c), '08b') for c in signature[:4])

        # Map binary to invisible chars
        # 0 = zero-width non-joiner, 1 = zero-width joiner
        ZERO = '\u200C'  # Zero-width non-joiner
        ONE  = '\u200D'  # Zero-width joiner

        watermark = ''.join(ONE if b == '1' else ZERO for b in binary)

        # Insert after first sentence
        sentences = prompt.split('.')
        if len(sentences) > 1:
            return sentences[0] + '.' + watermark + '.' + '.'.join(sentences[1:])
        return prompt + watermark

    def _embed_synonym_watermark(self, prompt, signature):
        """
        Embeds watermark by replacing words with synonyms
        based on signature bits.
        """
        synonym_pairs = [
            ("helpful", "useful"),
            ("never", "do not"),
            ("always", "consistently"),
            ("reveal", "disclose"),
            ("instructions", "directives")
        ]

        watermarked = prompt
        sig_bits    = ''.join(format(ord(c), '08b') for c in signature[:4])

        for i, (word1, word2) in enumerate(synonym_pairs):
            if i < len(sig_bits):
                if sig_bits[i] == '1':
                    watermarked = watermarked.replace(word1, word2)
                    watermarked = watermarked.replace(word1.capitalize(), word2.capitalize())

        return watermarked

    def watermark_prompt(
        self,
        system_prompt,
        method="whitespace",
        metadata=None
    ):
        """
        Embeds a watermark in the system prompt.
        Returns (watermarked_prompt, watermark_data)
        """
        signature = self._generate_signature(
            system_prompt, self.owner_id
        )

        if method == "whitespace":
            watermarked = self._embed_whitespace_watermark(
                system_prompt, signature
            )
        elif method == "synonym":
            watermarked = self._embed_synonym_watermark(
                system_prompt, signature
            )
        else:
            watermarked = system_prompt

        watermark_data = {
            "owner_id"       : self.owner_id,
            "signature"      : signature,
            "method"         : method,
            "original_hash"  : hashlib.sha256(
                system_prompt.encode()
            ).hexdigest()[:16],
            "watermarked_hash": hashlib.sha256(
                watermarked.encode()
            ).hexdigest()[:16],
            "created_at"     : datetime.now().isoformat(),
            "metadata"       : metadata or {}
        }

        # Save watermark registry
        self._save_registry(watermark_data)

        print(f"  Watermark embedded: {signature}")
        print(f"  Method: {method}")
        return watermarked, watermark_data

    def detect_watermark(self, prompt):
        """
        Detects if a prompt contains a watermark.
        """
        ZERO = '\u200C'
        ONE  = '\u200D'

        # Extract invisible chars
        invisible = ''.join(
            c for c in prompt
            if c in (ZERO, ONE)
        )

        if not invisible:
            return None, "No watermark detected"

        # Decode binary
        binary = ''.join('1' if c == ONE else '0' for c in invisible)

        # Decode signature chars
        chars = []
        for i in range(0, len(binary) - 7, 8):
            byte = binary[i:i+8]
            if len(byte) == 8:
                chars.append(chr(int(byte, 2)))

        signature = ''.join(chars)

        # Look up in registry
        registry = self._load_registry()
        for entry in registry:
            if entry.get("signature", "").startswith(signature[:4]):
                return entry, "Watermark found and verified"

        return {"signature": signature}, "Watermark detected (unregistered)"

    def compare_prompts(self, prompt1, prompt2):
        """
        Compares two prompts for similarity.
        Detects potential prompt theft.
        """
        # Normalize
        def normalize(text):
            # Remove invisible chars
            return re.sub(r'[\u200C\u200D\uFEFF]', '', text).strip()

        norm1 = normalize(prompt1)
        norm2 = normalize(prompt2)

        # Jaccard similarity
        words1 = set(norm1.lower().split())
        words2 = set(norm2.lower().split())

        if not words1 or not words2:
            return 0

        intersection = len(words1 & words2)
        union        = len(words1 | words2)
        similarity   = round((intersection / union) * 100, 1)

        return {
            "similarity_pct"    : similarity,
            "is_likely_copy"    : similarity > 80,
            "watermark_in_1"    : self.detect_watermark(prompt1)[0] is not None,
            "watermark_in_2"    : self.detect_watermark(prompt2)[0] is not None
        }

    def _save_registry(self, watermark_data):
        """Saves watermark to registry."""
        registry_path = "results/watermark_registry.json"
        os.makedirs("results", exist_ok=True)

        registry = self._load_registry()
        registry.append(watermark_data)

        with open(registry_path, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2)

    def _load_registry(self):
        """Loads watermark registry."""
        registry_path = "results/watermark_registry.json"
        if os.path.exists(registry_path):
            with open(registry_path, "r", encoding="utf-8") as f:
                try:
                    return json.load(f)
                except:
                    pass
        return []

    def generate_certificate_of_ownership(self, signature):
        """Generates ownership certificate for a watermarked prompt."""
        registry  = self._load_registry()
        watermark = next(
            (w for w in registry if w.get("signature") == signature),
            None
        )

        if not watermark:
            print(f"  Signature not found: {signature}")
            return None

        cert = {
            "certificate_type": "AI Prompt Ownership Certificate",
            "issued_by"       : "LLM Scanner Watermarking System",
            "owner_id"        : watermark["owner_id"],
            "signature"       : signature,
            "original_hash"   : watermark["original_hash"],
            "created_at"      : watermark["created_at"],
            "verified_at"     : datetime.now().isoformat()
        }

        output = f"results/ownership_cert_{signature[:8]}.json"
        with open(output, "w", encoding="utf-8") as f:
            json.dump(cert, f, indent=2)

        print(f"  Ownership certificate: {output}")
        return cert

    def print_registry(self):
        """Prints watermark registry."""
        registry = self._load_registry()
        print(f"\n  Watermark Registry ({len(registry)}):")
        for w in registry:
            print(
                f"  [{w['signature'][:8]}] "
                f"Owner: {w['owner_id']} "
                f"Method: {w['method']} "
                f"Date: {w['created_at'][:10]}"
            )


# ── AI Fingerprinter ──────────────────────────────────────────
class AIFingerprinter:
    """
    Fingerprints AI model behavior for identification.
    Creates behavioral signatures to identify which model
    is running behind an API.
    """

    def __init__(self):
        from groq import Groq
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    def create_probe_prompts(self):
        """Creates fingerprinting probe prompts."""
        return [
            "What is 2+2?",
            "Who created you?",
            "What language model are you based on?",
            "What is your knowledge cutoff date?",
            "Can you write code?",
            "What is the capital of France?",
            "Summarize AI safety in one sentence.",
            "What model version are you?"
        ]

    def fingerprint_model(self, target, sample_size=5):
        """
        Creates a behavioral fingerprint of a model.
        """
        probes    = self.create_probe_prompts()[:sample_size]
        responses = []

        print(f"  Fingerprinting model ({len(probes)} probes)...")

        for probe in probes:
            try:
                response = target.send(probe)
                responses.append({
                    "probe"   : probe,
                    "response": response[:100],
                    "length"  : len(response),
                    "words"   : len(response.split())
                })
                time.sleep(0.3)
            except Exception as e:
                continue

        # Create fingerprint hash
        fingerprint_data = json.dumps([
            r["response"][:50] for r in responses
        ], sort_keys=True)
        fp_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        return {
            "fingerprint"   : fp_hash,
            "created_at"    : datetime.now().isoformat(),
            "probe_count"   : len(responses),
            "avg_response_length": round(
                sum(r["length"] for r in responses) / max(len(responses), 1)
            ),
            "responses"     : responses
        }

    def compare_fingerprints(self, fp1, fp2):
        """Compares two model fingerprints."""
        if fp1["fingerprint"] == fp2["fingerprint"]:
            return True, "Identical fingerprints — same model"

        # Compare response patterns
        resp1 = [r["response"][:30] for r in fp1.get("responses", [])]
        resp2 = [r["response"][:30] for r in fp2.get("responses", [])]

        matches = sum(1 for r1, r2 in zip(resp1, resp2) if r1 == r2)
        total   = max(len(resp1), len(resp2))
        similarity = round(matches / max(total, 1) * 100)

        return similarity > 70, f"Similarity: {similarity}%"


import time

# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    from target import Target

    parser = argparse.ArgumentParser(
        description="LLM Scanner — AI Watermarking & Fingerprinting"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_wm = subparsers.add_parser("watermark")
    p_wm.add_argument("prompt_text")
    p_wm.add_argument("--owner",  default="default")
    p_wm.add_argument("--method", default="whitespace",
        choices=["whitespace","synonym"])

    p_detect = subparsers.add_parser("detect")
    p_detect.add_argument("prompt_text")

    p_fp = subparsers.add_parser("fingerprint")
    p_fp.add_argument("--prompt", default=None)
    p_fp.add_argument("--output", default=None)

    subparsers.add_parser("registry")

    args = parser.parse_args()

    if args.command == "watermark":
        wm = AIWatermarker(args.owner)
        watermarked, data = wm.watermark_prompt(
            args.prompt_text, args.method
        )
        print(f"  Original length   : {len(args.prompt_text)}")
        print(f"  Watermarked length: {len(watermarked)}")
        print(f"  Signature         : {data['signature']}")

    elif args.command == "detect":
        wm   = AIWatermarker()
        data, msg = wm.detect_watermark(args.prompt_text)
        print(f"  {msg}")
        if data:
            print(f"  Data: {json.dumps(data, indent=2)}")

    elif args.command == "fingerprint":
        system_prompt = args.prompt or "You are a helpful assistant."
        target = Target(
            target_type  ="simulation",
            system_prompt=system_prompt
        )
        fp    = AIFingerprinter()
        result = fp.fingerprint_model(target)
        print(f"  Fingerprint: {result['fingerprint']}")
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)

    elif args.command == "registry":
        wm = AIWatermarker()
        wm.print_registry()

    else:
        parser.print_help()