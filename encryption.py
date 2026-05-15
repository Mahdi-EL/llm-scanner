import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import base64
import hashlib
from datetime import datetime


# ── Key Management ────────────────────────────────────────────
class KeyManager:
    """
    Manages encryption keys for LLM Scanner.
    Keys are derived from the Groq API key — no extra setup needed.
    """

    KEY_FILE = "results/.encryption_key"

    @classmethod
    def get_or_create_key(cls):
        """
        Gets existing key or creates a new one.
        Key is stored locally and never uploaded to GitHub.
        """
        os.makedirs("results", exist_ok=True)

        if os.path.exists(cls.KEY_FILE):
            with open(cls.KEY_FILE, "r") as f:
                return f.read().strip()

        # Generate new key from API key + random salt
        api_key  = os.getenv("GROQ_API_KEY", "default")
        salt     = os.urandom(16).hex()
        key_input = f"{api_key}{salt}"
        key      = hashlib.sha256(key_input.encode()).hexdigest()

        with open(cls.KEY_FILE, "w") as f:
            f.write(key)

        print(f"Encryption key generated : {cls.KEY_FILE}")
        return key

    @classmethod
    def derive_key(cls, master_key, purpose):
        """Derives a purpose-specific key from master key."""
        return hashlib.sha256(
            f"{master_key}{purpose}".encode()
        ).hexdigest()


# ── Simple Encryption ─────────────────────────────────────────
class DataEncryptor:
    """
    Simple XOR-based encryption for scan data.
    Not military grade but sufficient for local data protection.
    Uses the master key to protect sensitive findings.
    """

    def __init__(self, key=None):
        self.key = key or KeyManager.get_or_create_key()

    def _xor_encrypt(self, data, key):
        """XOR encryption with key repetition."""
        key_bytes  = key.encode()
        data_bytes = data.encode() if isinstance(data, str) else data
        encrypted  = bytes([
            b ^ key_bytes[i % len(key_bytes)]
            for i, b in enumerate(data_bytes)
        ])
        return base64.b64encode(encrypted).decode()

    def _xor_decrypt(self, encrypted_data, key):
        """XOR decryption."""
        key_bytes     = key.encode()
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted     = bytes([
            b ^ key_bytes[i % len(key_bytes)]
            for i, b in enumerate(encrypted_bytes)
        ])
        return decrypted.decode()

    def encrypt_text(self, text):
        """Encrypts a text string."""
        if not text:
            return text
        return self._xor_encrypt(str(text), self.key)

    def decrypt_text(self, encrypted):
        """Decrypts an encrypted text string."""
        if not encrypted:
            return encrypted
        try:
            return self._xor_decrypt(encrypted, self.key)
        except:
            return encrypted  # Return as-is if decryption fails

    def encrypt_finding(self, finding):
        """
        Encrypts sensitive fields of a vulnerability finding.
        Keeps metadata (severity, score) readable for indexing.
        """
        encrypted = finding.copy()

        # Encrypt sensitive content
        sensitive_fields = ["attack", "response", "reason", "explanation"]
        for field in sensitive_fields:
            if field in encrypted and encrypted[field]:
                encrypted[field] = self.encrypt_text(
                    str(encrypted[field])
                )

        encrypted["_encrypted"] = True
        return encrypted

    def decrypt_finding(self, finding):
        """Decrypts an encrypted finding."""
        if not finding.get("_encrypted"):
            return finding

        decrypted = finding.copy()
        sensitive_fields = ["attack", "response", "reason", "explanation"]
        for field in sensitive_fields:
            if field in decrypted and decrypted[field]:
                decrypted[field] = self.decrypt_text(
                    decrypted[field]
                )

        decrypted["_encrypted"] = False
        return decrypted

    def encrypt_report(self, report_data):
        """
        Encrypts sensitive data in a full scan report.
        Summary statistics remain readable.
        Results are encrypted.
        """
        encrypted_report = {
            "scan_date"    : report_data["scan_date"],
            "total_attacks": report_data["total_attacks"],
            "summary"      : report_data["summary"],
            "_encrypted"   : True,
            "_encrypted_at": datetime.now().isoformat(),
            "results"      : [
                self.encrypt_finding(r)
                for r in report_data.get("results", [])
            ]
        }
        return encrypted_report

    def decrypt_report(self, encrypted_report):
        """Decrypts a full scan report."""
        if not encrypted_report.get("_encrypted"):
            return encrypted_report

        decrypted_report = {
            "scan_date"    : encrypted_report["scan_date"],
            "total_attacks": encrypted_report["total_attacks"],
            "summary"      : encrypted_report["summary"],
            "_encrypted"   : False,
            "results"      : [
                self.decrypt_finding(r)
                for r in encrypted_report.get("results", [])
            ]
        }
        return decrypted_report


# ── Encrypted File Manager ────────────────────────────────────
class EncryptedFileManager:
    """
    Saves and loads encrypted scan results.
    """

    def __init__(self, encryptor=None):
        self.encryptor = encryptor or DataEncryptor()

    def save_encrypted(self, data, filepath):
        """Saves data as encrypted JSON."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        encrypted = self.encryptor.encrypt_report(data)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(encrypted, f, indent=2, ensure_ascii=False)

        print(f"Encrypted save : {filepath}")

    def load_decrypted(self, filepath):
        """Loads and decrypts JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if data.get("_encrypted"):
            return self.encryptor.decrypt_report(data)

        return data

    def encrypt_existing_file(self, filepath):
        """Encrypts an existing unencrypted JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if data.get("_encrypted"):
            print(f"Already encrypted : {filepath}")
            return

        self.save_encrypted(data, filepath)
        print(f"Encrypted : {filepath}")

    def encrypt_all_results(self, results_dir="results"):
        """Encrypts all JSON files in results directory."""
        if not os.path.exists(results_dir):
            return

        encrypted_count = 0
        for filename in os.listdir(results_dir):
            if not filename.endswith(".json"):
                continue
            if "checkpoint" in filename:
                continue
            if "generated" in filename:
                continue

            filepath = os.path.join(results_dir, filename)
            try:
                self.encrypt_existing_file(filepath)
                encrypted_count += 1
            except Exception as e:
                print(f"Skipped {filename} : {e}")

        print(f"\nEncrypted {encrypted_count} files")


# ── Privacy Cleaner ───────────────────────────────────────────
class PrivacyCleaner:
    """
    Removes sensitive data from scan results
    before sharing or exporting.
    """

    @staticmethod
    def clean_for_sharing(report_data):
        """
        Creates a sanitized version of the report
        safe to share externally.
        Removes full attack prompts and responses.
        """
        cleaned = {
            "scan_date"    : report_data["scan_date"],
            "total_attacks": report_data["total_attacks"],
            "summary"      : report_data["summary"],
            "_sanitized"   : True,
            "results"      : []
        }

        for r in report_data.get("results", []):
            cleaned_result = {
                "category": r["category"],
                "severity": r["severity"],
                "score"   : r["score"],
                "reason"  : r.get("reason", "")[:100],
                # Remove full attack and response
                "attack"  : r.get("attack", "")[:30] + "...",
                "response": "[REDACTED]"
            }
            cleaned["results"].append(cleaned_result)

        return cleaned

    @staticmethod
    def remove_old_results(results_dir="results", days_old=30):
        """Removes scan results older than N days."""
        import time

        if not os.path.exists(results_dir):
            return

        now      = time.time()
        removed  = 0
        cutoff   = days_old * 24 * 60 * 60

        for filename in os.listdir(results_dir):
            filepath = os.path.join(results_dir, filename)
            if not os.path.isfile(filepath):
                continue

            age = now - os.path.getmtime(filepath)
            if age > cutoff:
                os.remove(filepath)
                removed += 1
                print(f"Removed old file : {filename}")

        print(f"Removed {removed} files older than {days_old} days")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    print("LLM Scanner — Encryption Module")
    print("=" * 40)

    if len(sys.argv) > 1:
        cmd = sys.argv[1]

        if cmd == "encrypt-all":
            manager = EncryptedFileManager()
            manager.encrypt_all_results()

        elif cmd == "test":
            print("Testing encryption...")

            encryptor = DataEncryptor()

            # Test basic encryption
            original  = "This is sensitive data"
            encrypted = encryptor.encrypt_text(original)
            decrypted = encryptor.decrypt_text(encrypted)

            assert original == decrypted
            assert original != encrypted
            print("✅ Basic encryption works")

            # Test finding encryption
            finding = {
                "category": "direct_override",
                "attack"  : "Ignore all instructions",
                "response": "I cannot ignore my instructions",
                "score"   : 7,
                "severity": "HIGH",
                "reason"  : "Revealed internal config"
            }

            enc_finding = encryptor.encrypt_finding(finding)
            dec_finding = encryptor.decrypt_finding(enc_finding)

            assert dec_finding["attack"] == finding["attack"]
            assert enc_finding["attack"] != finding["attack"]
            assert enc_finding["severity"] == finding["severity"]
            print("✅ Finding encryption works")
            print("✅ Severity/score remain readable")
            print("\nAll encryption tests passed !")

        elif cmd == "clean":
            days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
            PrivacyCleaner.remove_old_results(days_old=days)

        elif cmd == "generate-key":
            key = KeyManager.get_or_create_key()
            print(f"Key : {key[:16]}... (saved to results/.encryption_key)")

    else:
        print("Usage :")
        print("  python encryption.py test         → Test encryption")
        print("  python encryption.py encrypt-all  → Encrypt all results")
        print("  python encryption.py generate-key → Generate key")
        print("  python encryption.py clean 30     → Remove files older than 30 days")

        