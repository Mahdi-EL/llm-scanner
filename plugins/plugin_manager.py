import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import importlib.util
from attacks.prompts import ATTACK_PROMPTS


class PluginManager:
    """
    Manages LLM Scanner plugins.
    Automatically loads all plugins from the plugins/ directory.
    """

    def __init__(self):
        self.attack_prompts = dict(ATTACK_PROMPTS)
        self.detectors      = {}
        self.loaded_plugins = []

    def register_detector(self, name, func):
        """Registers a custom detector function."""
        self.detectors[name] = func
        print(f"  Detector registered : {name}")

    def load_plugins(self, plugins_dir="plugins"):
        """Loads all plugins from the plugins directory."""
        if not os.path.exists(plugins_dir):
            return

        print(f"\n  Loading plugins from {plugins_dir}/...")

        for filename in os.listdir(plugins_dir):
            if not filename.endswith(".py"):
                continue
            if filename.startswith("_"):
                continue

            plugin_path = os.path.join(plugins_dir, filename)
            self._load_plugin(plugin_path)

        print(f"  Loaded {len(self.loaded_plugins)} plugin(s)")

    def _load_plugin(self, path):
        """Loads a single plugin file."""
        try:
            spec   = importlib.util.spec_from_file_location("plugin", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, "register"):
                module.register(self)
                self.loaded_plugins.append({
                    "name"   : getattr(module, "PLUGIN_NAME", path),
                    "version": getattr(module, "PLUGIN_VERSION", "1.0.0"),
                    "author" : getattr(module, "PLUGIN_AUTHOR", "Unknown"),
                    "path"   : path
                })
        except Exception as e:
            print(f"  Failed to load plugin {path} : {e}")

    def get_all_prompts(self):
        """Returns all prompts including plugin prompts."""
        return self.attack_prompts

    def run_custom_detectors(self, attack, response):
        """
        Runs all registered custom detectors.
        Returns list of findings.
        """
        findings = []
        for name, detector in self.detectors.items():
            try:
                is_vuln, reason = detector(attack, response)
                if is_vuln:
                    findings.append({
                        "detector": name,
                        "reason"  : reason
                    })
            except Exception as e:
                print(f"  Detector error ({name}) : {e}")
        return findings

    def print_info(self):
        """Prints info about loaded plugins."""
        if not self.loaded_plugins:
            print("  No plugins loaded")
            return

        print(f"\n  Loaded Plugins ({len(self.loaded_plugins)}) :")
        for p in self.loaded_plugins:
            print(f"  → {p['name']} v{p['version']} by {p['author']}")

        total_custom = sum(
            len(v) for k, v in self.attack_prompts.items()
            if k not in ATTACK_PROMPTS
        )
        print(f"  Custom prompts added : {total_custom}")
        print(f"  Custom detectors     : {len(self.detectors)}")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    manager = PluginManager()
    manager.load_plugins()
    manager.print_info()

    total = sum(len(p) for p in manager.get_all_prompts().values())
    print(f"\n  Total prompts with plugins : {total}")
    