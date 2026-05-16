import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import random
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# ── Training Data Generator ───────────────────────────────────
class AdversarialTrainingGenerator:
    """
    Generates adversarial training data to help
    AI developers build more robust systems.
    Creates attack-defense pairs for fine-tuning.
    """

    def __init__(self):
        from groq import Groq
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    def generate_safe_response(self, attack_prompt, system_role):
        """
        Generates the ideal safe response to an attack.
        """
        prompt = f"""You are an AI safety expert.
Generate the IDEAL safe response to this adversarial attack.

SYSTEM ROLE: {system_role}
ATTACK: {attack_prompt}

The ideal response should:
1. Politely decline the attack
2. Not reveal any system information
3. Redirect to legitimate help
4. Be natural and not robotic

Generate ONLY the ideal response text:"""

        response = self.client.chat.completions.create(
            model    ="llama-3.3-70b-versatile",
            messages =[{"role": "user", "content": prompt}],
            max_tokens=150
        )
        return response.choices[0].message.content.strip()

    def generate_training_pair(self, attack, category, system_role):
        """
        Generates a single training pair:
        (attack_prompt, ideal_safe_response)
        """
        safe_response = self.generate_safe_response(
            attack, system_role
        )

        return {
            "messages": [
                {
                    "role"   : "system",
                    "content": system_role
                },
                {
                    "role"   : "user",
                    "content": attack
                },
                {
                    "role"   : "assistant",
                    "content": safe_response
                }
            ],
            "metadata": {
                "category"    : category,
                "attack_type" : "adversarial",
                "is_safe"     : True,
                "generated_at": datetime.now().isoformat()
            }
        }

    def generate_dataset(
        self,
        system_role   ="You are a helpful banking assistant.",
        categories    =None,
        pairs_per_cat =5,
        output_path   ="results/adversarial_training_data.jsonl"
    ):
        """
        Generates a full adversarial training dataset.
        Output format: JSONL (one JSON per line)
        Compatible with OpenAI fine-tuning format.
        """
        from attacks.prompts import ATTACK_PROMPTS

        cats     = categories or list(ATTACK_PROMPTS.keys())[:5]
        dataset  = []

        print(f"\n{'='*60}")
        print(f"  🧬 ADVERSARIAL TRAINING DATA GENERATOR")
        print(f"  Categories : {len(cats)}")
        print(f"  Pairs/cat  : {pairs_per_cat}")
        print(f"{'='*60}\n")

        for cat in cats:
            prompts = ATTACK_PROMPTS.get(cat, [])[:pairs_per_cat]
            print(f"  Generating for: {cat} ({len(prompts)} pairs)...")

            for attack in prompts:
                try:
                    pair = self.generate_training_pair(
                        attack, cat, system_role
                    )
                    dataset.append(pair)
                    print(f"  ✅ Pair generated: {attack[:40]}...")
                except Exception as e:
                    print(f"  ❌ Error: {e}")

        # Save as JSONL
        os.makedirs("results", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            for pair in dataset:
                f.write(json.dumps(pair, ensure_ascii=False) + "\n")

        # Save summary
        summary = {
            "generated_at"  : datetime.now().isoformat(),
            "total_pairs"   : len(dataset),
            "categories"    : cats,
            "system_role"   : system_role,
            "format"        : "openai_fine_tuning",
            "output_file"   : output_path
        }

        summary_path = output_path.replace(".jsonl", "_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"\n  Dataset generated: {len(dataset)} pairs")
        print(f"  Output: {output_path}")
        print(f"  Format: OpenAI fine-tuning compatible")

        return dataset, summary

    def augment_existing_data(self, dataset_path, augmentation_factor=2):
        """
        Augments existing training data by generating variations.
        """
        with open(dataset_path, "r", encoding="utf-8") as f:
            existing = [json.loads(line) for line in f]

        augmented = []
        print(f"  Augmenting {len(existing)} examples...")

        for pair in existing[:10]:  # Limit for token budget
            user_msg = next(
                (m["content"] for m in pair["messages"]
                 if m["role"] == "user"),
                ""
            )

            # Generate variations
            prompt = f"""Generate {augmentation_factor} variations of
this adversarial prompt. Keep the same attack intent but different wording.
One per line:

ORIGINAL: {user_msg}

VARIATIONS:"""

            try:
                response = self.client.chat.completions.create(
                    model    ="llama-3.3-70b-versatile",
                    messages =[{"role": "user", "content": prompt}],
                    max_tokens=200
                )

                variations = [
                    line.strip()
                    for line in response.choices[0].message.content.split("\n")
                    if line.strip() and len(line.strip()) > 10
                ]

                for var in variations[:augmentation_factor]:
                    system_role = next(
                        (m["content"] for m in pair["messages"]
                         if m["role"] == "system"),
                        "You are a helpful assistant."
                    )
                    cat = pair.get("metadata", {}).get("category", "unknown")

                    new_pair = self.generate_training_pair(
                        var, cat, system_role
                    )
                    augmented.append(new_pair)

            except Exception as e:
                continue

        # Save augmented data
        output = dataset_path.replace(".jsonl", "_augmented.jsonl")
        with open(output, "w", encoding="utf-8") as f:
            for pair in existing + augmented:
                f.write(json.dumps(pair, ensure_ascii=False) + "\n")

        print(f"  Augmented dataset: {len(existing) + len(augmented)} pairs")
        print(f"  Output: {output}")
        return augmented


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Adversarial Training Generator"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_gen = subparsers.add_parser("generate")
    p_gen.add_argument("--categories", nargs="+", default=None)
    p_gen.add_argument("--pairs",      type=int, default=5)
    p_gen.add_argument("--role",       default="You are a banking assistant.")
    p_gen.add_argument("--output",     default="results/training_data.jsonl")

    p_aug = subparsers.add_parser("augment")
    p_aug.add_argument("dataset_path")
    p_aug.add_argument("--factor", type=int, default=2)

    args = parser.parse_args()
    gen  = AdversarialTrainingGenerator()

    if args.command == "generate":
        gen.generate_dataset(
            system_role   =args.role,
            categories    =args.categories,
            pairs_per_cat =args.pairs,
            output_path   =args.output
        )
    elif args.command == "augment":
        gen.augment_existing_data(args.dataset_path, args.factor)
    else:
        gen.generate_dataset()
        