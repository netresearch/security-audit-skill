#!/usr/bin/env python3
"""Validate checkpoints.yaml structure and check for duplicate IDs."""

import sys

import yaml


def main() -> int:
    with open("skills/security-audit/checkpoints.yaml") as f:
        data = yaml.safe_load(f)

    if "mechanical" not in data:
        print("ERROR: missing mechanical section")
        return 1
    if "llm_reviews" not in data:
        print("ERROR: missing llm_reviews section")
        return 1

    mech_ids = [r["id"] for r in data["mechanical"]]
    llm_ids = [r["id"] for r in data["llm_reviews"]]
    all_ids = mech_ids + llm_ids
    dupes = [x for x in all_ids if all_ids.count(x) > 1]
    if dupes:
        print(f"ERROR: duplicate checkpoint IDs: {set(dupes)}")
        return 1

    print(f"Valid: {len(mech_ids)} mechanical + {len(llm_ids)} LLM review checkpoints")
    return 0


if __name__ == "__main__":
    sys.exit(main())
