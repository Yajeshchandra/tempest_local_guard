from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from litellm import completion

from tempest.lde.evidence import Finding
from tempest.rim import RepositoryIntelligenceModel

def apply_semantic_filter(
    findings: list[Finding],
    rim: RepositoryIntelligenceModel
) -> list[Finding]:
    """
    Lazily filters Rule B findings (test -> prod) by asking an LLM if the 
    operation is actually a WRITE/mutation. Drops it if it's just a READ.
    
    Triggered only if llm_config exists in tempest.config.yaml.
    """
    llm_cfg = rim.config.get("llm_config")
    if not llm_cfg or not llm_cfg.get("enabled"):
        return findings

    model = llm_cfg.get("model", "gpt-4o-mini")
    api_key = llm_cfg.get("api_key") or os.environ.get("OPENAI_API_KEY")
    api_base = llm_cfg.get("api_base")

    if not api_key and not api_base:
        # Fallback if config is malformed but enabled
        return findings

    filtered = []
    for f in findings:
        if f.rule != "b":
            filtered.append(f)
            continue

        # Extract the file containing the test/caller
        src_file = f.source_node.get("source_file")
        if not src_file:
            filtered.append(f)
            continue

        full_path = Path(rim.repo_root) / src_file
        if not full_path.exists():
            filtered.append(f)
            continue

        try:
            code_text = full_path.read_text(encoding="utf-8")
        except Exception:
            filtered.append(f)
            continue

        prompt = f"""
You are a security leak detection assistant. We found a structural connection 
between a test/dev function and a production database.

Test/Dev Function: {f.source_node.get("label")}
Production Target: {f.target_node.get("label")}

Here is the source file containing the test/dev function:
```
{code_text}
```

Does this function actually WRITE, SEED, DELETE, or MUTATE data in the production target?
Or is it strictly READING data?

Reply with exactly one word: "WRITE" or "READ".
"""
        try:
            response = completion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                api_key=api_key,
                api_base=api_base,
                temperature=0.0,
            )
            answer = response.choices[0].message.content.strip().upper()
            if "WRITE" in answer:
                f.evidence["semantic_verification"] = "WRITE (LLM Confirmed)"
                filtered.append(f)
            else:
                # Dropped! It's just a read.
                pass
        except Exception as e:
            # Ponytail: on LLM failure, default to noisy (keep the finding)
            f.evidence["semantic_verification"] = f"ERROR: {e}"
            filtered.append(f)

    return filtered
