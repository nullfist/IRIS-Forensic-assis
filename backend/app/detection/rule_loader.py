from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from backend.app.core.logging import get_logger

logger = get_logger(__name__)


class RuleLoader:
    """Load YAML rule packs from the repository detection directory."""

    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules_path = rules_path or Path(__file__).resolve().parents[3] / "detection" / "rules"

    def load_rules(self) -> dict[str, list[dict[str, Any]]]:
        if not self.rules_path.exists():
            logger.warning(
                "Rule path does not exist",
                extra={"extra_data": {"rules_path": str(self.rules_path)}},
            )
            return {}

        loaded: dict[str, list[dict[str, Any]]] = {}
        for rule_file in sorted(self.rules_path.glob("*.yml")):
            with rule_file.open("r", encoding="utf-8") as handle:
                # Rules files use --- multi-document YAML; load all documents
                docs = list(yaml.safe_load_all(handle))
            rules: list[dict[str, Any]] = []
            for doc in docs:
                if doc is None:
                    continue
                if isinstance(doc, dict):
                    # Wrapped format: {rules: [...]}
                    if "rules" in doc and isinstance(doc["rules"], list):
                        rules.extend(doc["rules"])
                    else:
                        # Each document IS a rule
                        rules.append(doc)
                elif isinstance(doc, list):
                    rules.extend(doc)
            loaded[rule_file.stem] = rules
        return loaded