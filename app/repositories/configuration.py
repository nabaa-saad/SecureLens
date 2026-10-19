"""Configuration and governance repositories."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.database import DatabaseHandler


class ConfigurationRepository:
    """Encapsulate app configuration and governance-rule persistence."""

    def __init__(self, db: DatabaseHandler):
        self.db = db

    def set_value(self, key: str, value: str) -> None:
        self.db.set_config(key, value)

    def get_value(self, key: str) -> Optional[str]:
        return self.db.get_config_value(key)

    def add_rule(self, domain: str, rule_type: str) -> bool:
        return self.db.add_rule(domain, rule_type)

    def delete_rule(self, rule_id: int) -> None:
        self.db.delete_rule(rule_id)

    def get_rules(self) -> List[Dict[str, Any]]:
        return self.db.get_rules()
