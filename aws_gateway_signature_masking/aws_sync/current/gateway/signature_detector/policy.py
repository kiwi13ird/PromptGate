"""관리자 제어 Signature 정책과 안전한 우선순위."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import os
from typing import Iterable, Mapping


class PolicyAction(str, Enum):
    ALLOW = "allow"
    ALLOW_NOTIFY = "allow_notify"
    BLOCK_NOTIFY = "block_notify"
    MASK_PARTIAL = "mask_partial"
    MASK_FULL = "mask_full"


CREDENTIAL_ENTITIES = frozenset({"GITHUB_TOKEN", "GENERIC_API_KEY", "PASSWORD"})

ACTION_PRIORITY = {
    PolicyAction.ALLOW: 0,
    PolicyAction.ALLOW_NOTIFY: 1,
    PolicyAction.MASK_PARTIAL: 2,
    PolicyAction.MASK_FULL: 3,
    PolicyAction.BLOCK_NOTIFY: 4,
}


@dataclass(frozen=True)
class PolicyConfig:
    """Entity별 관리자 정책. 지정되지 않은 탐지는 기본적으로 전체 마스킹한다."""

    entity_actions: Mapping[str, PolicyAction] = field(default_factory=dict)
    default_action: PolicyAction = PolicyAction.MASK_FULL

    def action_for(self, entity_type: str) -> PolicyAction:
        action = PolicyAction(self.entity_actions.get(entity_type, self.default_action))
        if entity_type in CREDENTIAL_ENTITIES and action is PolicyAction.MASK_PARTIAL:
            return PolicyAction.MASK_FULL
        return action

    @classmethod
    def from_json(cls, raw: str | None) -> "PolicyConfig":
        """관리자 설정 JSON을 엄격히 읽는다. 잘못된 정책은 조용히 허용하지 않는다."""

        if not raw:
            return cls()
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Signature policy must be a JSON object")
        default_action = PolicyAction(data.get("default_action", PolicyAction.MASK_FULL))
        entity_actions = data.get("entity_actions", {})
        if not isinstance(entity_actions, dict):
            raise ValueError("entity_actions must be a JSON object")
        return cls(
            {str(entity): PolicyAction(action) for entity, action in entity_actions.items()},
            default_action,
        )

    @classmethod
    def from_environment(cls, name: str = "SIGNATURE_POLICY_JSON") -> "PolicyConfig":
        return cls.from_json(os.getenv(name))


def strongest_action(actions: Iterable[PolicyAction]) -> PolicyAction:
    values = [PolicyAction(action) for action in actions]
    if not values:
        return PolicyAction.ALLOW
    return max(values, key=ACTION_PRIORITY.__getitem__)
