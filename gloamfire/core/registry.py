# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Plugin registry — maps scenario YAML `attack:` keys to Python attack classes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gloamfire.attacks.base import BaseAttack

_REGISTRY: dict[str, type["BaseAttack"]] = {}


def register(cls: type["BaseAttack"]) -> type["BaseAttack"]:
    """Class decorator — registers an attack plugin under its `name` attribute."""
    if not hasattr(cls, "name") or not cls.name:
        raise ValueError(f"{cls.__qualname__} must define a non-empty `name` attribute")
    _REGISTRY[cls.name] = cls
    return cls


def get(name: str) -> type["BaseAttack"]:
    from gloamfire.core.exceptions import AttackNotFoundError

    if name not in _REGISTRY:
        raise AttackNotFoundError(name)
    return _REGISTRY[name]


def all_attacks() -> dict[str, type["BaseAttack"]]:
    return dict(_REGISTRY)


def load_builtin_attacks() -> None:
    """Import all built-in attack modules so they self-register."""
    import gloamfire.attacks.curl_wget  # noqa: F401
    import gloamfire.attacks.dns_suspicious  # noqa: F401
    import gloamfire.attacks.encoded_command  # noqa: F401
    import gloamfire.attacks.fake_ransomware  # noqa: F401
    import gloamfire.attacks.persistence  # noqa: F401
    import gloamfire.attacks.reverse_shell  # noqa: F401
    import gloamfire.attacks.shell_exec  # noqa: F401
    import gloamfire.attacks.credential_dump  # noqa: F401
    import gloamfire.attacks.log_tampering  # noqa: F401
    import gloamfire.attacks.privilege_escalation  # noqa: F401
