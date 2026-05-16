"""
YARA rule scanner for forensic file matching.

Loads a compiled .yar rule set and scans file content bytes against it.
Returns structured match results usable in the UI results table.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class YARAMatch:
    rule_name:  str
    tags:       list[str]
    strings:    list[tuple[int, str, bytes]]   # (offset, identifier, data)
    file_path:  str


class YARAScanner:
    """Load rules once, scan many files."""

    def __init__(self):
        self._rules = None

    def load_rules(self, rules_path: str) -> None:
        """Compile and load a .yar file. Raises on syntax errors."""
        import yara
        self._rules = yara.compile(filepath=rules_path)

    def load_rules_from_string(self, source: str) -> None:
        """Compile rules from a string (useful for testing)."""
        import yara
        self._rules = yara.compile(source=source)

    @property
    def rules_loaded(self) -> bool:
        return self._rules is not None

    def scan_bytes(self, file_path: str, data: bytes) -> list[YARAMatch]:
        """
        Scan data bytes against loaded rules.
        Returns list of YARAMatch (empty if no matches or rules not loaded).
        """
        if not self._rules:
            return []
        try:
            matches = self._rules.match(data=data)
            results = []
            for m in matches:
                strings = []
                for s in m.strings:
                    if s.instances:
                        inst = s.instances[0]
                        strings.append((inst.offset, s.identifier, inst.matched_data))
                    else:
                        strings.append((0, s.identifier, b""))
                results.append(YARAMatch(
                    rule_name=m.rule,
                    tags=list(m.tags),
                    strings=strings,
                    file_path=file_path,
                ))
            return results
        except Exception:
            return []

    def scan_file(self, file_path: str) -> list[YARAMatch]:
        """Scan a file on disk (convenience wrapper)."""
        if not self._rules:
            return []
        try:
            with open(file_path, "rb") as f:
                return self.scan_bytes(file_path, f.read())
        except Exception:
            return []
