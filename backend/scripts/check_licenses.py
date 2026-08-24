"""Fail CI when a direct Python dependency declares a forbidden copyleft license."""

import importlib.metadata
import re
from pathlib import Path

FORBIDDEN = re.compile(r"\b(AGPL|SSPL|GPL-[123]|GPLv[123])\b", re.IGNORECASE)


def requirement_names(path: Path) -> set[str]:
    names = set()
    for raw in path.read_text().splitlines():
        value = raw.strip()
        if not value or value.startswith(("#", "-r")):
            continue
        names.add(re.split(r"[<>=!~\[]", value, maxsplit=1)[0].strip().lower().replace("_", "-"))
    return names


failures = []
for name in sorted(requirement_names(Path(__file__).parents[1] / "requirements.txt")):
    metadata = importlib.metadata.metadata(name)
    declared = " | ".join([metadata.get("License", ""), *metadata.get_all("Classifier", [])])
    if FORBIDDEN.search(declared):
        failures.append(f"{name}: {metadata.get('License', 'unknown')}")

if failures:
    raise SystemExit("Forbidden dependency licenses:\n" + "\n".join(failures))
print("Python direct-dependency license policy passed.")
