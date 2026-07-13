"""
Correlation engine.

Crosses findings from different modules to find relationships.
This base version detects values appearing in more than one module
(e.g. the same domain referenced by DNS and WHOIS, or an email that
appears in a WHOIS record and also as a target).

It's straightforward to extend with richer rules (e.g. username ->
profiles -> associated emails).
"""
from collections import defaultdict

from .models import ModuleResult, Correlation


def correlate(results: list[ModuleResult]) -> list[Correlation]:
    # Map normalized value -> set of modules mentioning it
    value_to_modules: dict[str, set[str]] = defaultdict(set)

    for res in results:
        for f in res.findings:
            key = f.value.strip().lower()
            if len(key) < 4:
                continue
            value_to_modules[key].add(res.module)

    correlations: list[Correlation] = []
    for value, modules in value_to_modules.items():
        if len(modules) >= 2:
            correlations.append(
                Correlation(
                    description="Value referenced by multiple sources",
                    linked_values=[value],
                    modules=sorted(modules),
                )
            )
    return correlations
