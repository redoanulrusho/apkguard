"""AG-CODE-002: reflection-heavy code."""

from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar

from apkguard.analysis import StrConst, iter_calls
from apkguard.context import ApkContext
from apkguard.model import Category, Finding, RuleMeta, Severity
from apkguard.rules._util import class_location
from apkguard.rules.base import Rule

REFLECTION_APIS = frozenset(
    {
        "Ljava/lang/Class;->forName",
        "Ljava/lang/Class;->getMethod",
        "Ljava/lang/Class;->getDeclaredMethod",
        "Ljava/lang/Class;->getField",
        "Ljava/lang/Class;->getDeclaredField",
        "Ljava/lang/Class;->getDeclaredConstructor",
        "Ljava/lang/Class;->newInstance",
        "Ljava/lang/reflect/Method;->invoke",
        "Ljava/lang/reflect/Constructor;->newInstance",
        "Ljava/lang/reflect/AccessibleObject;->setAccessible",
        "Ljava/lang/reflect/Method;->setAccessible",
        "Ljava/lang/reflect/Field;->setAccessible",
        "Ljava/lang/reflect/Field;->set",
    }
)
# Lookups whose first argument names the class/member being reached.
_NAME_LOOKUPS = frozenset(
    {
        "Ljava/lang/Class;->forName",
        "Ljava/lang/Class;->getMethod",
        "Ljava/lang/Class;->getDeclaredMethod",
        "Ljava/lang/Class;->getField",
        "Ljava/lang/Class;->getDeclaredField",
    }
)
# Prefixes of platform internals commonly reached via reflection to bypass API restrictions.
HIDDEN_API_PREFIXES = ("android.app.ActivityThread", "com.android.internal.", "dalvik.system.")


class ReflectionRule(Rule):
    meta = RuleMeta(
        id="AG-CODE-002",
        title="Reflection-heavy code",
        severity=Severity.LOW,
        category=Category.CODE,
        description=(
            "Classes that make many reflective calls (Class.forName, getDeclaredMethod, "
            "Method.invoke, setAccessible), especially with names that are not compile-time "
            "constants, hide their behaviour from static analysis and are a common obfuscation "
            "technique. Reflection is also used to reach hidden platform APIs."
        ),
        remediation=(
            "Prefer direct, type-safe calls. Where reflection is needed (e.g. optional "
            "dependencies), use constant class/member names, never build them from external "
            "input, and avoid accessing non-SDK (hidden) interfaces."
        ),
        references=(
            "https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces",
            "https://cwe.mitre.org/data/definitions/470.html",
        ),
        cwe="CWE-470",
        masvs="MASVS-CODE-4",
    )
    default_options: ClassVar[dict[str, object]] = {"threshold": 8}

    def check(self, ctx: ApkContext) -> Iterable[Finding]:
        threshold = self.option_int("threshold")
        for cls in ctx.app_classes():
            total = 0
            dynamic = 0
            hidden: set[str] = set()
            apis: set[str] = set()
            for method in cls.methods:
                for call in iter_calls(method):
                    target = call.short_target
                    if target not in REFLECTION_APIS:
                        continue
                    total += 1
                    apis.add(target.split(";->")[-1])
                    if target in _NAME_LOOKUPS:
                        name = call.arg(0)
                        if isinstance(name, StrConst):
                            if name.value.startswith(HIDDEN_API_PREFIXES):
                                hidden.add(name.value)
                        else:
                            dynamic += 1
            if hidden:
                yield self.finding(
                    f"{cls.name} uses reflection to reach non-SDK platform internals: "
                    f"{', '.join(sorted(hidden))}.",
                    class_location(cls),
                    evidence=", ".join(sorted(hidden)),
                )
            if total >= threshold:
                yield self.finding(
                    f"{cls.name} makes {total} reflective calls ({dynamic} with non-constant "
                    f"names) using {', '.join(sorted(apis))}.",
                    class_location(cls),
                    # No count-based evidence: it feeds the fingerprint, and one extra call
                    # must not turn an accepted (baselined) finding into a "new" one.
                    reflective_calls=total,
                    dynamic_names=dynamic,
                )
