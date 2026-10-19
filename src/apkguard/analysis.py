"""Lightweight intra-method analysis over :class:`~apkguard.context.Instruction` lists.

The analysis is intentionally simple: a single linear pass per method that tracks constant values
held in registers (integers, strings, byte arrays derived from constant strings). It ignores
control flow, so it can miss values that are assigned on another branch, but it is fast and
predictable, which matters more for a CI scanner than perfect precision.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from apkguard.context import Instruction, MethodInfo


@dataclass(frozen=True)
class StrConst:
    value: str


@dataclass(frozen=True)
class BytesConst:
    """A byte/char array whose content is fixed at compile time."""

    source: str  # human-readable origin, e.g. '"secret".getBytes()' or 'array literal'


Value = int | StrConst | BytesConst | None

_NON_WRITING_PREFIXES = (
    "invoke",
    "if-",
    "return",
    "goto",
    "throw",
    "packed-switch",
    "sparse-switch",
    "monitor-",
    "check-cast",
    "iput",
    "sput",
    "aput",
    "nop",
    "filled-new-array",
    "fill-array-data",
)

# Calls whose result is a compile-time constant byte array when their input is a constant string,
# mapped to the register position of that input string. For String methods it is the receiver
# (position 0): in ``password.getBytes("UTF-8")`` the constant "UTF-8" is the charset, not the
# data, so only the receiver may count.
_BYTES_FROM_STRING: dict[str, int] = {
    "Ljava/lang/String;->getBytes": 0,
    "Ljava/lang/String;->toCharArray": 0,
    "Landroid/util/Base64;->decode": 0,  # static decode(String, int)
    "Ljava/util/Base64$Decoder;->decode": 1,  # receiver is the Decoder
}


@dataclass(frozen=True)
class CallSite:
    caller: MethodInfo
    index: int
    target: str  # full reference, e.g. 'Ljava/lang/Class;->forName(Ljava/lang/String;)...'
    args: tuple[Value, ...]

    @property
    def target_class(self) -> str:
        return self.target.split("->", 1)[0]

    @property
    def target_name(self) -> str:
        rest = self.target.split("->", 1)[1] if "->" in self.target else self.target
        return rest.split("(", 1)[0]

    @property
    def short_target(self) -> str:
        return f"{self.target_class}->{self.target_name}"

    @property
    def is_static(self) -> bool:
        op = self.caller.instructions[self.index].op
        return op.startswith("invoke-static")

    def arg(self, position: int) -> Value:
        """Return the value of the *declared* parameter at ``position`` (receiver excluded)."""
        offset = 0 if self.is_static else 1
        idx = position + offset
        return self.args[idx] if 0 <= idx < len(self.args) else None

    def string_args(self) -> list[str]:
        return [a.value for a in self.args if isinstance(a, StrConst)]


def iter_calls(method: MethodInfo) -> Iterator[CallSite]:
    """Yield every invoke instruction in ``method`` together with known constant arguments.

    The result is computed once per method and cached on it: seven code rules walk every method,
    and repeating the register tracking for each of them doubled the scan time of large apps.
    Instructions never change after loading, so the cache cannot go stale during a scan.
    """
    if method.call_cache is None:
        method.call_cache = tuple(_track_calls(method))
    return iter(method.call_cache)


def _track_calls(method: MethodInfo) -> Iterator[CallSite]:
    regs: dict[int, Value] = {}
    pending: Value = None
    for index, ins in enumerate(method.instructions):
        op = ins.op
        if op.startswith("invoke"):
            args = tuple(regs.get(r) for r in ins.regs)
            target = ins.ref or ""
            yield CallSite(caller=method, index=index, target=target, args=args)
            pending = _bytes_from_string(target, args)
            continue
        _apply(ins, regs, pending)
        if not op.startswith("move-result"):
            pending = None


def _bytes_from_string(target: str, args: tuple[Value, ...]) -> BytesConst | None:
    """Constant byte array produced by e.g. ``"secret".getBytes()``, or ``None``."""
    short_target = target.split("(", 1)[0]
    position = _BYTES_FROM_STRING.get(short_target)
    if position is None or position >= len(args):
        return None
    source = args[position]
    if not isinstance(source, StrConst):
        return None
    method_name = short_target.split("->", 1)[1]
    return BytesConst(source=f'"{source.value}" ({method_name})')


def _apply(ins: Instruction, regs: dict[int, Value], pending: Value) -> None:
    op = ins.op
    if not ins.regs:
        return
    dest = ins.regs[0]
    if op.startswith("const-string"):
        regs[dest] = StrConst(ins.string or "")
    elif op.startswith("const"):
        regs[dest] = ins.literal
    elif op.startswith("move-result"):
        regs[dest] = pending
    elif op.startswith("move") and not op.startswith("move-exception") and len(ins.regs) > 1:
        regs[dest] = regs.get(ins.regs[1])
    elif op.startswith("fill-array-data"):
        regs[dest] = BytesConst(source="array literal")
    elif not op.startswith(_NON_WRITING_PREFIXES):
        regs[dest] = None


def opcodes(method: MethodInfo) -> list[str]:
    return [ins.op for ins in method.instructions]


def returns_constant(method: MethodInfo, value: int) -> bool:
    """True if every return in ``method`` returns the literal ``value`` and nothing else happens.

    Used to detect e.g. ``HostnameVerifier.verify`` implementations that always return true.
    Only methods made exclusively of constant loads, moves and returns qualify.
    """
    regs: dict[int, Value] = {}
    saw_return = False
    for ins in method.instructions:
        op = ins.op
        if op.startswith("return"):
            if not ins.regs or regs.get(ins.regs[0]) != value:
                return False
            saw_return = True
        elif op.startswith(("const", "move")) or op == "nop":
            _apply(ins, regs, None)
        else:
            return False
    return saw_return


def is_empty_body(method: MethodInfo) -> bool:
    """True if the method does nothing but ``return-void`` (ignoring nops)."""
    ops = [op for op in opcodes(method) if op != "nop"]
    return ops == ["return-void"]
