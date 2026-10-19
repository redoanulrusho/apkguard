from __future__ import annotations

from apkguard.analysis import (
    BytesConst,
    StrConst,
    is_empty_body,
    iter_calls,
    returns_constant,
)
from apkguard.context import Instruction

from helpers import const, const_string, fill_array, invoke, method, move_result, ret, ret_void

CLS = "Lcom/example/A;"


def test_iter_calls_tracks_string_and_int_constants() -> None:
    m = method(
        CLS,
        "f",
        const_string(0, "hello"),
        const(1, 7),
        invoke("Lcom/x/Y;->g(Ljava/lang/String;I)V", 2, 0, 1),
    )
    calls = list(iter_calls(m))
    assert len(calls) == 1
    call = calls[0]
    assert call.short_target == "Lcom/x/Y;->g"
    assert call.target_name == "g"
    assert call.arg(0) == StrConst("hello")
    assert call.arg(1) == 7
    assert call.string_args() == ["hello"]


def test_static_call_has_no_receiver_offset() -> None:
    m = method(
        CLS,
        "f",
        const_string(0, "x"),
        invoke("Lcom/x/Y;->s(Ljava/lang/String;)V", 0, kind="static"),
    )
    assert next(iter_calls(m)).arg(0) == StrConst("x")


def test_move_copies_register_value() -> None:
    m = method(
        CLS,
        "f",
        const_string(0, "v"),
        Instruction("move-object", (3, 0)),
        invoke("Lcom/x/Y;->s(Ljava/lang/String;)V", 3, kind="static"),
    )
    assert next(iter_calls(m)).arg(0) == StrConst("v")


def test_getbytes_on_constant_yields_bytes_constant() -> None:
    m = method(
        CLS,
        "f",
        const_string(0, "key"),
        invoke("Ljava/lang/String;->getBytes()[B", 0),
        move_result(1),
        invoke("Lcom/x/Y;->use([B)V", 1, kind="static"),
    )
    calls = list(iter_calls(m))
    assert isinstance(calls[1].arg(0), BytesConst)


def test_getbytes_with_constant_charset_on_unknown_string_is_not_constant() -> None:
    # Regression (found in the F-Droid evaluation): password.getBytes("UTF-8") was treated as
    # the constant "UTF-8" because any constant argument counted, not just the receiver.
    m = method(
        CLS,
        "f",
        const_string(3, "UTF-8"),
        invoke("Ljava/lang/String;->getBytes(Ljava/lang/String;)[B", 6, 3),
        move_result(6),
        invoke("Lcom/x/Y;->use([B)V", 6, kind="static"),
    )
    calls = list(iter_calls(m))
    assert calls[1].arg(0) is None


def test_java_base64_decoder_uses_argument_not_receiver() -> None:
    m = method(
        CLS,
        "f",
        const_string(1, "c2VjcmV0"),
        invoke("Ljava/util/Base64$Decoder;->decode(Ljava/lang/String;)[B", 0, 1),
        move_result(2),
        invoke("Lcom/x/Y;->use([B)V", 2, kind="static"),
    )
    assert next(c for c in iter_calls(m) if c.target_name == "use").arg(0) == BytesConst(
        '"c2VjcmV0" (decode)'
    )


def test_unknown_instruction_clears_destination_register() -> None:
    m = method(
        CLS,
        "f",
        const_string(0, "x"),
        Instruction("iget-object", (0, 5), ref="Lcom/x/Y;->field:Ljava/lang/String;"),
        invoke("Lcom/x/Y;->s(Ljava/lang/String;)V", 0, kind="static"),
    )
    assert next(iter_calls(m)).arg(0) is None


def test_move_result_after_unrelated_call_is_unknown() -> None:
    m = method(
        CLS,
        "f",
        invoke("Lcom/x/Y;->get()[B", kind="static"),
        move_result(1),
        invoke("Lcom/x/Y;->use([B)V", 1, kind="static"),
    )
    assert list(iter_calls(m))[1].arg(0) is None


def test_fill_array_marks_constant_array() -> None:
    m = method(CLS, "f", fill_array(2), invoke("Lcom/x/Y;->use([B)V", 2, kind="static"))
    assert next(iter_calls(m)).arg(0) == BytesConst("array literal")


def test_returns_constant() -> None:
    assert returns_constant(method(CLS, "v", const(0, 1), ret(0)), 1)
    assert not returns_constant(method(CLS, "v", const(0, 0), ret(0)), 1)
    assert not returns_constant(
        method(CLS, "v", invoke("Lx;->y()Z", kind="static"), move_result(0), ret(0)), 1
    )
    assert not returns_constant(method(CLS, "v"), 1)


def test_is_empty_body() -> None:
    assert is_empty_body(method(CLS, "m", ret_void()))
    assert is_empty_body(method(CLS, "m", Instruction("nop"), ret_void()))
    assert not is_empty_body(method(CLS, "m", invoke("Lx;->y()V", kind="static"), ret_void()))
