"""出站模型适配器:把模型返回的 function tool_calls 安全映射回领域 ToolCall。

重点守住「畸形模型输出不破坏安全管线」——参数恒收敛为 dict,函数名映射到内部工具名。
"""

from __future__ import annotations

from fulcrum.adapters.model.openai_client import OpenAICompatModelClient, _parse_args


def _to_response(data: dict):
    return OpenAICompatModelClient._to_response("req-1", data)


def _with_args(arguments) -> dict:
    return {
        "choices": [
            {
                "message": {
                    "tool_calls": [{"function": {"name": "file_read", "arguments": arguments}}]
                }
            }
        ]
    }


# ---- _parse_args:参数恒为 dict ----
def test_parse_valid_object() -> None:
    assert _parse_args('{"path": "a.txt"}') == {"path": "a.txt"}


def test_parse_malformed_json_falls_back_to_raw() -> None:
    assert _parse_args("{not valid") == {"_raw": "{not valid"}


def test_parse_non_object_json_falls_back_to_raw() -> None:
    # 合法 JSON 但不是对象(数组 / 标量 / null)→ 收敛为 _raw,不让下游拿到非 dict。
    assert _parse_args("[1, 2, 3]") == {"_raw": "[1, 2, 3]"}
    assert _parse_args("42") == {"_raw": "42"}
    assert _parse_args('"hi"') == {"_raw": '"hi"'}
    assert _parse_args("null") == {"_raw": "null"}


def test_parse_empty_or_missing() -> None:
    assert _parse_args("") == {}
    assert _parse_args(None) == {}


def test_parse_already_dict_passthrough() -> None:
    assert _parse_args({"url": "http://x"}) == {"url": "http://x"}


# ---- _to_response:端到端映射 ----
def test_function_name_mapped_to_internal_tool() -> None:
    resp = _to_response(_with_args('{"path": "notice.txt"}'))
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].tool_name == "file.read"
    assert resp.tool_calls[0].arguments == {"path": "notice.txt"}


def test_non_object_args_do_not_crash_mapping() -> None:
    """模型给数组作 arguments → 仍产出可被闸门检测的 ToolCall,不抛错绕过管线。"""
    resp = _to_response(_with_args('["rm -rf /"]'))
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].arguments == {"_raw": '["rm -rf /"]'}


def test_no_tool_calls_yields_content_only() -> None:
    resp = _to_response({"choices": [{"message": {"content": "你好"}}]})
    assert resp.tool_calls == []
    assert resp.content == "你好"
