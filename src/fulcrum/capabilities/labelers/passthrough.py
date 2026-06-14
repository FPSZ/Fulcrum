"""PassthroughLabeler —— M0 桩:把每条消息标成一个 SourceSpan。

约定(可在 M1 细化):user 角色记为 TRUSTED,其余记为 UNTRUSTED;
请求自带的 sources 原样并入。
"""

from __future__ import annotations

import hashlib

from ...core.domain import ModelRequest, SourceSpan, SourceType, TrustLevel
from ...core.registry import capability


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@capability("labeler", "passthrough")
class PassthroughLabeler:
    def label(self, req: ModelRequest) -> list[SourceSpan]:
        spans: list[SourceSpan] = list(req.sources)
        for msg in req.messages:
            is_user = msg.role == "user"
            spans.append(
                SourceSpan(
                    source_type=SourceType.USER if is_user else SourceType.TOOL_RETURN,
                    trust_level=TrustLevel.TRUSTED if is_user else TrustLevel.UNTRUSTED,
                    content_hash=_hash(msg.content),
                    excerpt=msg.content[:200],
                )
            )
        return spans
