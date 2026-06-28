"""InjectionCascadeDetector —— 级联:确定性规则先出分,规则已拦的不重判,其余落 LLM-judge。

**为什么级联**:LLM-judge 补召回有效(整机 78.8%→94.1%、0 FPR 不破),但每条 ~0.8s(本地 8B)。
规则已经强命中(≥gray_high,必被复核/拦)的 span **没必要再判**——级联跳过这些,只对规则"没拦下"
的 span 调 judge:

  · `max_kw ≥ gray_high` —— 规则已足以拦/复核 → 结果已定,**不调 judge**(无召回损失)。
  · `gray_low ≤ max_kw < gray_high` —— 规则没拦下 → 落 judge 语义研判,融合分数。
  · `max_kw < gray_low` —— 低于下界直接放行,**不调 judge**(见下"实测警告")。

**实测警告(冻结语料 v1.0.0)**:本检测器的 keyword 分数是**二极的**——要么 ≥0.6(强命中)、要么
**恰为 0**(完全无信号);几乎没有中间灰区。规则漏网的 35 条攻击 keyword 分**全为 0**,与良性同档,
**无任何分数阈值能把二者分开**。故:
  · `gray_low=0.0`(默认)= "判所有未被规则拦下的 span":召回 94.1%、但 judge 落在 ~50% 输入上,
    P95 ≈ judge 单条延迟(本地 8B ~575ms)。**与 full 同召回同 P95,但 judge 调用量减半**(规则已拦的
    不重判)——省一半算力,尾延迟不变。
  · `gray_low>0`(如 0.2)对当前二极分数**几乎无召回增益**(漏网攻击全在 0 档、被快放),仅当未来
    检测器产出**分级分数**时才有意义。
要把 P95 压到 ~0.7ms 又保召回,得走**异步旁路**(judge 移出关键路径,裁决喂下游工具/出口闸门)或
**更快的 judge 模型**,而非调 gray_low。见 plan/14。

**fail-safe**:judge 端点不可达/异常 → 自动降级为纯 `keyword_rules`,**绝不 fail-open、也绝不
因 judge 故障反而拦一切**(降级语义沿用 `llm_judge`)。组合的是 `keyword_rules` + `llm_judge`
两个对等能力(capabilities 可依赖 capabilities,只是不依赖 adapters/app),口径与单独装配完全一致。

装配:把 `injection_cascade` 放进某区域(闸门)的 detectors,`options.injection_cascade` 配
`gray_low`/`gray_high` 与 `judge`(=LlmJudgeDetector 构造参数 dict:endpoint/model/api_key/
extra_body)。该区域**不要**再单列 `keyword_rules`——级联已内含,避免重复跑。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ...core.domain import Context, Finding, SourceSpan
from ...core.registry import capability
from .keyword_rules import KeywordRuleDetector
from .llm_judge import LlmJudgeDetector

if TYPE_CHECKING:
    from ...core.ports import Detector


@capability("detector", "injection_cascade")
class InjectionCascadeDetector:
    """灰区级联检测器:keyword_rules(快路径)+ llm_judge(灰区兜底)。注册名 `injection_cascade`。

    可注入 fast / judge 实例以便确定性测试;省略则按配置惰性构建(judge 端点经 `judge` dict 注入)。
    """

    name = "injection_cascade"

    def __init__(
        self,
        gray_low: float = 0.0,
        gray_high: float = 0.6,
        judge: dict[str, Any] | None = None,
        *,
        fast: Detector | None = None,
        judge_detector: Detector | None = None,
    ) -> None:
        self._fast = fast or KeywordRuleDetector()
        self._judge = judge_detector or LlmJudgeDetector(**(judge or {}))
        self._gray_low = float(gray_low)
        self._gray_high = float(gray_high)
        # 观测(评测算延迟占比用,不入 Finding):本实例累计 span 数 / 实际落 judge 的 span 数。
        self.span_count = 0
        self.judged_count = 0

    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        for span in spans:
            self.span_count += 1
            kw = self._fast.detect([span], ctx)
            findings.extend(kw)
            max_kw = max((f.score for f in kw), default=0.0)
            # 规则未拦下(< gray_high)且不低于下界 → 落 judge;规则已强命中的(≥ gray_high)跳过不重判。
            if self._gray_low <= max_kw < self._gray_high:
                self.judged_count += 1
                findings.extend(self._judge.detect([span], ctx))
        return findings
