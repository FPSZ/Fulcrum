"""AgentDojo × Fulcrum —— 把枢衡检测器作为 defense 插入公认基准 AgentDojo(NeurIPS'24),
量化"接枢衡后 agent ASR 降多少"。

AgentDojo 的攻击把恶意指令注入**工具返回数据**(间接注入);枢衡作为**数据层输入筛查**——
每条工具输出过我们真实的 `keyword_rules` 检测,命中即判为注入并按 PI-detector 协议剥离/中止。
工具无关(不依赖具体工具名),正好检验枢衡的检测引擎在标准基准上的防护力。

跑在 agentdojo venv;经 fulcrum src 上 sys.path 复用真检测器(跨 venv import,纯 py+pydantic)。
需先起 local_model_proxy(把 MiMo 接成 localhost 后端):
  1) <项目 venv> python samples/eval/benchmarks/local_model_proxy.py 8123
  2) LOCAL_LLM_PORT=8123 <agentdojo venv python> \
       samples/eval/benchmarks/agentdojo_fulcrum.py [suite] [n_user_tasks]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, r"D:\WUYI\Proj\Fulcrum\src")

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig  # noqa: E402
from agentdojo.agent_pipeline.pi_detector import PromptInjectionDetector  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.benchmark import benchmark_suite_with_injections  # noqa: E402
from agentdojo.logging import OutputLogger  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from fulcrum.capabilities.detectors.keyword_rules import KeywordRuleDetector  # noqa: E402
from fulcrum.capabilities.detectors.llm_judge import LlmJudgeDetector  # noqa: E402
from fulcrum.core.domain import Context, SourceSpan, SourceType, TrustLevel  # noqa: E402

_DET = KeywordRuleDetector()
_CTX = Context(session_id="agentdojo-defense")
_THRESHOLD = 0.5  # 工具输出 finding 最大分 ≥ 此值 → 判为注入(与输入闸门 REVIEW_AT 同档)
_VERSION = "v1.2"
# LLM-judge 经 local_model_proxy(LOCAL_LLM_PORT)→ MiMo 关思考;语义/语言通用,补规则在英文
# 隐蔽注入(如 important_instructions)上的盲区(实测 keyword_rules 漏、judge 抓)。
_PORT = os.environ.get("LOCAL_LLM_PORT", "8123")
_JUDGE = LlmJudgeDetector(endpoint=f"http://localhost:{_PORT}/v1", api_key="proxy", model="mimo")


class FulcrumPIDetector(PromptInjectionDetector):
    """枢衡 PI 检测器:工具输出先过 keyword_rules(快)再过 LLM-judge(语义,通用),任一命中即剥离。"""

    def detect(self, tool_output: str) -> tuple[bool, float]:
        sp = SourceSpan(
            source_type=SourceType.TOOL_RETURN,
            trust_level=TrustLevel.UNTRUSTED,
            content_hash="x",
            excerpt=tool_output,
        )
        score = max((f.score for f in _DET.detect([sp], _CTX)), default=0.0)
        if score >= _THRESHOLD:
            return True, score
        jf = _JUDGE.detect([sp], _CTX)  # 语义层:抓无触发词的社工注入
        if jf:
            return True, max(f.score for f in jf)
        return False, score


def _build(defense: str | None) -> AgentPipeline:
    pipe = AgentPipeline.from_config(
        PipelineConfig(
            llm="vllm_parsed",
            model_id=None,
            defense=None,
            system_message_name=None,
            system_message=None,
            tool_output_format="json",
        )
    )
    if defense == "fulcrum":
        loop = pipe.elements[-1]  # ToolsExecutionLoop([ToolsExecutor, llm])
        loop.elements.insert(-1, FulcrumPIDetector(mode="message"))  # 置于工具执行后、llm 前
        pipe.name = f"{pipe.name}-fulcrum-judge"  # 独立缓存键(区别于 keyword_rules 版)
    return pipe


def _run(suite, attack: str, defense: str | None, user_tasks):
    pipe = _build(defense)
    attacker = load_attack(attack, suite, pipe)
    logdir = Path(r"D:\AI\agentdojo\runs")
    with OutputLogger(str(logdir), live=None):
        res = benchmark_suite_with_injections(
            pipe, suite, attacker, user_tasks=user_tasks, injection_tasks=None,
            logdir=logdir, force_rerun=False, benchmark_version=_VERSION,
        )
    util = res["utility_results"].values()
    sec = res["security_results"].values()
    avg_util = sum(util) / len(util)
    asr = 1 - sum(sec) / len(sec)  # security=未被攻破率 → ASR=1-security
    return avg_util, asr, len(sec)


def main() -> int:
    suite_name = sys.argv[1] if len(sys.argv) > 1 else "banking"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 0  # 0=全套
    attack = "important_instructions"
    suite = get_suite(_VERSION, suite_name)
    all_ut = list(suite.user_tasks.keys())
    user_tasks = all_ut[:n] if n > 0 else None
    print(f"AgentDojo {suite_name} · 攻击={attack} · 用户任务={n or '全部'} · 注入×用户组合对照\n")

    bu, ba, npairs = _run(suite, attack, None, user_tasks)
    print(f"[裸基线]   utility={bu * 100:5.1f}%   ASR={ba * 100:5.1f}%   ({npairs} 组合)")
    fu, fa, _ = _run(suite, attack, "fulcrum", user_tasks)
    print(f"[接枢衡]   utility={fu * 100:5.1f}%   ASR={fa * 100:5.1f}%")
    print(
        f"\nASR {ba * 100:.1f}% → {fa * 100:.1f}%  "
        f"(降 {(ba - fa) * 100:.1f} 点);utility 保 {fu * 100:.1f}%"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
