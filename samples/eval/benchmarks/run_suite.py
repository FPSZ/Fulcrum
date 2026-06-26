"""枢衡 · 一键回归测试台 —— 选「模型 × 测试套件」组合,子进程隔离跑,汇总矩阵。

改了检测器/策略/judge/样例后,一条命令回归多模型多套件,随时验证有没有掉点。
模型注册见 bench_backends.py(本地 llama-server / MiMo / DeepSeek);套件见下方 SUITES。

用法:
  # 跑所有可用模型 × 所有结构化套件(本地模型自启 llama-server):
  uv run python samples/eval/benchmarks/run_suite.py --models all --suites all --serve
  # 只测本地 8B 的 redteam + judge(假设 llama-server 已在 8123):
  uv run python samples/eval/benchmarks/run_suite.py --models qwen3-8b --suites redteam,judge
  # 只测 MiMo 的 judge(读 .env):
  uv run python samples/eval/benchmarks/run_suite.py --models mimo --suites judge

选项:--models(逗号分隔 / all)、--suites(逗号分隔 / all)、--trials N、
      --serve(本地模型自启/停 llama-server)、--list(列出可选模型与套件)。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "samples/eval/benchmarks")
import bench_backends as B  # noqa: E402

_ROOT = os.getcwd()  # 仓库根(uv run 的 cwd);子进程脚本按相对路径读 src/ 与 corpus/

# 套件登记:structured=能输出 ##RESULT## 机读行(进矩阵);否则只回显(如 realistic 表)。
SUITES: dict[str, dict] = {
    "redteam": {
        "script": "samples/eval/benchmarks/gov_agentic_redteam.py",
        "env": {"GOV_DEFENSE": "both"}, "structured": True, "use_trials": True,
        "desc": "18 场景 agentic ASR + 接枢衡拦截 + judge/闸门双误报",
    },
    "judge": {
        "script": "samples/eval/benchmarks/llm_judge_bench.py",
        "env": {}, "structured": True, "use_trials": False,
        "desc": "LLM-judge 语义层 召回/FPR(冻结语料输入子集)",
    },
    "realistic": {
        "script": "samples/eval/benchmarks/gov_agentic_realistic.py",
        "env": {"GOV_ATTACK": "crescendo", "GOV_SAFETY": "strict"},
        "structured": False, "use_trials": True,
        "desc": "厚 agent · crescendo 多轮 vs 单发(strict 档,回显)",
    },
}


def _http_ok(url: str, headers: dict | None = None, timeout: float = 6.0) -> bool:
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 500  # 401/404 也算"通"(端点在,只是鉴权/路径)
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def _reachable(env: dict[str, str]) -> bool:
    base = env["LLM_BASE"].rstrip("/")
    if "127.0.0.1" in base or "localhost" in base:
        return _http_ok(base.rsplit("/v1", 1)[0] + "/health")
    key = env.get("LLM_API_KEY", "")
    return _http_ok(base + "/models", {"Authorization": f"Bearer {key}"} if key else None)


def _start_llama(name: str) -> subprocess.Popen | None:
    """自启 llama-server 服务该本地模型(关思考默认),返回进程;失败返回 None。"""
    path = B.gguf(name)
    if not path or not os.path.exists(B.LLAMA_EXE) or not os.path.exists(path):
        print(f"  [serve] 跳过自启({name}):缺 exe 或 gguf,请确认 BENCH_LLAMA_EXE / 模型路径")
        return None
    _kill_llama()
    env = {**os.environ, "LLAMA_CHAT_TEMPLATE_KWARGS": '{"enable_thinking":false}'}
    proc = subprocess.Popen(
        [B.LLAMA_EXE, "-m", path, "--host", "127.0.0.1", "--port", B.LOCAL_PORT,
         "--jinja", "-ngl", "99", "-c", "8192", "--no-webui", "--alias", name],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    health = B.LOCAL_BASE.rsplit("/v1", 1)[0] + "/health"
    for _ in range(60):
        if _http_ok(health, timeout=3):
            print(f"  [serve] {name} 就绪")
            return proc
        if proc.poll() is not None:
            print(f"  [serve] {name} 启动失败(进程退出)")
            return None
        time.sleep(3)
    print(f"  [serve] {name} 启动超时")
    proc.terminate()
    return None


def _kill_llama() -> None:
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/IM", "llama-server.exe"],
                       capture_output=True, check=False)
    else:
        subprocess.run(["pkill", "-f", "llama-server"], capture_output=True, check=False)


def _run_suite(suite: str, model_env: dict[str, str], trials: int) -> dict | None:
    spec = SUITES[suite]
    env = {**os.environ, **model_env, **spec["env"]}
    if spec["use_trials"]:
        env["GOV_TRIALS"] = str(trials)
    print(f"  ▸ {suite} …", flush=True)
    proc = subprocess.run(
        [sys.executable, spec["script"]], env=env, cwd=_ROOT,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        print(f"    [失败 rc={proc.returncode}] {(proc.stderr or '').strip()[-300:]}")
        return None
    if not spec["structured"]:
        for line in (proc.stdout or "").splitlines():
            if line.strip():
                print("    " + line)
        return None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("##RESULT## "):
            return json.loads(line[len("##RESULT## "):])
    print("    [无 ##RESULT## 行] " + (proc.stdout or "")[-200:])
    return None


def _pct(x) -> str:
    return f"{x * 100:.1f}%" if isinstance(x, (int, float)) else "—"


def _print_matrix(results: dict[tuple[str, str], dict]) -> None:
    print("\n" + "=" * 72 + "\n汇总矩阵\n" + "=" * 72)
    rt = {m: r for (m, s), r in results.items() if s == "redteam"}
    if rt:
        print("\n[redteam] ASR 口径(全表越低越好):模型自身 ASR → 接枢衡 ASR · 末两列误报率")
        print(f"{'模型':<12}{'自身ASR':>9}{'leak':>8}{'escalate':>10}"
              f"{'接枢衡ASR':>11}{'judge误报':>10}{'闸门误报':>9}")
        for m, r in rt.items():
            print(f"{m:<12}{_pct(r['asr']):>9}{_pct(r['leak_asr']):>8}{_pct(r['escalate_asr']):>10}"
                  f"{_pct(r['gateway_asr']):>11}{_pct(r['judge_fpr']):>10}{_pct(r['gate_fpr']):>9}")
    jd = {m: r for (m, s), r in results.items() if s == "judge"}
    if jd:
        print("\n[judge] LLM-judge 语义层 召回/FPR(规则+judge 融合)")
        print(f"{'模型':<12}{'judge召回':>10}{'judgeFPR':>10}{'融合召回':>10}{'融合FPR':>9}{'s/条':>7}")
        for m, r in jd.items():
            print(f"{m:<12}{_pct(r['judge_recall']):>10}{_pct(r['judge_fpr']):>10}"
                  f"{_pct(r['fused_recall']):>10}{_pct(r['fused_fpr']):>9}{r['sec_per_item']:>7}")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description="枢衡一键回归测试台")
    ap.add_argument("--models", default="qwen3-8b", help="逗号分隔 / all(默认 qwen3-8b)")
    ap.add_argument("--suites", default="redteam,judge", help="逗号分隔 / all")
    ap.add_argument("--trials", type=int, default=2, help="agentic 套件聚合轮数(默认 2)")
    ap.add_argument("--serve", action="store_true", help="本地模型自启/停 llama-server")
    ap.add_argument("--list", action="store_true", help="列出可选模型与套件后退出")
    a = ap.parse_args()

    if a.list:
        print("模型:", ", ".join(B.ALL_MODELS))
        print("套件:")
        for k, v in SUITES.items():
            print(f"  {k:<10} {v['desc']}")
        return 0

    models = B.ALL_MODELS if a.models == "all" else [m.strip() for m in a.models.split(",")]
    suites = list(SUITES) if a.suites == "all" else [s.strip() for s in a.suites.split(",")]
    bad = [s for s in suites if s not in SUITES]
    if bad:
        print(f"未知套件:{bad};可选 {list(SUITES)}")
        return 2

    print(f"测试台 · 模型={models} · 套件={suites} · trials={a.trials} · serve={a.serve}")
    results: dict[tuple[str, str], dict] = {}
    served: subprocess.Popen | None = None
    try:
        for model in models:
            env = B.env_for(model)
            if env is None:
                print(f"\n■ {model}:跳过 —— {B.skip_reason(model)}")
                continue
            print(f"\n■ {model}  ({env['LLM_BASE']})")
            if B.is_local(model):
                if a.serve:
                    served = _start_llama(model)
                    if served is None:
                        continue
                elif not _reachable(env):
                    print(f"  本地端点不可达;先起 llama-server(或加 --serve)。跳过 {model}")
                    continue
            elif not _reachable(env):
                print(f"  云端点不可达/鉴权失败,跳过 {model}")
                continue
            for suite in suites:
                r = _run_suite(suite, env, a.trials)
                if r is not None:
                    results[(model, suite)] = r
            if served is not None:
                served.terminate()
                served = None
    finally:
        if served is not None:
            served.terminate()
        if a.serve:
            _kill_llama()

    if results:
        _print_matrix(results)
    else:
        print("\n(无结构化结果;structured 套件未产出或全部跳过)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
