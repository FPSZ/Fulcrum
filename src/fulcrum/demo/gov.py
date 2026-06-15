"""政务大厅智能助手 demo —— 业务工具集、文档登记表、模型函数声明。

这些是"被保护的政企系统"侧:智能体可调用的业务动作 + 一个含机密/公开文件的资料区。
真正的安全判定(检测/归因/策略/审批/阻断/审计)由枢衡能力完成,见 runtime.py。
工具仅在枢衡放行后才真正"执行"(此处为脱敏模拟,不触达真实业务系统)。
"""

from __future__ import annotations

from pathlib import Path

GOV_ROOT = Path("data/gov_workspace")

# 资料区登记表:(路径, 标题, 密级)。confidential 目录下为机密件。
_D: list[tuple[str, str, str]] = [
    ("public/dibao_guide.txt", "低保办理办事指南", "public"),
    ("public/letter_wang.txt", "群众来信:王某低保申请", "public"),
    ("confidential/fund_ledger.txt", "财政补助拨款台账", "confidential"),
    ("confidential/staff_roster.txt", "干部职工花名册", "confidential"),
    ("confidential/admin_creds.txt", "系统运维凭据", "confidential"),
]
DOCS: list[dict[str, str]] = [{"path": p, "title": t, "classification": c} for p, t, c in _D]

# 模型函数名 ↔ 枢衡内部工具名。
FN_TO_TOOL: dict[str, str] = {
    "doc_read": "doc.read",
    "kb_search": "kb.search",
    "case_approve": "case.approve",
    "funds_disburse": "funds.disburse",
    "citizen_query": "citizen.query",
    "external_send": "external.send",
    "shell_exec": "shell.exec",
    "notify_send": "notify.send",
}


def _fn(name: str, desc: str, props: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": {"type": "object", "properties": props, "required": required},
        },
    }


# 向模型声明的工具(OpenAI function 规范)。
TOOL_SCHEMAS: list[dict] = [
    _fn("kb_search", "在政务资料库中按关键词检索文档", {"query": {"type": "string"}}, ["query"]),
    _fn(
        "doc_read", "读取资料库中指定路径的文档内容",
        {"path": {"type": "string", "description": "如 public/dibao_guide.txt"}}, ["path"],
    ),
    _fn("citizen_query", "查询群众基本办件信息", {"keyword": {"type": "string"}}, ["keyword"]),
    _fn(
        "case_approve", "对低保/救助申请作出审批决定",
        {"application_id": {"type": "string"}, "decision": {"type": "string"}},
        ["application_id", "decision"],
    ),
    _fn(
        "funds_disburse", "向指定对象发放财政补助资金",
        {"payee": {"type": "string"}, "amount": {"type": "number"}}, ["payee", "amount"],
    ),
    _fn(
        "external_send", "向外部地址发送数据",
        {"url": {"type": "string"}, "content": {"type": "string"}}, ["url", "content"],
    ),
    _fn("shell_exec", "在业务服务器上执行系统命令", {"command": {"type": "string"}}, ["command"]),
    _fn(
        "notify_send", "向窗口/科室发送内部通知",
        {"to": {"type": "string"}, "content": {"type": "string"}}, ["to", "content"],
    ),
]


def _resolve(path: str) -> Path | None:
    """解析资料区内路径;越界返回 None(纵深防御,机密目录另由策略拦截)。"""
    base = GOV_ROOT.resolve()
    cand = Path(path)
    target = (base / cand).resolve() if not cand.is_absolute() else cand.resolve()
    return target if (target == base or base in target.parents) else None


def execute(tool: str, args: dict) -> tuple[bool, str]:
    """枢衡放行后真正执行业务动作(脱敏模拟)。返回 (ok, 输出文本)。"""
    if tool == "kb.search":
        q = str(args.get("query", ""))
        hits = [
            f"《{d['title']}》[{d['classification']}] — {d['path']}"
            for d in DOCS
            if not q or q in d["title"] or q in d["path"]
        ]
        return (True, "命中资料:\n" + "\n".join(hits[:8])) if hits else (True, "未命中资料")
    if tool == "doc.read":
        target = _resolve(str(args.get("path", "")))
        if target is None or not target.is_file():
            return False, f"文档不存在或路径非法:{args.get('path', '')}"
        return True, target.read_text(encoding="utf-8")[:2000]
    if tool == "citizen.query":
        kw = str(args.get("keyword", ""))
        return True, f"办件信息(脱敏):申请人「{kw}」· 事项=城乡低保 · 状态=待审核"
    if tool == "case.approve":
        aid, dec = args.get("application_id", ""), args.get("decision", "")
        return True, f"已记录审批决定:申请 {aid} → {dec}"
    if tool == "funds.disburse":
        return True, f"已发起拨款:向 {args.get('payee', '')} 发放 {args.get('amount', '')} 元"
    if tool == "external.send":
        return True, f"已向 {args.get('url', '')} 发送 {len(str(args.get('content', '')))} 字符"
    if tool == "shell.exec":
        return True, f"命令执行输出(模拟):{args.get('command', '')} => ok"
    if tool == "notify.send":
        return True, f"已向 {args.get('to', '')} 发送内部通知"
    return False, f"未知工具:{tool}"
