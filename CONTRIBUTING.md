# 贡献指南(CONTRIBUTING)

枢衡是团队项目。一句话规矩:**功能都长在 `src/fulcrum/capabilities/` 里,内核 `src/fulcrum/core/` 不要动。**

详细加功能配方见 [docs/arch/04-开发者指南.md](docs/arch/04-开发者指南.md);本文只讲最关键的"别动哪里、怎么加、怎么提"。

---

## 1. 准备环境

```powershell
uv sync --extra dev      # 装依赖(Python 3.11)
pre-commit install       # 提交前自动跑 ruff + 依赖检查
```

## 2. 别动哪里(禁区)

| 禁区 | 为什么 |
|---|---|
| `src/fulcrum/core/**` | 域类型、接口、注册表、管线——动它等于改地基,属架构变更 |
| `src/fulcrum/app.py` | 组装根,架构负责人维护 |
| `pyproject.toml` 的 import-linter 契约 | 依赖方向铁律,改了等于拆地基 |

> 确实需要改内核/接口?**先找架构负责人评审**,不要自己改。CI 也会拦反向依赖。

## 3. 怎么加功能(三步)

1. **实现**:在 `src/fulcrum/capabilities/<类型>/` 新建文件,写一个类实现对应接口;
2. **注册**:类上加 `@capability("<类型>", "<名字>")`,并在 `src/fulcrum/capabilities/__init__.py` 的 `load_builtin_capabilities()` 里加一行 import;
3. **启用**:在 `src/fulcrum/config/fulcrum.yml` 按名字启用。

加测试放 `tests/`。完整示例(加一个检测器)见 [开发者指南](docs/arch/04-开发者指南.md#2-完整示例加一个检测器)。

## 4. 提交前必须全绿

```powershell
uv run pytest -q
uv run ruff check src tests
uv run ruff format src tests
uv run lint-imports
```

## 5. 分支与提交

- 从 `dev` 切功能分支:`feat/你的功能`、`docs/xxx`、`fix/xxx`;完成后合回 `dev`。
- **提交信息用详细中文**,格式 `<类型>: <简述>` + 正文说清"做了什么、为什么"。类型与示例见 [AGENTS.md](AGENTS.md#8-git-规范)。
- 不提交:密钥、真实数据、未脱敏样例、大文件、运行期产物(见 `.gitignore`)。

## 6. 一句话自检

> 我只改了 `capabilities/` 和 `config/`、加了测试、本地四项全绿、提交信息写清楚了——就可以提 PR。
