# detectors —— 输入风险检测能力

实现 `fulcrum.core.ports.Detector` 协议:

```python
class Detector(Protocol):
    name: str
    def detect(self, spans: list[SourceSpan], ctx: Context) -> list[Finding]: ...
```

## 如何新增一个检测器

1. 在本目录新建 `my_detector.py`,写一个类实现 `detect()`;
2. 加装饰器注册:`@capability("detector", "my_detector")`;
3. 在 `src/fulcrum/capabilities/__init__.py` 补一行 `from .detectors import my_detector`;
4. 在 `src/fulcrum/config/fulcrum.yml` 的 `detectors:` 列表加 `"my_detector"`;
5. 在 `tests/capabilities/detectors/` 加单测。

**不需要**改 `core/`、不需要改 `pipeline.py`、不需要改别人的代码。

参考示例:`keyword_rules.py`(确定性关键词规则)。桩示例:`noop.py`。
