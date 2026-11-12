# C2Trace

C2Trace 根据网络告警调查 Windows 主机，通过领域规划指导、共享 CaseFile、独立审核与受约束执行完成响应，并在执行后验证主机状态。

## 实验数据

| 实验 | 次数 | 内容 |
|---|---:|---|
| RQ1 | 8 | 八个场景的效果实验 |
| RQ2 在线基线 | 48 | C2Trace 与 Public ReAct，每场景每系统重复三次 |
| RQ2 离线基线 | 8 | 固定输入下的调查发现和动作提案 |
| RQ3 | 96 | 完整系统及三个变体，每场景每配置重复三次 |

RQ3 采用论文编号：A1 对应原 B1，移除领域知识及专用规划指导；A2 对应原 B4，关闭调查阶段的命令行载荷路径提取；A3 对应原 B3，移除独立证据审核并保留执行防护。完整系统独立保留24次试验。原始记录的运行编号保持不变，编号对应关系见数据清单。A2 为后续批次，四次首次请求传输失败仍计入24次试验。

## 离线复核

```shell
python scripts/extract_artifacts.py
python scripts/recompute_results.py
python scripts/rescore_rq3.py
```

需要 Python 3.11 或更新版本；解压脚本自动合并分卷并核对校验值，命令不调用模型、不连接实验主机。结果位于 `results/recomputed/`，包含逐次、逐场景及汇总结果。未定义指标保留为空。离线 LLM 采用已纠正的输出适配评分，Trace F1 为0.730，Action F1为0.444；原始模型输出保持不变。

## 代码与论文

主程序在 `src/c2trace/`，入口为 `run_case.py`。通用领域知识和提示位于 `kb/` 与 `prompts/`。解压后，`variants/rq3_core/` 提供完整系统、A1和A3的源代码，`variants/rq3_payload/` 提供A2的源代码。通过 `python scripts/run_ablation.py --variant A1 --help` 查看论文编号入口。

`paper/` 包含本地提供的论文源文件及其引用图片。运行和安装说明见英文 [README](README.md)，验证结果见 [TESTING.md](TESTING.md)。
