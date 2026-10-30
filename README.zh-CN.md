# C2Trace 初稿复现包

本包对应旧8案初稿，以及2026年10月15日更新后的基线数据。包含系统源码、案例静态定义、已选定实验记录、消融变体源码和完整 LaTeX 稿件；不包含后续新增案例与双基线开发工作。

**查看系统实现：**从 `run_case.py`、`src/c2trace/agents/`、`src/c2trace/orchestrator.py`、`src/c2trace/mcp/` 开始。知识库实现在 `kb.py`，历史经验实现在 `experience.py`；本次实验未开启历史经验读写，不能声称它带来实验收益。

**查看论文：**`paper/main.tex` 是完整主稿。将 `paper` 内的文件和子文件夹上传到 Overleaf，选择 pdfLaTeX。未修改当前论文内容，也未将后续绘图草稿替换进来。

**查看和复算数据：**在仓库根目录执行：

```shell
python scripts/extract_artifacts.py
python scripts/recompute_results.py
```

解压后，`data/effect` 为8条效果记录，`data/baseline` 为48条基线记录，`data/ablation` 为32条消融记录，`data/llm_direct` 为8条单次推理记录。总计96条记录，不是96个独立场景。耗时、调用数和 Token 来自这些记录。

复算结果在 `results/recomputed`：每条记录和每个案例的 TP、FP、FN、Precision、Recall、F1，以及时间和 Token 均可查阅。`null` 表示该指标在对应条件下未定义或没有记录，不能改成0。基线复算采用最终选定的v5数据，保留有效实验中的失败结果；消融仍按描述性 smoke 实验解释。

数据中的密钥、认证字段和个人用户目录经过脱敏。为保持实验事实可追踪，保留实验用 IP、PID、路径主体、文件哈希和数值记录。原记录中的历史摘要不代表脱敏后文件的摘要，发布包校验请使用新的清单。

本包提供离线数据复算和源代码检查。重新在虚拟机运行实验仍需安装外部工具、配置自己的密钥并采集当前对象身份；不包含虚拟机镜像、第三方植入体二进制或现成凭据。源码与每次历史运行完全一致的保证超出了已留存证据，具体版本检查见 `data/source_version_checks.json`。

完整安装、测试与实验边界见 [README.md](README.md)。
