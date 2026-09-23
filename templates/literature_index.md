# Project Literature Index Template

Use this template as the reusable literature cache for a single project. Write
in Chinese by default unless the project is English-only. Keep evidence and
background literature separate.

Recommended path:

```text
docs/literature/LITERATURE_INDEX.md
```

Fallback paths:

```text
literature/LITERATURE_INDEX.md
docs/LITERATURE_INDEX.md
LITERATURE_INDEX.md
```

## Required Structure

```markdown
# 文献索引：<项目名>

## 元数据

- project_root:
- created:
- last_updated:
- owner_agent:
- literature_state: reuse | index-local | collect-new | stale
- query_fingerprint:
- covered_questions:
  - 
- not_covered_questions:
  - 

## 本地文献盘点

| 类型 | 相对路径 | 数量/状态 | 备注 |
| --- | --- | --- | --- |
| PDF |  |  |  |
| BibTeX/RIS |  |  |  |
| 论文笔记 |  |  |  |
| Related-work 文档 |  |  |  |
| 项目证据文件 |  |  |  |

## 检索记录

只在真正需要外部检索时填写；同一个项目后续复用这里，不要重复搜。

| 日期 | 工具/来源 | Query | 目的 | 结果数量 | 纳入数量 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |  |

## 已纳入文献

| ID | 标题 | 作者/年份 | venue/source | DOI/arXiv/URL | 本地路径 | 为什么纳入 |
| --- | --- | --- | --- | --- | --- | --- |
| P001 |  |  |  |  |  |  |

## 文献逻辑图

把文献按研究逻辑分组，而不是只按时间堆列表：

| 方向/问题 | 代表文献 | 共同假设 | 常用指标 | 本项目可借鉴什么 | 本项目如何改进 |
| --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |

## 和本项目的关系

### 支撑背景的文献

- 

### 竞争或相邻工作的文献

- 

### 可借鉴方法/指标的文献

- 

### 不能直接支撑本项目结论的文献

- 

## 项目证据边界

这些是本项目自己的证据，不要和外部文献混淆：

| 证据文件/实验 | 支持什么结论 | 不能支持什么 |
| --- | --- | --- |
|  |  |  |

## 缺口与更新条件

只有满足这些条件才重新检索：

- 当前问题不在 `covered_questions` 里。
- 用户明确要求最新/最近三年/某个新方向。
- 关键 claim 没有任何文献支撑。
- index 中的来源只有泛综述，没有关键原始论文。
- 外部审稿/写作需要更严格 venue/年份/指标对照。

下一次需要检索的具体问题：

1. 
2. 
3. 

## Agent 复用说明

- 后续 agent 先读本文件。
- 如果 `literature_state=reuse`，不要外部检索。
- 如果要新增文献，追加到 `检索记录` 和 `已纳入文献`，不要覆盖旧内容。
- 每条文献必须写明为什么纳入。
- 每个项目结论必须标清是“外部文献背景”还是“本项目证据”。
```

## Agent Instructions

- Start with local inventory before web search.
- Prefer structured sources such as BibTeX/RIS, existing PDFs, prior notes, and
  project evidence maps.
- Do not duplicate an existing search unless the uncovered question is explicit.
- Record query strings and search date for every external search.
- Use relative paths for local files.
- Keep failed/irrelevant search results in notes if they explain why a route was
  not pursued.
