# Feynman Project Explainer Template

Use this template when a local agent produces or reviews a research/code project
that contains physics, algorithms, experiments, metrics, paper claims, or
concepts the user may need to understand deeply. Write in Chinese by default
unless the user asks otherwise.

The goal is not to impress. The goal is that the user can explain the project
back in simple words.

## File Name

Use one of these paths:

```text
PROJECT_FEYNMAN_EXPLAINER.md
docs/PROJECT_FEYNMAN_EXPLAINER.md
项目讲明白 · <project-or-topic>.md
```

## Required Structure

```markdown
# 项目讲明白：<项目名>

## 30 秒版本

用三到五句话说明：

1. 这个项目想解决什么问题。
2. 为什么这个问题重要。
3. 现在的方法或实验做到哪一步。
4. 最关键的证据是什么。
5. 下一步最应该验证什么。

## 一句话主线

如果只能记住一句话，这个项目是在：

> <一句话，不超过 40 个汉字。>

## 最简单的图景

不用术语，像给聪明的高中生讲一样说明：

- 研究对象是什么。
- 输入是什么。
- 输出是什么。
- 中间发生了什么。
- 为什么普通方法不够。

## 日常类比

给一个贴近生活的类比。类比要说明相似点和不相似点，避免让类比变成误导。

## 物理概念卡

每个重要物理概念都按这个格式写：

### <物理概念名>

- 简单解释：
- 它在这个项目里对应什么：
- 最小数学/符号版本：
- 它影响哪个实验或模型设计：
- 常见误解：
- 我还不确定的地方：

## 算法概念卡

每个重要算法概念都按这个格式写：

### <算法概念名>

- 简单解释：
- 输入是什么：
- 输出是什么：
- 它比基线多做了什么：
- 它可能失败在哪里：
- 怎么从实验结果看它有没有用：

## 项目地图

把项目拆成几块：

| 模块 | 它负责什么 | 关键文件/笔记 | 当前状态 |
| --- | --- | --- | --- |
| 论文叙事 |  |  |  |
| 数据/本体 |  |  |  |
| 算法/模型 |  |  |  |
| 实验/证据 |  |  |  |
| 后续计划 |  |  |  |

## 证据边界

明确区分：

- 已经被代码、实验、数据、图表支持的结论：
- 只是合理猜想、设计意图或待验证方向：
- 明确失败或负结果：
- 不能从当前材料推出的东西：

## 费曼缺口清单

这些地方如果讲不清，说明还没有真的懂：

| 缺口 | 我现在的说法 | 为什么还不够清楚 | 下一步怎么补 |
| --- | --- | --- | --- |
|  |  |  |  |

## 从零复述

用更顺的一段话重新讲一遍整个项目。要求：

- 先讲直觉，再讲术语。
- 先讲问题，再讲方法。
- 先讲证据，再讲野心。
- 不要把实验结果和未来愿景混在一起。

## 一个检查问题

最后给用户一个问题，用来确认 TA 是否真的抓住了主线：

> <一个具体、可回答的问题。>
```

## Agent Instructions

When creating this file:

- Read actual project files before explaining.
- Do not fabricate metrics, paper claims, or implementation status.
- Preserve evidence boundaries.
- Prefer one clear mental model over many clever metaphors.
- Define jargon immediately after first use.
- Keep formulas minimal and explain what each symbol means.
- Include negative results if they shape the project direction.
- End with one focused check question, not a quiz list.
