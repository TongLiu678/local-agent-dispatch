# Skill 路由、自动进化与 Agent 调度控制面：研究与开源借鉴

> 证据快照：2026-09-22。论文事实只取自 arXiv 官方页面，项目事实只取自各项目的官方 GitHub 仓库。论文中的指标是作者报告值，尚未在本仓库复现。

## 结论

不应寻找一个项目整体照搬，而应把系统拆成两个相互独立、以版本化数据连接的平面：

```text
Skill 平面
可信包/清单 -> 离线索引 -> 候选召回 -> 3/5/10 组合 -> 依赖 DAG
                                              |
                                              v
控制平面
任务包 -> 策略/资源准入 -> worker/harness -> receipt/验证 -> outcome
                                                        |
                                                        v
                                     进化提案 -> 评测/审核 -> 激活或回滚
```

近期研究支持三点：skill 组合是“选哪些、选几个、按什么顺序”的联合问题；复杂任务的分解质量往往先于检索成为瓶颈；在大而高度重叠的库中，正文包含仅靠名称和描述无法恢复的路由信号。但正文也是不可信指令面，因此合理架构不是把整个 skill 库塞进上下文，而是“metadata-only 安全召回 + 可信候选上的隔离式 body-aware 重排 + 组合/顺序规划”。

## 论文：可借鉴与不可照搬

| 工作 | 官方证据与主要结果 | 可借鉴 | 不可照搬 |
| --- | --- | --- | --- |
| [SkillComposer: Generative Skill Composition for LLM Agents](https://arxiv.org/abs/2606.32025) | 将子集、数量、执行顺序联合建模为受约束的 skill-ID 序列预测；摘要报告在两个 coding agent 上，相对无 skill 基线分别提高 23.1 和 18.2 个百分点，并优于 top-3 retrieval。 | 输出应是带顺序、版本和约束的组合计划，而不是 top-k 相似度列表；以后可把当前确定性组合器作为 learned router 的安全基线和约束解码器。 | 本仓库目前没有足够的人工 task-composition 对和跨域复现，不能先上训练式 decoder；论文收益也不能外推到本地异构 worker 或不同 harness。 |
| [SkillWeaver: Compositional Skill Routing for LLM Agents](https://arxiv.org/abs/2606.18051) | decompose-retrieve-compose；用依赖感知 DAG 规划。其 CompSkillBench 含 300 个组合查询、2,209 个 MCP skills、24 类；摘要把任务分解识别为首要瓶颈，并报告 skill-aware 迭代分解带来明显改善。 | 在检索前形成可审计的原子子任务，在召回后显式建 prerequisite/data-flow DAG；若某一步没有可用 skill，应回到分解而不是硬凑组合。 | MCP tool specification 与长指令型 `SKILL.md` 不完全同构；LLM 分解结果不能直接取得执行权限，必须通过能力、平台、harness、成本和新鲜度硬门。 |
| [SkillRouter: Skill Routing for LLM Agents at Scale](https://arxiv.org/abs/2603.22455) | 在约 80K 候选的 SkillsBench 衍生评测中，摘要报告隐藏正文使路由准确率下降 37–44 个百分点；body-distilled description 仍落后于 all-field，1.2B body-aware retrieve-and-rerank 达到 74.0% Hit@1。 | 做 metadata-only 与 body-aware 两阶段对照；正文信号只进入已通过信任门的候选重排器，并记录正文快照摘要、模型与索引版本。 | 不能因此把未审查正文暴露给 planner/model，更不能导入或执行正文引用的代码；80K 场景的单 skill Hit@1 也不等于 3/5/10 组合成功率。 |
| [Comparative Approaches to Agent Retrieval over Large Skill Libraries](https://arxiv.org/abs/2608.06196) | 在 690 skills、117 个非 echo 查询上，摘要报告 hybrid ranker 的 top-5 命中为 73.5% ± 8.0；由同一 embedding 邻域预筛出的 typed graph 反而低 11.2 个百分点，且多数检索遗漏不在图的可达范围内。 | 图适合在已有候选中表达先决条件、数据流和顺序；评测查询必须避免复述 skill 文案，并单独测 candidate recall。 | 不要用同一 embedding 邻域先构图，再声称图能扩大召回；相似性边也不能冒充 prerequisite 或可组合性证据。 |

这些论文彼此并不矛盾：SkillRouter 说明正文可能提升“找得到”，SkillComposer/SkillWeaver 说明找到后仍需解决集合、数量和顺序，Comparative Approaches 则限定了图结构最适合介入的位置——召回之后，而不是替代召回。

## GitHub：可以复用的工程形状

| 项目 | 可借鉴 | 不可照搬 |
| --- | --- | --- |
| [majiayu000/harness](https://github.com/majiayu000/harness) | 将多 agent 的 thread/task/turn 生命周期、adapter、执行策略、独立交叉审查、可观测性和 MCP 接口放入一个控制面；“实施者不能自审”的结构很适合 skill 进化的 promotion gate。 | 它是 Rust/Postgres 为中心的完整 fleet service；LAD 的离线优先、桌面/服务器混合部署不应为了复用概念而整体迁移技术栈。 |
| [boundflow/boundflow](https://github.com/boundflow/boundflow) | 明确分离 control plane 与运行在操作者环境的 workers；lease/checkpoint、运行中成本与 tool-call 限制、审批等待、回滚到 known-good version，适合 outcome-to-promotion 生命周期。 | README 明确标注 public preview、pre-1.0，且尚未经过外部用户生产运行；其 gRPC/API 不能作为成熟性证明，也不应替换 LAD 的 fence、artifact validation 和离线测试。 |
| [dovetail/conduit](https://github.com/dovetail/conduit) | `RunSpec` 作为自包含、可序列化任务描述，`WorkerFactory`/event sink 分离编排和执行，可落到 local、remote、EKS、Fargate；多 CLI runner 与远端 worker 形状接近 LAD 目标。 | dev auth bypass 和 shared worker token 是部署便利，不是零信任证明；工作区、凭据、artifact 和租约仍需更细的 scope、digest 与 fence。 |
| [jo-inc/safe-skill-search](https://github.com/jo-inc/safe-skill-search) | 本地 Tantivy/BM25 索引、质量阈值、来源/信任标签和跨平台二进制，适合做廉价、离线的第一阶段候选生成。 | README 的实现是 BM25 全文检索，不能把项目简介中的“semantic”当作 latent-space 证据；外部生成的质量分和 registry 信任标签也必须在本地重算或降级为未验证声明。 |

三个成熟通用系统只应提供底层语义，而不是 skill 策略：

- [Temporal](https://github.com/temporalio/temporal) 提供可恢复 workflow、失败重试和 worker 模型，可借鉴 durable state machine；不负责 skill 相关性、正文信任或组合归因。
- [Ray](https://github.com/ray-project/ray) 的 task、actor、object 抽象适合规模化执行器；它不会替我们决定哪个 skill 正确，也不能替代 provider quota 和 artifact gate。
- [Kubernetes Kueue](https://github.com/kubernetes-sigs/kueue) 的 job admission、优先级、公平共享、资源 flavor、抢占和多集群分发适合服务器池调度；桌面版不应因此强依赖 Kubernetes。

## 与本仓库现实现的映射

| 研究/工程概念 | 当前实现 | 尚缺的关键能力 |
| --- | --- | --- |
| Homebrew/pip 式 skill 分发 | [`packages/manifest.py`](../../src/local_agent_dispatch/packages/manifest.py)、[`catalog.py`](../../src/local_agent_dispatch/packages/catalog.py)、[`lockfile.py`](../../src/local_agent_dispatch/packages/lockfile.py)、[`store.py`](../../src/local_agent_dispatch/packages/store.py) 已有严格 manifest、确定性依赖解析/lock、本地校验安装、激活、回滚和安全卸载；`kind=skill` 要求 data-only entrypoint 和根 `SKILL.md`。 | 远端 registry、发布者签名、透明日志、下载器、多包原子安装事务；安装仍不等于执行授权，这一点应保留。 |
| 安全索引与 latent 表征 | [`skills/models.py`](../../src/local_agent_dispatch/skills/models.py) 只接收有 TTL/证据状态的 bounded metadata 和预计算 embedding；[`skills/latent.py`](../../src/local_agent_dispatch/skills/latent.py) 在计算预算内输出 pairwise cosine 聚合、冗余 pair/连通组和 capability/facet coverage，不泄露向量；正文、路径、entrypoint 不进入索引。 | 可复现的离线 index builder、embedding/model provenance、正文隔离解析器、lexical/hybrid baseline，以及按 skill family/version 的去泄漏数据切分。 |
| 3/5/10 多 skill 组合 | [`skills/composition.py`](../../src/local_agent_dispatch/skills/composition.py) 先做 freshness、availability、platform、harness、allow/prohibit、成本和不确定性硬过滤，再按 coverage、facet complementarity、latent relevance、redundancy、cost、uncertainty 确定性选满 3/5/10。 | 当前 rank 是选择次序，不是显式 prerequisite DAG；尚无 learned router、body-aware reranker、组合交互模型和真实任务 benchmark。 |
| Outcome、lineage 与进化 | [`skills/evolution.py`](../../src/local_agent_dispatch/skills/evolution.py) 将 exact skill versions、结果、指标和 evidence refs 记录为数据，并只生成待审核 metadata revision 与 lineage；[`skills/scaffold.py`](../../src/local_agent_dispatch/skills/scaffold.py) 可把已审核 spec 原子生成 inert、digest-bound 的 skill 包，但不安装或启用。 | 组合级因果归因、自动发现缺口后的 `create`/merge/split 提案生成、隔离评测、签名发布、canary promotion、自动回滚；低分不能直接自改 `SKILL.md`。 |
| 资源/配额自适应调度 | [`scheduler/core.py`](../../src/local_agent_dispatch/scheduler/core.py) 提供 filter-score-reserve-reconcile，[`scheduler/policy.py`](../../src/local_agent_dispatch/scheduler/policy.py) 提供分层 policy、资源/配额硬上限与 AIMD 并发。 | 跨 worker 的持久公平队列、全局预算与优先级、抢占/checkpoint 成本模型，以及长期在线校准。 |
| 异构 worker 与 harness | [`worker/state.py`](../../src/local_agent_dispatch/worker/state.py)、[`plugins/protocols.py`](../../src/local_agent_dispatch/plugins/protocols.py) 和 [`adapters/harness/cursor.py`](../../src/local_agent_dispatch/adapters/harness/cursor.py) 已分离 worker heartbeat/fence、provider/runtime/transport/harness/batch scheduler 和显式 Cursor lifecycle。 | 生产级 out-of-process plugin host、更多 harness/scheduler adapters、跨机身份与签名 attestations、统一事件流和可观测面。 |

因此，本仓库已经有“安全内核”，但还没有证据证明它是一个更好的 skill router。下一步优先级应是 benchmark 和两阶段检索，不是继续堆调度器功能。

## Skill create / evolve 的建议生命周期

创建和进化必须是 proposal pipeline，而不是运行中的 agent 直接覆盖 skill：

1. **发现缺口**：只有当 fresh outcomes 显示无覆盖能力、反复失败或现有组合成本过高时，生成 `create`、`revise`、`merge` 或 `split` 候选。
2. **生成数据提案**：记录父版本、触发 outcomes、目标 capabilities/facets、预期成本、不确定性和评测计划；此步不写 `SKILL.md`。
3. **构建隔离候选包**：审核后的 scaffold spec 可生成新的 `kind=skill` 版本和完整 artifact digest；随后再独立 resolve/lock/install，但不自动激活、索引或启用。
4. **静态与沙箱评测**：检查 schema、权限、prompt injection、平台/harness 约束；在无凭据 fixture 上先测，再做显式授权的 canary。
5. **独立审核与 promotion**：审核者不能是生成该候选的同一 agent；通过后才激活 exact version，并保留上一 generation。
6. **观测与回滚**：outcome 必须绑定 plan、skill exact versions、worker/harness/model、任务集版本和 evidence；触发 guardrail 即回滚，而不是原地修补。

当前 evolution 模块已经覆盖第 1–2 步的一部分和 lineage 数据形状，scaffold 覆盖第 3 步中“从已审核 spec 生成 inert 源包”的窄边界；自动 `create` 缺口提案、评测和 promotion controller 仍应作为后续独立边界实现。

## 建议的最小 benchmark

### 1. 数据集与防泄漏

- 使用真实、非 echo 的任务描述，不能复述 skill 名称或 description；另外加入近义、歧义、冲突约束、缺 skill、过期索引和恶意正文样本。
- 按 skill family 和版本切分 train/validation/holdout，避免同一 skill 的改写同时出现在训练与测试。
- 每个样本标注 required capabilities、允许的候选集合、可接受组合、prerequisite/data-flow DAG、预算与平台/harness；允许多个正确答案。
- 固定 skill/index/package 快照摘要，使论文式结果可以重放。

### 2. 对照组

至少比较以下路径，并对每条路径分别跑 `k ∈ {3, 5, 10}`：

1. 无 skill；
2. metadata BM25 top-k；
3. metadata dense top-k；
4. metadata hybrid recall -> metadata rerank；
5. metadata hybrid recall -> **可信候选的 body-aware 隔离重排**；
6. 5 + 当前 coverage/diversity/cost/uncertainty 组合器；
7. 6 + dependency DAG 排序；
8. 人工 gold/oracle 上界。

正文阶段只读取通过 package digest、来源策略和静态检查的候选快照；不得 import、执行、联网，也不得把正文写入最终 plan/receipt。发生未知来源、摘要不匹配或 parser 异常时退回 metadata-only，而不是放宽信任门。

### 3. 组合目标和分阶段指标

组合目标可保持可解释形式：

```text
J(S) = coverage + facet diversity + task relevance
       - latent redundancy - expected cost - uncertainty
```

但权重必须用 holdout 校准，不由单次主观调参决定。分阶段测量：

- **召回**：candidate Recall@N、缺失能力率；metadata-only 与 body-aware 的增益及其 token/延迟成本。
- **组合**：required-capability coverage、set precision/recall、pairwise latent redundancy、facet diversity、预算违规率、3/5/10 的边际收益。
- **顺序**：DAG 合法率、prerequisite violation、关键路径长度；不要把 cosine similarity 当顺序真值。
- **端到端**：任务成功率、独立 validator 通过率、总 token/时间/费用、失败恢复率和 artifact freshness。
- **安全**：未可信正文曝光率、错误执行率、stale/unknown fail-closed 率、跨 scope 写入率；这些必须是硬 guardrail，而不是与成功率加权平均。
- **不确定性**：预测置信与实际成功的校准，以及 abstain 后的 coverage/accuracy 曲线。

### 4. Outcome lineage 与进化评测

- 每个 outcome 绑定 `dataset/task -> index digest -> plan id -> ordered exact skill versions -> execution attempt -> validator receipt`。
- 对组合失败先做 paired replay 和 leave-one-skill-out；证据不足时只标记“组合失败”，不要把责任平均分给所有 skill。
- 新版本只在固定 holdout、回归集和安全集均不过界时 promotion；同时保留旧版本对照和可逆 generation。
- 单独报告 proposal acceptance、canary regression、rollback、重复缺口消失率，避免用“产生了更多新 skill”冒充进化质量。

## 研究成熟度警告

四篇 skill 论文都是 2026 年 arXiv 预印本；其中 SkillRouter 在 2026 年内已有多次修订。arXiv 页面能证明版本、摘要与作者报告的实验，不能证明同行评审、跨环境复现或长期生产稳定性。四个 agent/skill GitHub 项目的 README 同样属于项目自述；BoundFlow 还明确声明 pre-1.0 public preview。任何实现借鉴都应固定论文版本和 Git commit，通过本仓库的离线 benchmark、威胁模型和真实 canary 后再晋级为设计依据。
