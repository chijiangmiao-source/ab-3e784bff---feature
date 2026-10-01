# 姿态保护控制器 · 规则审计台

工程师在把无序保护规则下发给固件之前，用本服务审计两件事：

1. **覆盖**：任一遥测布尔组合是否恰好命中一条动作——既不允许遗漏组合落入未定义状态（空洞），也不允许相反动作同时触发（重叠）。
2. **危险偏序单调性**：为每个已声明遥测变量指定**真值更危险**或**假值更危险**、为每个动作填写由低到高的**唯一保护等级**后，精确复核“危险程度上升时，裁决是否会被降为更低等级”。

- 至多 **64** 个稳定变量、至多 **96** 条规则；每条规则含唯一标识、动作名与由非（`!`）、与（`&`/`&&`）、或（`|`/`||`）、括号组成的条件。
- 覆盖裁决在**按变量标识 ASCII 升序固定的 ROBDD**（简约有序二叉决策图）上进行，对全部 2^N 个赋值精确有效，**不以枚举、抽样或有限测试替代**。
- 单调性裁决把“赋值对”编码为 **2N 个变量的关系 ROBDD**（共享同一 ASCII 变量序），精确检验**全部满足危险偏序的赋值对**（上界 3^N 对），不枚举遥测组合、不抽样、不只检查相邻翻转。
- 系统**只接受无空洞、无不同动作重叠的冻结结论**；变量遗漏危险方向、未知动作、等级重复/缺失/非整数，或规则仍有空洞/重叠时，页面与 API 明确拒绝并清除过期证据。
- 空洞/重叠给出精确个数与**首个赋值**（ASCII 变量序、假先于真的字典序）；重叠同时列出该赋值下**按标识排序的命中规则**。
- 单调性降级时，按**先低危险赋值、再高危险赋值**的稳定次序返回**首个反例**，并列出两侧命中规则、动作与等级；通过时展示**每个动作等级的规范覆盖摘要**。
- 录入错误（非法标识、重复标识、未知变量、空条件、空动作、残缺语法、数量超限、危险方向缺失/非法、动作等级遗漏/未知/重复/非整数）**一次定位、整体返回**。
- 提交后页面冻结审计结论；修改规则草稿、危险方向或等级配置任一内容，旧单调性结论立即失效并清除证据。

## 快速开始（Compose）

```bash
# 启动审计页面（宿主机端口可用 WEB_PORT 配置，默认 8080）
WEB_PORT=8080 docker compose up -d web

# 页面：http://localhost:8080/        健康路径：http://localhost:8080/health

# 一次性验收：构建检查 + 单元测试 + 页面/健康路径冒烟 + 决策表边界核对，
# 完成后自动退出，退出码即验收结果（0 通过 / 1 失败）
docker compose up --exit-code-from verify --abort-on-container-exit verify
# 或：docker compose run --rm verify
```

## 本地开发（无 Docker，仅 Python ≥ 3.10 标准库）

```bash
python -m app.server                 # 监听 0.0.0.0:8000（PORT 环境变量可改）
python -m unittest discover -s tests -t .   # 单元测试
python -m verify.verify              # 对 http://127.0.0.1:8000 执行验收（WEB_URL 可改）
```

## API

### `GET /health`
健康路径，返回 `{"status": "ok"}`。

### `GET /`
审计操作页面。

### `POST /api/audit`
请求体：

```json
{
  "variables": ["armed", "tilt"],
  "danger": {"armed": "true", "tilt": "true"},
  "rules": [
    {"id": "R1", "action": "hold",  "condition": "!armed"},
    {"id": "R2", "action": "arm",   "condition": "armed & !tilt"},
    {"id": "R3", "action": "emergency", "condition": "armed & tilt"}
  ],
  "levels": {"hold": 1, "arm": 2, "emergency": 3}
}
```

- `danger`：每个变量的危险方向，必填，取值 `"true"`（真值更危险）或 `"false"`（假值更危险）。
- `levels`：每个规则动作的保护等级，必填，整数且同一配置内唯一；数值越小保护等级越低。
- 录入非法：`422`，`errors` 数组一次列出全部问题（`kind` 含 `illegal_identifier`、`duplicate_variable`、`duplicate_rule_id`、`unknown_variable`、`empty_condition`、`empty_action`、`syntax`、`too_many_variables`、`too_many_rules`、`missing_danger_direction`、`invalid_danger_direction`、`unknown_danger_variable`、`missing_action_level`、`unknown_action`、`duplicate_level`、`invalid_level` 等）。
- 覆盖未冻结（仍有空洞或不同动作重叠）：裁决照常返回 `200`，但 `frozen=false`、`monotonicity=null`，总裁决 `FAIL`——**系统不接受在未冻结结论上给出单调性结论**。
- 录入合法：`200`，返回：

| 字段 | 含义 |
| --- | --- |
| `verdict` | `PASS`（覆盖冻结且单调性通过）/ `FAIL` |
| `coverage_verdict` / `frozen` | 覆盖裁决是否无空洞、无不同动作重叠（冻结） |
| `variable_order` | 裁决所用的 ASCII 变量顺序 |
| `space` | 赋值空间大小 2^N |
| `holes.count` / `holes.first` | 空洞精确个数 / 首个空洞赋值 |
| `overlaps.count` / `overlaps.first` / `overlaps.rules` | 重叠精确个数 / 首个重叠赋值 / 该赋值下按标识排序的命中规则 |
| `monotonicity.verdict` | `PASS`（全部可比对无降级）/ `FAIL` |
| `monotonicity.comparable_pairs` | 满足危险偏序的赋值对精确个数（自比对 2^N + 严格偏序对，全“真更危险”时为 3^N） |
| `monotonicity.violating_pairs` / `counterexample` | 降级赋值对精确个数 / 首个反例（先低危险 α、再高危险 β），两侧各列 `assignment`、`rules`、`actions`、`level` |
| `monotonicity.coverage[]` | 通过时每个动作等级的规范覆盖摘要：`action`、`level`、`rules`、精确 `assignments` |
| `rules[].nodes` / `rules[].root` | 各规则在共享 ROBDD 中的规范节点摘要（可达节点数、根节点号） |
| `danger_directions` / `action_levels` | 本次裁决实际采用的方向与等级（去空白后的规范回显） |
| `conclusion` | 覆盖与单调性的结论文本 |

## 单调性语义

- **危险偏序**：β 比 α 更危险，当且仅当在每个变量上 β 的值沿该变量声明的方向离开安全侧（“真值更危险”要求 α=false 时 β 可真可假、α=true 时 β 必须真；“假值更危险”对称）。该偏序是含等号的偏序（含 α=β 自身对）。
- **降级反例**：α ≼ β，但 β 命中动作的等级**严格低于** α 命中动作的等级。冻结结论保证每个赋值的裁决唯一，因此“裁决等级”定义无歧义。
- **首个反例次序**：先按低危险赋值 α、α 相同再按高危险赋值 β，各自按 `variable_order` 假先于真的字典序取最小；通过 BDD 共因子（cofactor）受限直接提取，不枚举候选对。
- **精确性**：关系 ROBDD 的层序为 `v0 < v0' < v1 < v1' < …`（既有 ASCII 序的交错扩展，让每条偏序边相邻）；反例关系是 `⋁_{等级(A)>等级(B)} f_A(α) ∧ f_B(β) ∧ (α ≼ β)`，比较总数与反例数均为精确大整数。
- **覆盖摘要**：通过时对每个动作函数取 ROBDD 精确满足计数（非枚举），各动作覆盖之和恰为 2^N。

## 语义约定

- **空洞**：没有任何规则命中的赋值；**重叠**：至少两条**不同动作**的规则同时命中的赋值（同动作规则相交不算冲突）。
- **首个**赋值：按 `variable_order`、每个变量假先于真的字典序。
- 规范节点摘要：固定变量序下 ROBDD 表示唯一，因此可达节点数是条件的规范指纹。
- 资源护栏：BDD 节点数超过预算（4,000,000）时返回 `complexity` 错误，而非退化为近似裁决。

## 目录结构

```
app/
  parser.py        条件表达式词法/语法分析
  bdd.py           ROBDD 管理器（规范构造、首个赋值、精确计数、共因子）
  monotonicity.py  2N 变量关系 ROBDD：危险偏序反例与首个证据、逐等级覆盖
  audit.py         单遍校验 + 空洞/重叠裁决 + 冻结门控 + 单调性裁决
  server.py        标准库 HTTP 服务（页面、/health、/api/audit）
  static/index.html  审计操作页面（提交冻结、改稿清证据、反例/覆盖展示）
tests/             单元测试（parser / bdd / audit / api / 单调性）
verify/            一次性验收服务（退出码报告结果）
docker-compose.yml / Dockerfile
```
