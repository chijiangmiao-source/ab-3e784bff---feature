# 姿态保护控制器 · 规则审计台

工程师在把无序保护规则下发给固件之前，用本服务审计：**任一遥测布尔组合是否恰好命中一条动作**——既不允许遗漏组合落入未定义状态（空洞），也不允许相反动作同时触发（重叠）。覆盖审计冻结后，再为每个已声明遥测变量指定**危险方向**、为每个现有动作填写**保护等级**，在同一张共享 ROBDD 上精确复核**危险偏序单调性**：危险程度上升时，裁决等级不得下降。

- 至多 **64** 个稳定变量、至多 **96** 条规则；每条规则含唯一标识、动作名与由非（`!`）、与（`&`/`&&`）、或（`|`/`||`）、括号组成的条件。
- 裁决在**按变量标识 ASCII 升序固定的 ROBDD**（简约有序二叉决策图）上进行，对全部 2^N 个赋值精确有效，**不以枚举、抽样或有限测试替代**。
- 空洞/重叠给出精确个数与**首个赋值**（ASCII 变量序、假先于真的字典序）；重叠同时列出该赋值下**按标识排序的命中规则**。
- 单调复核精确检验全部满足危险偏序的赋值对（每变量 3 种合法相对关系，共 **3^N** 对）；降级时**先按低危险赋值 α、再按高危险赋值 β** 稳定返回首个反例，并列出两侧命中规则、动作与等级；通过时给出每个动作等级的**规范覆盖摘要**。
- 录入错误（非法标识、重复标识、未知变量、空条件、空动作、残缺语法、数量超限、**变量遗漏危险方向、未知动作、等级重复、危险方向缺失**）**一次定位、整体返回**。
- 单调复核**只接受无空洞、无不同动作重叠的冻结结论**；提交后页面冻结审计结论；修改规则草稿、危险方向或等级配置即清除旧证据，旧单调性结论立即失效。

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
  "variables": ["armed", "safe"],
  "rules": [
    {"id": "R1", "action": "hold",  "condition": "safe | armed"},
    {"id": "R2", "action": "alarm", "condition": "safe"},
    {"id": "R3", "action": "hold",  "condition": "!safe & !armed"}
  ]
}
```

- 录入非法：`422`，`errors` 数组一次列出全部问题（`kind` 含 `illegal_identifier`、`duplicate_variable`、`duplicate_rule_id`、`unknown_variable`、`empty_condition`、`empty_action`、`syntax`、`too_many_variables`、`too_many_rules` 等）。
- 录入合法：`200`，返回：

| 字段 | 含义 |
| --- | --- |
| `verdict` | `PASS`（无空洞且无重叠）/ `FAIL` |
| `variable_order` | 裁决所用的 ASCII 变量顺序 |
| `space` | 赋值空间大小 2^N |
| `holes.count` / `holes.first` | 空洞精确个数 / 首个空洞赋值 |
| `overlaps.count` / `overlaps.first` / `overlaps.rules` | 重叠精确个数 / 首个重叠赋值 / 该赋值下按标识排序的命中规则 |
| `rules[].nodes` / `rules[].root` | 各规则在共享 ROBDD 中的规范节点摘要（可达节点数、根节点号） |
| `conclusion` | 覆盖结论文本 |

### `POST /api/monotonicity`
危险偏序单调复核。请求体在变量与规则之外附加：

```json
{
  "variables": ["armed", "safe"],
  "rules": [
    {"id": "R1", "action": "hold",  "condition": "!armed"},
    {"id": "R2", "action": "alarm", "condition": "armed"}
  ],
  "directions": {"armed": "high", "safe": "low"},
  "levels": {"hold": 1, "alarm": 2}
}
```

- `directions`：每个已声明变量一个危险方向，`high` 表示**真值更危险**、`low` 表示**假值更危险**。
- `levels`：每个现有动作一个由低到高、**连续唯一**的保护等级（取值 1..K 且无重复，即 1..K 的一个排列）。
- 配置非法（变量遗漏方向、方向值非法、引用未声明变量、动作漏配等级、等级超范围/重复、引用未知动作）或规则本身存在空洞/不同动作重叠时：`422`，错误种类含 `missing_variable_direction`、`invalid_direction`、`unknown_variable`、`missing_action_level`、`invalid_level`、`duplicate_level`、`unknown_action`、`coverage_incomplete`。
- 合法：`200`，返回：

| 字段 | 含义 |
| --- | --- |
| `monotonicity` | `PASS`（危险上升不降级）/ `FAIL` |
| `ordered_pairs` | 已精确检验的偏序赋值对数量 3^N |
| `violating_pairs` | 降级赋值对精确数量 |
| `counterexample.less_dangerous` / `counterexample.more_dangerous` | 首个反例的低危险侧 α 与更危险侧 β（各含 `assignment`、命中 `action`、`level`、按标识排序的 `rules`） |
| `coverage[]` | 通过时每个动作等级的规范覆盖摘要（`level`、`action`、`rules`、命中赋值数、规范节点数、首个命中赋值），按等级升序 |
| `conclusion` | 单调结论文本 |

首个反例按 α 赋值（ASCII、假先于真）再 β 赋值的字典序稳定选取。

## 语义约定

- **空洞**：没有任何规则命中的赋值；**重叠**：至少两条**不同动作**的规则同时命中的赋值（同动作规则相交不算冲突）。
- **首个**赋值：按 `variable_order`、每个变量假先于真的字典序。
- **危险偏序**：β 比 α 更危险（α ≤d β）当且仅当逐变量满足——`high` 方向：`!α_i | β_i`；`low` 方向：`α_i | !β_i`。每变量有 3 种合法相对关系（相等×2 + 沿方向上升×1），故偏序对恰为 3^N。
- **单调性**：α ≤d β 时，α 命中动作的等级不得高于 β 命中动作的等级；否则该赋值对构成降级反例。
- 关系复核图是共享 ROBDD 上的双副本构造，采用交错变量序 `低₀, 高₀, 低₁, 高₁, …`（下标为 ASCII 序）以保持线性规模；首个反例由优先级共因子搜索按 α 全部变量、再 β 全部变量（ASCII、假先于真）精确求出，与 BDD 物理层顺序无关。
- 规范节点摘要：固定变量序下 ROBDD 表示唯一，因此可达节点数是条件的规范指纹。
- 资源护栏：BDD 节点数超过预算（4,000,000）时返回 `complexity` 错误，而非退化为近似裁决。

## 目录结构

```
app/
  parser.py        条件表达式词法/语法分析
  bdd.py           ROBDD 管理器（规范构造、首个赋值、精确计数、共因子优先级首解）
  audit.py         单遍校验 + 空洞/重叠裁决
  monotonicity.py  危险方向/等级校验 + 危险偏序单调复核（双副本关系 ROBDD）
  server.py        标准库 HTTP 服务（页面、/health、/api/audit、/api/monotonicity）
  static/index.html  审计操作页面（提交冻结、改稿/改配置清证据）
tests/             单元测试（parser / bdd / audit / monotonicity / api）
verify/            一次性验收服务（退出码报告结果）
docker-compose.yml / Dockerfile
```
