# 姿态保护控制器 · 规则审计台

工程师在把无序保护规则下发给固件之前，用本服务审计：**任一遥测布尔组合是否恰好命中一条动作**——既不允许遗漏组合落入未定义状态（空洞），也不允许相反动作同时触发（重叠）。

- 至多 **64** 个稳定变量、至多 **96** 条规则；每条规则含唯一标识、动作名与由非（`!`）、与（`&`/`&&`）、或（`|`/`||`）、括号组成的条件。
- 裁决在**按变量标识 ASCII 升序固定的 ROBDD**（简约有序二叉决策图）上进行，对全部 2^N 个赋值精确有效，**不以枚举、抽样或有限测试替代**。
- 空洞/重叠给出精确个数与**首个赋值**（ASCII 变量序、假先于真的字典序）；重叠同时列出该赋值下**按标识排序的命中规则**。
- 录入错误（非法标识、重复标识、未知变量、空条件、空动作、残缺语法、数量超限）**一次定位、整体返回**。
- 提交后页面冻结审计结论；修改任一草稿即清除旧证据。

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

## 语义约定

- **空洞**：没有任何规则命中的赋值；**重叠**：至少两条**不同动作**的规则同时命中的赋值（同动作规则相交不算冲突）。
- **首个**赋值：按 `variable_order`、每个变量假先于真的字典序。
- 规范节点摘要：固定变量序下 ROBDD 表示唯一，因此可达节点数是条件的规范指纹。
- 资源护栏：BDD 节点数超过预算（4,000,000）时返回 `complexity` 错误，而非退化为近似裁决。

## 目录结构

```
app/
  parser.py    条件表达式词法/语法分析
  bdd.py       ROBDD 管理器（规范构造、首个赋值、精确计数）
  audit.py     单遍校验 + 空洞/重叠裁决
  server.py    标准库 HTTP 服务（页面、/health、/api/audit）
  static/index.html  审计操作页面（提交冻结、改稿清证据）
tests/         单元测试（parser / bdd / audit / api）
verify/        一次性验收服务（退出码报告结果）
docker-compose.yml / Dockerfile
```
