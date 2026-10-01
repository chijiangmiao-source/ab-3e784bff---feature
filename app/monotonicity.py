"""危险偏序单调性的精确裁决。

审计要求：若遥测赋值 β 比 α 更危险（在每个变量上沿其声明的危险方向
移动），则 β 命中动作的保护等级不得**低于** α 命中动作的等级。规则集
必须已冻结为“无空洞、无不同动作重叠”，故每个赋值的裁决是唯一动作。

本模块**不枚举 2^N 个赋值、不抽样、不只检查相邻翻转**。做法是把“赋值
对”编码为 2N 个变量的关系 ROBDD，层序在既有 ASCII 序上交错扩展（让每
个偏序边的两个变量相邻，关系 BDD 保持线性规模）：

    v0 < v0' < v1 < v1' < ... < vN-1 < vN-1'
    └ α_i ┘ └ β_i ┘  （β 侧变量加 ' 后缀）

危险偏序逐坐标直接用原始遥测值表达：

    真值更危险：α_i ≤ β_i，即 ¬(α_i ∧ ¬β_i)
    假值更危险：α_i ≥ β_i，即 ¬(¬α_i ∧ β_i)

反例关系（全部是 ROBDD 规范构造，无一例外按赋值枚举）::

    violation = ⋁_{等级(A) > 等级(B)} f_A(α) ∧ f_B(β) ∧ (α ≼ β)

首个反例的稳定次序要求“先按低危险赋值 α、再按高危险赋值 β”排序，这与
交错层序不同；提取时按外部优先级（α 整块在前、β 整块在后，各自 ASCII
序、假先于真）逐步对关系 BDD 取假分支受限（cofactor restrict），受限为
空才走真分支——仍是 BDD 上的规范操作，不枚举候选对。
"""
from __future__ import annotations

from . import bdd as _bdd

FALSE = _bdd.FALSE
TRUE = _bdd.TRUE

HI_SUFFIX = "'"  # 高危险侧 β 的变量名后缀


class PairManager:
    """2N 变量（α/β 两份拷贝）上的关系 ROBDD 管理器。"""

    def __init__(self, variables: list[str], src: "_bdd.Manager"):
        self.variables = list(variables)
        self.n = len(self.variables)
        # 交错层序：v0, v0', v1, v1', ...；α_i 在层 2i，β_i 在层 2i+1。
        self.pair_vars = [v for name in self.variables for v in (name, name + HI_SUFFIX)]
        self.mgr = _bdd.Manager(self.pair_vars)
        self.src = src

    # ----------------------------------------------------------- 关系拷贝
    def copy_low(self, root: int) -> int:
        """f(α)：原 BDD（层 i）嵌入对空间层 2i。"""
        return self._copy(root, 0)

    def copy_high(self, root: int) -> int:
        """f(β)：原 BDD（层 i）嵌入对空间层 2i+1。"""
        return self._copy(root, 1)

    def _copy(self, root: int, parity: int) -> int:
        memo: dict[int, int] = {}

        def rec(u: int) -> int:
            if u <= TRUE:
                return u
            hit = memo.get(u)
            if hit is not None:
                return hit
            var, low, high = self.src.nodes[u]
            result = self.mgr.mk(2 * var + parity, rec(low), rec(high))
            memo[u] = result
            return result

        return rec(root)

    # ----------------------------------------------------------- 偏序构造
    def danger_order(self, danger: dict[str, str]) -> int:
        """逐坐标危险偏序 α ≼ β，方向取自每个变量的危险声明。"""
        rel = TRUE
        for i, name in enumerate(self.variables):
            lo, hi = 2 * i, 2 * i + 1
            if danger[name] == "true":
                # 真值更危险：α=1 时要求 β=1。
                edge = self.mgr.mk(lo, TRUE, self.mgr.mk(hi, FALSE, TRUE))
            else:
                # 假值更危险：α=0 时要求 β=0。
                edge = self.mgr.mk(lo, self.mgr.mk(hi, TRUE, FALSE), TRUE)
            rel = self.mgr.apply("and", rel, edge)
        return rel

    # ------------------------------------------------------------- 取证据
    def sat_count(self, root: int) -> int:
        return self.mgr.sat_count(root)

    @staticmethod
    def _restrict(root: int, level: int, value: bool, mgr: "_bdd.Manager") -> int:
        """对单个变量取共因子（cofactor）：root|_{var(level)=value}。

        变量按交错层序构造，但取共因子的优先级是“先 α 整块后 β 整块”，
        因此目标层可能位于当前根的下层（下层层号更大）或上层结构之后；
        必须整树递归，只在终端停止，不能因根层更小而提前返回。
        """
        memo: dict[int, int] = {}

        def rec(u: int) -> int:
            if u <= TRUE:
                return u
            hit = memo.get(u)
            if hit is not None:
                return hit
            var, low, high = mgr.nodes[u]
            if var == level:
                result = rec(low if not value else high)
            else:
                result = mgr.mk(var, rec(low), rec(high))
            memo[u] = result
            return result

        return rec(root)

    def first_pair(self, root: int) -> tuple[dict[str, bool], dict[str, bool]] | None:
        """首个反例赋值对：先 α 整块（ASCII 序）、再 β 整块，假先于真。

        层序虽交错，但按外部优先级逐变量取假共因子：假受限为空才取真，
        全过程是 2N 次规范共因子操作，不枚举候选赋值对。
        """
        if root == FALSE:
            return None
        chosen: dict[int, bool] = {}
        current = root
        priority = [2 * i for i in range(self.n)] + [2 * i + 1 for i in range(self.n)]
        for level in priority:
            trial = self._restrict(current, level, False, self.mgr)
            if trial != FALSE:
                chosen[level] = False
                current = trial
            else:
                chosen[level] = True
                current = self._restrict(current, level, True, self.mgr)
        low = {name: chosen[2 * i] for i, name in enumerate(self.variables)}
        high = {name: chosen[2 * i + 1] for i, name in enumerate(self.variables)}
        return low, high


def check_monotonicity(
    variables: list[str],
    compiled_rules: list[dict],
    danger: dict[str, str],
    levels: dict[str, int],
    cover_node: int,
    src_manager,
) -> dict:
    """在共享 ROBDD 上精确检验危险偏序单调性。

    compiled_rules：[{"id", "action", "node"(原 manager 上的根)}]
    danger：{变量: "true"（真值更危险）/ "false"（假值更危险）}
    levels：{动作: 唯一整数等级（数值小者保护等级低）}
    cover_node：原 manager 上的覆盖函数（冻结结论下为 TRUE）
    """
    # 1) 每个动作的判定函数（同动作多条规则取并；同动作相交不算冲突）。
    actions_by_level = sorted(levels, key=lambda a: (levels[a], a))
    action_fn: dict[str, int] = {}
    action_rules: dict[str, list[str]] = {}
    for item in compiled_rules:
        action_fn[item["action"]] = src_manager.apply(
            "or", action_fn.get(item["action"], FALSE), item["node"]
        )
        action_rules.setdefault(item["action"], []).append(item["id"])

    # 2) 进入 2N 变量的对空间；偏序两侧都限制在已覆盖赋值上（冻结结论
    #    保证全覆盖，此限制只是与规范语义对齐的保守相交）。
    pm = PairManager(variables, src_manager)
    order = pm.danger_order(danger)
    order = pm.mgr.apply(
        "and",
        order,
        pm.mgr.apply("and", pm.copy_low(cover_node), pm.copy_high(cover_node)),
    )
    alpha_side = {a: pm.copy_low(action_fn[a]) for a in actions_by_level}
    beta_side = {a: pm.copy_high(action_fn[a]) for a in actions_by_level}

    # 3) 反例集：α 命中等级严格更高的动作 A、β 命中更低动作 B。
    #    按等级自低向高扫描，累积“严格更高的 α 侧”之并。
    violation = FALSE
    higher_or = FALSE
    for idx in reversed(range(len(actions_by_level))):
        beta = beta_side[actions_by_level[idx]]
        if higher_or != FALSE:
            violation = pm.mgr.apply(
                "or",
                violation,
                pm.mgr.apply("and", pm.mgr.apply("and", higher_or, beta), order),
            )
        higher_or = pm.mgr.apply("or", higher_or, alpha_side[actions_by_level[idx]])

    count = pm.sat_count(violation)

    def evidence(assign: dict[str, bool]) -> dict:
        # 直接在原始遥测坐标下列出命中规则与动作。
        rule_ids, hit_actions = [], set()
        for item in compiled_rules:
            if src_manager.evaluate(item["node"], assign):
                rule_ids.append(item["id"])
                hit_actions.add(item["action"])
        return {
            "assignment": dict(assign),
            "rules": sorted(rule_ids),
            "actions": sorted(hit_actions),
            "level": min(levels[a] for a in hit_actions),
            "levels": {a: levels[a] for a in sorted(hit_actions)},
        }

    counterexample = None
    if count:
        low_assign, high_assign = pm.first_pair(violation)
        counterexample = {
            "less_dangerous": evidence(low_assign),
            "more_dangerous": evidence(high_assign),
        }

    # 4) 每个动作等级的规范覆盖摘要（sat_count 精确计数，非枚举）。
    coverage = []
    for action in actions_by_level:
        exact = src_manager.sat_count(action_fn[action])
        coverage.append(
            {
                "action": action,
                "level": levels[action],
                "rules": sorted(action_rules[action]),
                "assignments": exact,
                "assignments_text": str(exact),
            }
        )

    comparable = pm.sat_count(order)
    return {
        "verdict": "PASS" if count == 0 else "FAIL",
        "pair_space": 1 << (2 * len(variables)),
        "pair_space_text": str(1 << (2 * len(variables))),
        "comparable_pairs": comparable,
        "comparable_pairs_text": str(comparable),
        "violating_pairs": count,
        "violating_pairs_text": str(count),
        "counterexample": counterexample,
        "coverage": coverage,
    }
