"""危险偏序单调性复核：危险程度上升不得把裁决降为更低保护等级。

工程师在空洞/重叠审计通过后，为每个已声明遥测变量指定危险方向
（``high``：真值更危险；``low``：假值更危险），并为每个现有动作填写
由低到高、连续唯一的保护等级（1..K）。

偏序定义：赋值 β 比 α 更危险（α ≤d β）当且仅当逐变量满足

- 真值更危险：α_i 为假或 β_i 为真（``!α_i | β_i``）；
- 假值更危险：α_i 为真或 β_i 为假（``α_i | !β_i``）。

单调性要求：α ≤d β 时，α 命中动作的等级不得高于 β 命中动作的等级。

裁决在按变量标识 ASCII 升序固定的共享 ROBDD 上进行。复核关系图采用
交错变量序 ``低₀, 高₀, 低₁, 高₁, …``（下标为 ASCII 序），使偏序关系的
BDD 保持线性规模；“先按低危险赋值、再按高危险赋值”的首个反例不依赖物理
层顺序，而由优先级共因子搜索按 ASCII 序逐变量（各自假先于真）精确求出。
检验覆盖全部满足偏序的赋值对（恰 3^N 对），既不枚举遥测组合，也不抽样或
只检查相邻翻转。
"""
from __future__ import annotations

from . import bdd, parser
from .audit import _error, validate as validate_rules

DIRECTION_HIGH = "high"  # 真值更危险
DIRECTION_LOW = "low"    # 假值更危险
DIRECTIONS = (DIRECTION_HIGH, DIRECTION_LOW)


def validate_config(order: list[str], actions: list[str], directions, levels) -> list[dict]:
    """单遍汇总危险方向与保护等级的全部录入错误。"""
    errors: list[dict] = []

    if not isinstance(directions, dict):
        errors.append(_error("invalid_payload", "directions 必须为变量到危险方向的映射对象"))
        directions = {}
    if not isinstance(levels, dict):
        errors.append(_error("invalid_payload", "levels 必须为动作到保护等级的映射对象"))
        levels = {}

    # 危险方向：每个已声明变量恰好一个，取值 high/low。
    for name in order:
        if name not in directions:
            errors.append(
                _error(
                    "missing_variable_direction",
                    f"已声明变量 {name!r} 遗漏危险方向：须指定“真值更危险”或“假值更危险”",
                    identifier=name,
                )
            )
            continue
        value = directions[name]
        if not isinstance(value, str) or value not in DIRECTIONS:
            errors.append(
                _error(
                    "invalid_direction",
                    f"变量 {name!r} 的危险方向缺失或非法：须为 high（真值更危险）或 low（假值更危险）",
                    identifier=name,
                    value=value if isinstance(value, str) else None,
                )
            )
    for key in directions:
        if not isinstance(key, str) or key not in order:
            errors.append(
                _error(
                    "unknown_variable",
                    f"危险方向引用了未声明的变量 {key!r}",
                    identifier=key if isinstance(key, str) else None,
                )
            )

    # 保护等级：每个现有动作一个，1..K 内连续唯一（无重复即构成排列）。
    k = len(actions)
    seen_level: dict[int, str] = {}
    duplicated: dict[int, list[str]] = {}
    for action in actions:
        if action not in levels:
            errors.append(
                _error(
                    "missing_action_level",
                    f"现有动作 {action!r} 未填写保护等级",
                    action=action,
                )
            )
            continue
        value = levels[action]
        if isinstance(value, bool) or not isinstance(value, int):
            errors.append(
                _error(
                    "invalid_level",
                    f"动作 {action!r} 的保护等级须为 1..{k} 的整数",
                    action=action,
                )
            )
            continue
        if not 1 <= value <= k:
            errors.append(
                _error(
                    "invalid_level",
                    f"动作 {action!r} 的等级 {value} 超出 1..{k} 范围",
                    action=action,
                    value=value,
                )
            )
            continue
        if value in seen_level:
            duplicated.setdefault(value, [seen_level[value]]).append(action)
        else:
            seen_level[value] = action
    for value, acts in duplicated.items():
        errors.append(
            _error(
                "duplicate_level",
                f"保护等级 {value} 被多个动作重复占用：{', '.join(acts)}（等级须由低到高唯一）",
                value=value,
                actions=acts,
            )
        )
    for action in levels:
        if not isinstance(action, str) or action not in actions:
            errors.append(
                _error(
                    "unknown_action",
                    f"等级配置引用了规则中不存在的未知动作 {action!r}",
                    action=action if isinstance(action, str) else None,
                )
            )
    return errors


def _copy_root(src: bdd.Manager, dst: bdd.Manager, root: int, level_map, memo: dict[int, int]) -> int:
    """把 src 中的规范 BDD 复制到 dst，变量层按 level_map 重定位（终端节点不变）。"""
    if root <= bdd.TRUE:
        return root
    hit = memo.get(root)
    if hit is not None:
        return hit
    var, low, high = src.nodes[root]
    result = dst.mk(
        level_map(var),
        _copy_root(src, dst, low, level_map, memo),
        _copy_root(src, dst, high, level_map, memo),
    )
    memo[root] = result
    return result


def _format_assignment(assignment: dict[str, bool]) -> str:
    return ", ".join(f"{name}={'true' if value else 'false'}" for name, value in assignment.items())


def monotonicity(variables, rules, directions, levels) -> dict:
    """校验并精确复核危险偏序单调性；返回可 JSON 序列化的结论。"""
    errors = validate_rules(variables, rules)
    if errors:
        return {"ok": False, "errors": errors}

    order = sorted(variables)  # 变量标识的 ASCII 升序
    actions = sorted({rule["action"].strip() for rule in rules})
    errors = validate_config(order, actions, directions, levels)
    if errors:
        return {"ok": False, "errors": errors}

    # 单调复核只接受无空洞、无不同动作重叠的冻结前提：每个赋值须有唯一动作裁决。
    mgr = bdd.Manager(order)
    try:
        compiled = []
        for rule in rules:
            ast = parser.parse(rule["condition"])
            compiled.append(
                {
                    "id": rule["id"],
                    "action": rule["action"].strip(),
                    "node": mgr.build(ast),
                }
            )

        coverage = bdd.FALSE
        for item in compiled:
            coverage = mgr.apply("or", coverage, item["node"])
        holes_fn = mgr.negate(coverage)
        hole_count = mgr.sat_count(holes_fn)

        action_fn: dict[str, int] = {}
        for name in actions:
            fn = bdd.FALSE
            for item in compiled:
                if item["action"] == name:
                    fn = mgr.apply("or", fn, item["node"])
            action_fn[name] = fn
        overlap_fn = bdd.FALSE
        for i in range(len(actions)):
            for j in range(i + 1, len(actions)):
                overlap_fn = mgr.apply(
                    "or",
                    overlap_fn,
                    mgr.apply("and", action_fn[actions[i]], action_fn[actions[j]]),
                )
        overlap_count = mgr.sat_count(overlap_fn)
    except bdd.ComplexityError as exc:
        return {"ok": False, "errors": [_error("complexity", f"表达式规模超出裁决预算：{exc}")]}

    if hole_count or overlap_count:
        return {
            "ok": False,
            "errors": [
                _error(
                    "coverage_incomplete",
                    "单调性复核只接受无空洞、无不同动作重叠的冻结结论：请先通过覆盖审计后再复核"
                    f"（当前空洞 {hole_count} 个、不同动作重叠 {overlap_count} 个）",
                    holes=hole_count,
                    overlaps=overlap_count,
                )
            ],
        }

    n = len(order)
    # 关系图交错变量序：低₀, 高₀, 低₁, 高₁, …（下标为 ASCII 序）。
    # 每个变量的 α/β 副本相邻，使偏序合取保持线性规模，避免整块排列的节点爆炸。
    pair_variables: list[str] = []
    for name in order:
        pair_variables.append(f"@lo/{name}")
        pair_variables.append(f"@hi/{name}")

    def lo_map(level: int) -> int:
        return 2 * level

    def hi_map(level: int) -> int:
        return 2 * level + 1

    try:
        pmgr = bdd.Manager(pair_variables)
        lo_memo: dict[int, int] = {}
        hi_memo: dict[int, int] = {}
        lo_action: dict[str, int] = {}
        hi_action: dict[str, int] = {}
        for name in actions:
            lo_fn = hi_fn = bdd.FALSE
            for item in compiled:
                if item["action"] != name:
                    continue
                lo_fn = pmgr.apply(
                    "or", lo_fn, _copy_root(mgr, pmgr, item["node"], lo_map, lo_memo)
                )
                hi_fn = pmgr.apply(
                    "or", hi_fn, _copy_root(mgr, pmgr, item["node"], hi_map, hi_memo)
                )
            lo_action[name] = lo_fn
            hi_action[name] = hi_fn

        # 危险偏序：逐变量的方向约束之合取。
        order_fn = bdd.TRUE
        for i, name in enumerate(order):
            lo_lit = pmgr.mk(lo_map(i), bdd.FALSE, bdd.TRUE)
            hi_lit = pmgr.mk(hi_map(i), bdd.FALSE, bdd.TRUE)
            if directions[name] == DIRECTION_HIGH:
                term = pmgr.apply("or", pmgr.negate(lo_lit), hi_lit)
            else:
                term = pmgr.apply("or", lo_lit, pmgr.negate(hi_lit))
            order_fn = pmgr.apply("and", order_fn, term)

        # 降级反例：α 命中高等级动作 a、β 命中低等级动作 b，且 α ≤d β。
        # 不同 (a,b) 的关系两两不交（每侧赋值命中唯一动作），并集可精确计数。
        violating_fn = bdd.FALSE
        for hi_level_action in actions:
            for lo_level_action in actions:
                if levels[hi_level_action] <= levels[lo_level_action]:
                    continue
                pair_fn = pmgr.apply(
                    "and", lo_action[hi_level_action], hi_action[lo_level_action]
                )
                pair_fn = pmgr.apply("and", pair_fn, order_fn)
                violating_fn = pmgr.apply("or", violating_fn, pair_fn)
        violating_pairs = pmgr.sat_count(violating_fn)

        counterexample = None
        if violating_pairs:
            # 首解优先级：低危险侧 α 全部变量（ASCII、假先于真），再高危险侧 β。
            priority = [lo_map(i) for i in range(n)] + [hi_map(i) for i in range(n)]
            raw = pmgr.first_assignment_by_priority(violating_fn, priority)
            less_assignment = {name: raw[f"@lo/{name}"] for name in order}
            more_assignment = {name: raw[f"@hi/{name}"] for name in order}

            def side(assignment: dict[str, bool]) -> dict:
                hit = [item for item in compiled if mgr.evaluate(item["node"], assignment)]
                hit_actions = {item["action"] for item in hit}
                # 无空洞/无重叠前提保证命中动作恰好一个。
                assert len(hit_actions) == 1
                action = next(iter(hit_actions))
                return {
                    "assignment": assignment,
                    "action": action,
                    "level": levels[action],
                    "rules": sorted(item["id"] for item in hit),
                }

            less = side(less_assignment)
            more = side(more_assignment)
            counterexample = {"less_dangerous": less, "more_dangerous": more}

        # 通过时每个动作等级的规范覆盖摘要。
        coverage_summary = []
        for name in actions:
            root = action_fn[name]
            count = mgr.sat_count(root)
            coverage_summary.append(
                {
                    "level": levels[name],
                    "action": name,
                    "rules": sorted(item["id"] for item in compiled if item["action"] == name),
                    "assignments": count,
                    "assignments_text": str(count),
                    "nodes": mgr.reachable_count(root),
                    "first": mgr.first_assignment(root),
                }
            )
        coverage_summary.sort(key=lambda row: row["level"])
    except bdd.ComplexityError as exc:
        return {"ok": False, "errors": [_error("complexity", f"表达式规模超出裁决预算：{exc}")]}

    ordered_pairs = 3 ** n  # 每变量 (假,假)/(假,真)/(真,真) 或其镜像，恰 3^N 个可比对
    if violating_pairs == 0:
        verdict = "PASS"
        conclusion = (
            f"单调结论：全部 {ordered_pairs} 个满足危险偏序的赋值对（3^{n}）均已精确检验，"
            "危险程度上升时裁决等级单调不降，无降级反例。"
        )
    else:
        verdict = "FAIL"
        less = counterexample["less_dangerous"]
        more = counterexample["more_dangerous"]
        conclusion = (
            f"单调结论：发现 {violating_pairs} 个降级赋值对（共检验 {ordered_pairs} = 3^{n} 个偏序赋值对）。"
            f"首个反例：低危险赋值（{_format_assignment(less['assignment'])}）命中动作 "
            f"{less['action']}（等级 {less['level']}，规则 {', '.join(less['rules'])}）；"
            f"更危险赋值（{_format_assignment(more['assignment'])}）命中动作 "
            f"{more['action']}（等级 {more['level']}，规则 {', '.join(more['rules'])}），"
            f"等级 {less['level']} → {more['level']} 为降级。"
        )

    return {
        "ok": True,
        "errors": [],
        "monotonicity": verdict,
        "variable_order": order,
        "directions": {name: directions[name] for name in order},
        "levels": {name: levels[name] for name in actions},
        "ordered_pairs": ordered_pairs,
        "ordered_pairs_text": str(ordered_pairs),
        "violating_pairs": violating_pairs,
        "violating_pairs_text": str(violating_pairs),
        "counterexample": counterexample,
        "coverage": coverage_summary,
        "conclusion": conclusion,
    }
