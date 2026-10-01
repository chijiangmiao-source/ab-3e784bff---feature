"""规则审计：单遍校验与全赋值空间的精确空洞/重叠裁决。

校验阶段一次性汇总全部问题（非法标识、重复标识、未知变量、空条件、
空动作、残缺语法、数量超限），不做短路返回。裁决阶段在按变量标识
ASCII 升序固定的 ROBDD 上进行，对全部 2^N 个赋值精确有效。
"""
from __future__ import annotations

import re

from . import bdd, parser

MAX_VARIABLES = 64
MAX_RULES = 96
MAX_IDENT_LEN = 64
MAX_ACTION_LEN = 64

IDENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _error(kind: str, message: str, **ctx) -> dict:
    err = {"kind": kind, "message": message}
    err.update(ctx)
    return err


def validate(variables, rules) -> list[dict]:
    """单遍收集全部录入错误；返回错误列表（为空表示录入合法）。"""
    errors: list[dict] = []

    if not isinstance(variables, list) or any(not isinstance(v, str) for v in variables):
        return [_error("invalid_payload", "variables 必须为字符串数组")]
    if not isinstance(rules, list):
        return [_error("invalid_payload", "rules 必须为对象数组")]

    if len(variables) > MAX_VARIABLES:
        errors.append(
            _error(
                "too_many_variables",
                f"变量数为 {len(variables)}，超过上限 {MAX_VARIABLES}",
                count=len(variables),
                limit=MAX_VARIABLES,
            )
        )
    if len(rules) > MAX_RULES:
        errors.append(
            _error(
                "too_many_rules",
                f"规则数为 {len(rules)}，超过上限 {MAX_RULES}",
                count=len(rules),
                limit=MAX_RULES,
            )
        )

    declared: set[str] = set()
    for name in variables:
        if not IDENT_PATTERN.match(name) or len(name) > MAX_IDENT_LEN:
            errors.append(
                _error(
                    "illegal_identifier",
                    f"非法变量标识 {name!r}：须匹配 [A-Za-z_][A-Za-z0-9_]* 且不超过 {MAX_IDENT_LEN} 字符",
                    identifier=name,
                )
            )
        elif name in declared:
            errors.append(
                _error("duplicate_variable", f"变量标识 {name!r} 重复", identifier=name)
            )
        else:
            declared.add(name)

    seen_rule_ids: set[str] = set()
    for index, rule in enumerate(rules):
        where = {"rule_index": index}
        if not isinstance(rule, dict):
            errors.append(_error("invalid_payload", f"第 {index + 1} 条规则不是对象", **where))
            continue
        rule_id = rule.get("id")
        action = rule.get("action")
        condition = rule.get("condition")
        if isinstance(rule_id, str) and rule_id:
            where["rule"] = rule_id

        if not isinstance(rule_id, str) or not rule_id:
            errors.append(_error("illegal_identifier", "规则缺少标识 id", **where))
        elif not IDENT_PATTERN.match(rule_id) or len(rule_id) > MAX_IDENT_LEN:
            errors.append(
                _error(
                    "illegal_identifier",
                    f"非法规则标识 {rule_id!r}：须匹配 [A-Za-z_][A-Za-z0-9_]* 且不超过 {MAX_IDENT_LEN} 字符",
                    identifier=rule_id,
                    **where,
                )
            )
        elif rule_id in seen_rule_ids:
            errors.append(
                _error("duplicate_rule_id", f"规则标识 {rule_id!r} 重复", identifier=rule_id, **where)
            )
        else:
            seen_rule_ids.add(rule_id)

        if not isinstance(action, str) or not action.strip():
            errors.append(_error("empty_action", "规则动作名为空", **where))
        elif len(action) > MAX_ACTION_LEN:
            errors.append(
                _error("invalid_action", f"动作名超过 {MAX_ACTION_LEN} 字符上限", **where)
            )

        if not isinstance(condition, str) or not condition.strip():
            errors.append(_error("empty_condition", "规则条件为空", **where))
            continue
        try:
            ast = parser.parse(condition)
        except parser.ParseError as exc:
            errors.append(
                _error(
                    "syntax",
                    f"条件语法残缺：{exc.message}（位置 {exc.pos}）",
                    condition=condition,
                    position=exc.pos,
                    **where,
                )
            )
            continue
        for name in parser.collect_vars(ast):
            if name not in declared:
                errors.append(
                    _error(
                        "unknown_variable",
                        f"条件引用了未声明的变量 {name!r}",
                        identifier=name,
                        condition=condition,
                        **where,
                    )
                )
    return errors


def _format_assignment(assignment: dict[str, bool]) -> str:
    return ", ".join(f"{name}={'true' if value else 'false'}" for name, value in assignment.items())


def audit(variables, rules) -> dict:
    """校验并在合法时执行精确审计；返回可 JSON 序列化的结论。"""
    errors = validate(variables, rules)
    if errors:
        return {"ok": False, "errors": errors}

    order = sorted(variables)  # 变量标识的 ASCII 升序
    mgr = bdd.Manager(order)

    try:
        compiled = []
        for rule in rules:
            ast = parser.parse(rule["condition"])
            node = mgr.build(ast)
            compiled.append(
                {
                    "id": rule["id"],
                    "action": rule["action"].strip(),
                    "node": node,
                    "uses": parser.collect_vars(ast),
                }
            )

        # 空洞：没有任何规则命中的赋值。
        coverage = bdd.FALSE
        for item in compiled:
            coverage = mgr.apply("or", coverage, item["node"])
        holes_fn = mgr.negate(coverage)
        hole_count = mgr.sat_count(holes_fn)
        first_hole = mgr.first_assignment(holes_fn) if hole_count else None

        # 重叠：至少两条不同动作的规则同时命中的赋值。
        actions = sorted({item["action"] for item in compiled})
        action_fn = {}
        for name in actions:
            fn = bdd.FALSE
            for item in compiled:
                if item["action"] == name:
                    fn = mgr.apply("or", fn, item["node"])
            action_fn[name] = fn
        overlap_fn = bdd.FALSE
        for i in range(len(actions)):
            for j in range(i + 1, len(actions)):
                both = mgr.apply("and", action_fn[actions[i]], action_fn[actions[j]])
                overlap_fn = mgr.apply("or", overlap_fn, both)
        overlap_count = mgr.sat_count(overlap_fn)
        first_overlap = mgr.first_assignment(overlap_fn) if overlap_count else None
        overlap_rules = []
        overlap_actions = []
        if first_overlap is not None:
            overlap_rules = sorted(
                item["id"] for item in compiled if mgr.evaluate(item["node"], first_overlap)
            )
            overlap_actions = sorted(
                {item["action"] for item in compiled if mgr.evaluate(item["node"], first_overlap)}
            )
    except bdd.ComplexityError as exc:
        return {
            "ok": False,
            "errors": [_error("complexity", f"表达式规模超出裁决预算：{exc}")],
        }

    verdict = "PASS" if hole_count == 0 and overlap_count == 0 else "FAIL"
    space = 1 << len(order)
    conclusions = []
    if hole_count == 0 and overlap_count == 0:
        conclusions.append(
            f"覆盖结论：全部 2^{len(order)} = {space} 个遥测组合均恰好命中一条动作，无空洞、无重叠。"
        )
    else:
        if hole_count:
            conclusions.append(
                f"空洞：{hole_count} 个赋值未命中任何规则，首个为 {_format_assignment(first_hole)}。"
            )
        if overlap_count:
            conclusions.append(
                f"重叠：{overlap_count} 个赋值同时命中多条动作，首个为 "
                f"{_format_assignment(first_overlap)}，命中规则（按标识排序）："
                f"{', '.join(overlap_rules)}。"
            )

    return {
        "ok": True,
        "errors": [],
        "verdict": verdict,
        "variable_order": order,
        "space": space,
        "space_text": str(space),
        "holes": {"count": hole_count, "count_text": str(hole_count), "first": first_hole},
        "overlaps": {
            "count": overlap_count,
            "count_text": str(overlap_count),
            "first": first_overlap,
            "rules": overlap_rules,
            "actions": overlap_actions,
        },
        "rules": [
            {
                "id": item["id"],
                "action": item["action"],
                "uses": item["uses"],
                "root": item["node"],
                "nodes": mgr.reachable_count(item["node"]),
            }
            for item in compiled
        ],
        "conclusion": "\n".join(conclusions),
    }
