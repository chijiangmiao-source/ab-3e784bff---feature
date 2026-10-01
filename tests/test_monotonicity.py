import itertools
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app import bdd, monotonicity, parser


def rule(rid, action, condition):
    return {"id": rid, "action": action, "condition": condition}


def brute_force_oracle(variables, rules, directions, levels):
    """穷举预言机：枚举全部 2^N 赋值与全部 α≤d β 赋值对。

    返回 (违规对数, 首个反例)；首个按 α 字典序、再 β 字典序（假先于真）。
    """
    order = sorted(variables)
    mgr = bdd.Manager(order)
    compiled = [(r["id"], r["action"], mgr.build(parser.parse(r["condition"]))) for r in rules]

    def action_of(assignment):
        hit = [a for _, a, node in compiled if mgr.evaluate(node, assignment)]
        return hit[0] if len(set(hit)) == 1 else None

    def le(less, more):
        for name in order:
            lo, hi = less[name], more[name]
            if directions[name] == "high":
                if lo and not hi:
                    return False
            else:
                if not lo and hi:
                    return False
        return True

    def table(bits):
        return dict(zip(order, bits))

    assignments = [table(bits) for bits in itertools.product([False, True], repeat=len(order))]
    violations = 0
    first = None
    for alpha in assignments:
        for beta in assignments:
            if not le(alpha, beta):
                continue
            a_action = action_of(alpha)
            b_action = action_of(beta)
            if a_action is not None and b_action is not None and levels[a_action] > levels[b_action]:
                violations += 1
                if first is None:
                    first = (alpha, beta, a_action, b_action)
    return violations, first


class MonotonicityPassTest(unittest.TestCase):
    def test_monotone_design_passes(self):
        # armed 真更危险、safe 假更危险；armed 触发 alarm(2)，否则 hold(1)。
        result = monotonicity.monotonicity(
            ["armed", "safe"],
            [rule("R1", "hold", "!armed"), rule("R2", "alarm", "armed")],
            {"armed": "high", "safe": "low"},
            {"hold": 1, "alarm": 2},
        )
        self.assertTrue(result["ok"], result.get("errors"))
        self.assertEqual(result["monotonicity"], "PASS")
        self.assertEqual(result["ordered_pairs"], 3 ** 2)
        self.assertEqual(result["violating_pairs"], 0)
        self.assertIsNone(result["counterexample"])
        # 通过时给出每个动作等级的规范覆盖摘要，按等级排序。
        self.assertEqual([row["action"] for row in result["coverage"]], ["hold", "alarm"])
        self.assertEqual([row["level"] for row in result["coverage"]], [1, 2])
        self.assertEqual(sum(row["assignments"] for row in result["coverage"]), 4)
        self.assertIn("3^2", result["conclusion"])

    def test_single_assignment_space_passes(self):
        # safe 真值更危险：safe=false→hold(1)，safe=true→alarm(2)，单调上升。
        result = monotonicity.monotonicity(
            ["safe"],
            [rule("R1", "hold", "!safe"), rule("R2", "alarm", "safe")],
            {"safe": "high"},
            {"hold": 1, "alarm": 2},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["monotonicity"], "PASS")
        self.assertEqual(result["ordered_pairs"], 3)
        self.assertEqual(result["violating_pairs"], 0)


class MonotonicityCounterexampleTest(unittest.TestCase):
    def test_level_inversion_reports_first_counterexample(self):
        # hold 被赋予比 alarm 更高的等级；armed=true 命中低等级 alarm。
        result = monotonicity.monotonicity(
            ["armed", "safe"],
            [rule("R1", "hold", "!armed"), rule("R2", "alarm", "armed")],
            {"armed": "high", "safe": "low"},
            {"hold": 2, "alarm": 1},
        )
        self.assertTrue(result["ok"], result.get("errors"))
        self.assertEqual(result["monotonicity"], "FAIL")
        ce = result["counterexample"]
        self.assertIsNotNone(ce)
        # 首个低危险侧赋值：armed=false（safe 无关，缺省 false），命中 hold@2；
        # 首个更危险侧赋值沿方向上升：armed=true, safe=false，命中 alarm@1。
        self.assertEqual(ce["less_dangerous"]["assignment"], {"armed": False, "safe": False})
        self.assertEqual(ce["less_dangerous"]["action"], "hold")
        self.assertEqual(ce["less_dangerous"]["level"], 2)
        self.assertEqual(ce["less_dangerous"]["rules"], ["R1"])
        # α=(F,F) 固定后，β 字典序首个为 (armed=T, safe=F)：armed 沿 high 方向上升，
        # safe 取相等（假先于真）；(T,T) 反而违反 safe 的“假更危险”偏序。
        self.assertEqual(ce["more_dangerous"]["assignment"], {"armed": True, "safe": False})
        self.assertEqual(ce["more_dangerous"]["action"], "alarm")
        self.assertEqual(ce["more_dangerous"]["level"], 1)
        # α_armed=F、β_armed=T 固定；safe 为 low 方向，(α_safe,β_safe) 有
        # (F,F)/(T,F)/(T,T) 三种合法组合，共 3 个降级对。
        self.assertEqual(result["violating_pairs"], 3)

    def test_low_direction_counterexample(self):
        # x“假更危险”：x 命中的动作若等级高于 !x 命中的动作，
        # 则 α=(true)→β=(false) 的危险上升构成降级。
        result = monotonicity.monotonicity(
            ["x"],
            [rule("R1", "act_true", "x"), rule("R2", "act_false", "!x")],
            {"x": "low"},
            {"act_true": 2, "act_false": 1},
        )
        self.assertEqual(result["monotonicity"], "FAIL")
        ce = result["counterexample"]
        self.assertEqual(ce["less_dangerous"]["assignment"], {"x": True})
        self.assertEqual(ce["more_dangerous"]["assignment"], {"x": False})
        self.assertEqual(ce["less_dangerous"]["action"], "act_true")
        self.assertEqual(ce["more_dangerous"]["action"], "act_false")
        self.assertEqual(result["violating_pairs"], 1)


class MonotonicityValidationTest(unittest.TestCase):
    BASE_VARS = ["a", "b"]
    BASE_RULES = [rule("R1", "hold", "!a"), rule("R2", "alarm", "a")]

    def check_rejected(self, directions, levels, *kinds):
        result = monotonicity.monotonicity(self.BASE_VARS, self.BASE_RULES, directions, levels)
        self.assertFalse(result["ok"])
        got = {e["kind"] for e in result["errors"]}
        for kind in kinds:
            self.assertIn(kind, got)
        return result

    def test_missing_variable_direction(self):
        self.check_rejected({"a": "high"}, {"hold": 1, "alarm": 2}, "missing_variable_direction")

    def test_unknown_variable_in_directions(self):
        self.check_rejected(
            {"a": "high", "b": "low", "ghost": "high"},
            {"hold": 1, "alarm": 2},
            "unknown_variable",
        )

    def test_invalid_direction_value(self):
        self.check_rejected(
            {"a": "up", "b": "low"}, {"hold": 1, "alarm": 2}, "invalid_direction"
        )

    def test_missing_action_level(self):
        self.check_rejected({"a": "high", "b": "low"}, {"hold": 1}, "missing_action_level")

    def test_unknown_action_in_levels(self):
        self.check_rejected(
            {"a": "high", "b": "low"},
            {"hold": 1, "alarm": 2, "ghost": 3},
            "unknown_action",
        )

    def test_duplicate_levels(self):
        self.check_rejected(
            {"a": "high", "b": "low"}, {"hold": 2, "alarm": 2}, "duplicate_level"
        )

    def test_level_out_of_range(self):
        self.check_rejected(
            {"a": "high", "b": "low"}, {"hold": 0, "alarm": 5}, "invalid_level"
        )

    def test_holes_block_monotonicity(self):
        result = monotonicity.monotonicity(
            ["a"], [rule("R1", "hold", "a")], {"a": "high"}, {"hold": 1}
        )
        self.assertFalse(result["ok"])
        self.assertIn("coverage_incomplete", {e["kind"] for e in result["errors"]})

    def test_overlap_blocks_monotonicity(self):
        result = monotonicity.monotonicity(
            ["a"],
            [rule("R1", "hold", "a"), rule("R2", "alarm", "a | !a")],
            {"a": "high"},
            {"hold": 1, "alarm": 2},
        )
        self.assertFalse(result["ok"])
        self.assertIn("coverage_incomplete", {e["kind"] for e in result["errors"]})

    def test_rule_errors_still_surfaced(self):
        result = monotonicity.monotonicity(
            ["a"],
            [rule("R1", "hold", "ghost")],
            {"a": "high"},
            {"hold": 1},
        )
        self.assertFalse(result["ok"])
        self.assertIn("unknown_variable", {e["kind"] for e in result["errors"]})


class OracleComparisonTest(unittest.TestCase):
    """小规模随机/固定用例：引擎结论必须与逐对枚举预言机完全一致。"""

    def _assert_matches_oracle(self, variables, rules, directions, levels):
        result = monotonicity.monotonicity(variables, rules, directions, levels)
        self.assertTrue(result["ok"], result.get("errors"))
        count, first = brute_force_oracle(variables, rules, directions, levels)
        self.assertEqual(result["violating_pairs"], count)
        if count == 0:
            self.assertEqual(result["monotonicity"], "PASS")
            self.assertIsNone(result["counterexample"])
        else:
            self.assertEqual(result["monotonicity"], "FAIL")
            ce = result["counterexample"]
            alpha, beta, a_action, b_action = first
            self.assertEqual(ce["less_dangerous"]["assignment"], alpha)
            self.assertEqual(ce["more_dangerous"]["assignment"], beta)
            self.assertEqual(ce["less_dangerous"]["action"], a_action)
            self.assertEqual(ce["more_dangerous"]["action"], b_action)

    def test_partition_into_three_actions(self):
        # a 把空间一分为二，b 再在 !a 一侧细分：三个互不相交且全覆盖的区域。
        rules = [
            rule("R1", "low_act", "!a & !b"),
            rule("R2", "mid_act", "!a & b"),
            rule("R3", "high_act", "a"),
        ]
        levels = {"low_act": 1, "mid_act": 2, "high_act": 3}
        # 单调：两个变量都真更危险。
        self._assert_matches_oracle(["a", "b"], rules, {"a": "high", "b": "high"}, levels)
        # 倒置最高/最低：与预言机的违规数与首个反例一致。
        self._assert_matches_oracle(
            ["a", "b"], rules, {"a": "high", "b": "high"},
            {"low_act": 3, "mid_act": 2, "high_act": 1},
        )
        # 混合方向 + 另一组等级。
        self._assert_matches_oracle(
            ["a", "b"], rules, {"a": "low", "b": "high"},
            {"low_act": 2, "mid_act": 1, "high_act": 3},
        )

    def test_all_direction_and_level_permutations_three_vars(self):
        # 固定划分：按三位格雷式前缀划分 8 个赋值；对照所有方向组合（2^3）。
        variables = ["a", "b", "c"]
        rules = [
            rule("R1", "x0", "!a & !b & !c"),
            rule("R2", "x1", "!a & !b & c"),
            rule("R3", "x2", "!a & b & !c"),
            rule("R4", "x3", "!a & b & c"),
            rule("R5", "x4", "a & !b & !c"),
            rule("R6", "x5", "a & !b & c"),
            rule("R7", "x6", "a & b & !c"),
            rule("R8", "x7", "a & b & c"),
        ]
        level_perm = {"x0": 1, "x1": 2, "x2": 3, "x3": 4, "x4": 5, "x5": 6, "x6": 7, "x7": 8}
        for bits in itertools.product(("high", "low"), repeat=3):
            directions = dict(zip(variables, bits))
            self._assert_matches_oracle(variables, rules, directions, level_perm)

    def test_constant_action_is_vacuously_monotone(self):
        # 全覆盖单一动作：任何等级配置下都应通过，且与预言机一致。
        self._assert_matches_oracle(
            ["a", "b"],
            [rule("R1", "hold", "a | !a"), rule("R2", "hold", "b & !b | a | !a")],
            {"a": "high", "b": "low"},
            {"hold": 1},
        )


if __name__ == "__main__":
    unittest.main()
