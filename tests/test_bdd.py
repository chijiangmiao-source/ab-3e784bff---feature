import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app import bdd
from app.parser import parse


class ManagerTest(unittest.TestCase):
    def setUp(self):
        self.mgr = bdd.Manager(["a", "b", "c"])  # 已按 ASCII 排序

    def build(self, text):
        return self.mgr.build(parse(text))

    def test_canonical_sharing(self):
        # 同一函数在同一变量序下得到同一规范节点
        self.assertEqual(self.build("a & b"), self.build("a & b"))
        self.assertEqual(self.build("a & !!b"), self.build("a & b"))

    def test_de_morgan_canonical(self):
        self.assertEqual(self.build("!(a | b)"), self.build("!a & !b"))

    def test_sat_count_exact(self):
        self.assertEqual(self.mgr.sat_count(self.build("a")), 4)          # 2^2
        self.assertEqual(self.mgr.sat_count(self.build("a & b")), 2)      # c 任意
        self.assertEqual(self.mgr.sat_count(self.build("a | b")), 6)
        self.assertEqual(self.mgr.sat_count(bdd.FALSE), 0)
        self.assertEqual(self.mgr.sat_count(bdd.TRUE), 8)

    def test_first_assignment_prefers_false(self):
        first = self.mgr.first_assignment(self.build("a | b"))
        self.assertEqual(first, {"a": False, "b": True, "c": False})

    def test_first_assignment_none_for_false(self):
        self.assertIsNone(self.mgr.first_assignment(bdd.FALSE))

    def test_first_assignment_skips_irrelevant_vars(self):
        first = self.mgr.first_assignment(self.build("c"))
        self.assertEqual(first, {"a": False, "b": False, "c": True})

    def test_evaluate(self):
        node = self.build("a & !b")
        self.assertTrue(self.mgr.evaluate(node, {"a": True, "b": False, "c": True}))
        self.assertFalse(self.mgr.evaluate(node, {"a": True, "b": True, "c": False}))

    def test_reachable_count(self):
        self.assertEqual(self.mgr.reachable_count(self.build("a")), 3)  # 根 + 两个终端
        self.assertEqual(self.mgr.reachable_count(bdd.TRUE), 1)

    def test_ascii_order_respected(self):
        # 变量表由调用方按 ASCII 排序给出："Z" < "a"（大写先于小写）
        mgr = bdd.Manager(sorted(["a", "Z"]))
        node = mgr.build(parse("Z"))
        first = mgr.first_assignment(node)
        self.assertEqual(list(first), ["Z", "a"])
        self.assertEqual(first, {"Z": True, "a": False})


if __name__ == "__main__":
    unittest.main()
