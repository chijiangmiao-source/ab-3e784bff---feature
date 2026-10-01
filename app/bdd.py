"""简约有序二叉决策图（ROBDD）管理器。

变量顺序在构造时固定（调用方传入按标识 ASCII 升序排列的变量表），
因此同一布尔函数在该顺序下具有唯一的规范表示。空洞与重叠的裁决、
"首个赋值"的选取以及各规则的规范节点摘要全部建立在该规范形式上，
不做任何枚举、抽样或有限测试。

节点编号 0 表示常量假，1 表示常量真，其余节点为 (变量层, 低分支, 高分支)。
"""
from __future__ import annotations

FALSE = 0
TRUE = 1

# 节点预算：防止恶意构造的表达式耗尽内存；超出时抛出 ComplexityError，
# 属于资源护栏而非对精确裁决的替代。
NODE_BUDGET = 4_000_000


class ComplexityError(Exception):
    """BDD 规模超出节点预算。"""


class Manager:
    def __init__(self, variables: list[str]):
        self.variables = list(variables)
        self.level = {name: idx for idx, name in enumerate(self.variables)}
        # nodes[i] = (var_level, low, high)；0/1 为终端节点，占位 None。
        self.nodes: list[tuple[int, int, int] | None] = [None, None]
        self.unique: dict[tuple[int, int, int], int] = {}
        self._neg_cache: dict[int, int] = {}

    # ------------------------------------------------------------------ 构造
    def mk(self, var_level: int, low: int, high: int) -> int:
        if low == high:
            return low
        key = (var_level, low, high)
        node = self.unique.get(key)
        if node is None:
            if len(self.nodes) >= NODE_BUDGET:
                raise ComplexityError(f"BDD 节点数超过预算 {NODE_BUDGET}")
            node = len(self.nodes)
            self.nodes.append(key)
            self.unique[key] = node
        return node

    def literal(self, name: str) -> int:
        return self.mk(self.level[name], FALSE, TRUE)

    def negate(self, u: int) -> int:
        if u <= TRUE:
            return TRUE - u
        cached = self._neg_cache.get(u)
        if cached is not None:
            return cached
        var, low, high = self.nodes[u]
        result = self.mk(var, self.negate(low), self.negate(high))
        self._neg_cache[u] = result
        return result

    def apply(self, op: str, a: int, b: int) -> int:
        """op 为 "and" 或 "or"；返回 a OP b 的规范节点。"""
        cache: dict[tuple[int, int], int] = {}
        top = len(self.variables)

        def rec(x: int, y: int) -> int:
            if op == "and":
                if x == FALSE or y == FALSE:
                    return FALSE
                if x == TRUE:
                    return y
                if y == TRUE:
                    return x
            else:
                if x == TRUE or y == TRUE:
                    return TRUE
                if x == FALSE:
                    return y
                if y == FALSE:
                    return x
            if x == y:
                return x
            key = (x, y) if x < y else (y, x)
            hit = cache.get(key)
            if hit is not None:
                return hit
            lx = self.nodes[x][0] if x > TRUE else top
            ly = self.nodes[y][0] if y > TRUE else top
            level = lx if lx < ly else ly
            if lx == level:
                _, xlo, xhi = self.nodes[x]
            else:
                xlo = xhi = x
            if ly == level:
                _, ylo, yhi = self.nodes[y]
            else:
                ylo = yhi = y
            result = self.mk(level, rec(xlo, ylo), rec(xhi, yhi))
            cache[key] = result
            return result

        return rec(a, b)

    def build(self, ast) -> int:
        kind = ast[0]
        if kind == "var":
            return self.literal(ast[1])
        if kind == "not":
            return self.negate(self.build(ast[1]))
        if kind == "and":
            return self.apply("and", self.build(ast[1]), self.build(ast[2]))
        if kind == "or":
            return self.apply("or", self.build(ast[1]), self.build(ast[2]))
        raise ValueError(f"未知 AST 节点：{kind!r}")

    # ------------------------------------------------------------------ 查询
    def reachable_count(self, root: int) -> int:
        """root 的可达节点数（含两个终端），即规范节点摘要。"""
        seen: set[int] = set()
        stack = [root]
        while stack:
            u = stack.pop()
            if u in seen:
                continue
            seen.add(u)
            if u > TRUE:
                _, low, high = self.nodes[u]
                stack.append(low)
                stack.append(high)
        return len(seen)

    def first_assignment(self, root: int) -> dict[str, bool] | None:
        """按变量表顺序、假先于真的字典序求首个满足赋值。

        未出现在路径上的变量取假（确定性的无关项缺省值）。
        root 为常量假时返回 None。
        """
        if root == FALSE:
            return None
        assignment = {name: False for name in self.variables}
        u = root
        while u > TRUE:
            var, low, high = self.nodes[u]
            if low != FALSE:
                u = low
            else:
                assignment[self.variables[var]] = True
                u = high
        return assignment

    def sat_count(self, root: int) -> int:
        """满足赋值在整个变量空间中的精确个数（大整数，非枚举）。"""
        total = len(self.variables)
        memo: dict[tuple[int, int], int] = {}

        def rec(u: int, from_level: int) -> int:
            if u == FALSE:
                return 0
            if u == TRUE:
                return 1 << (total - from_level)
            key = (u, from_level)
            hit = memo.get(key)
            if hit is not None:
                return hit
            var, low, high = self.nodes[u]
            count = (rec(low, var + 1) + rec(high, var + 1)) << (var - from_level)
            memo[key] = count
            return count

        return rec(root, 0)

    def evaluate(self, root: int, assignment: dict[str, bool]) -> bool:
        u = root
        while u > TRUE:
            var, low, high = self.nodes[u]
            u = high if assignment[self.variables[var]] else low
        return u == TRUE
