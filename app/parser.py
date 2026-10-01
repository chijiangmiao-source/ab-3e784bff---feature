"""布尔条件表达式的词法与语法分析。

文法（优先级自低到高：或、与、非）::

    expr     := or_expr
    or_expr  := and_expr (("|" | "||") and_expr)*
    and_expr := unary    (("&" | "&&") unary)*
    unary    := "!" unary | "(" expr ")" | IDENT

标识符形如 ``[A-Za-z_][A-Za-z0-9_]*``。解析器对每条规则报告其首个语法
错误；跨规则的错误聚合由 :mod:`app.audit` 负责。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

MAX_CONDITION_LEN = 4096


@dataclass(frozen=True)
class Token:
    kind: str  # IDENT / NOT / AND / OR / LPAREN / RPAREN
    text: str
    pos: int


class ParseError(Exception):
    """单个条件表达式内的语法错误。"""

    def __init__(self, message: str, pos: int):
        super().__init__(message)
        self.message = message
        self.pos = pos


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "!":
            tokens.append(Token("NOT", c, i))
            i += 1
        elif c == "&":
            if text[i : i + 2] == "&&":
                tokens.append(Token("AND", "&&", i))
                i += 2
            else:
                tokens.append(Token("AND", "&", i))
                i += 1
        elif c == "|":
            if text[i : i + 2] == "||":
                tokens.append(Token("OR", "||", i))
                i += 2
            else:
                tokens.append(Token("OR", "|", i))
                i += 1
        elif c == "(":
            tokens.append(Token("LPAREN", c, i))
            i += 1
        elif c == ")":
            tokens.append(Token("RPAREN", c, i))
            i += 1
        elif c.isalpha() and c.isascii() or c == "_":
            m = IDENT_RE.match(text, i)
            tokens.append(Token("IDENT", m.group(0), i))
            i = m.end()
        else:
            raise ParseError(f"非法字符 {c!r}", i)
    return tokens


# AST 节点：("var", name) | ("not", a) | ("and", a, b) | ("or", a, b)


def parse(text: str):
    """把条件文本解析为 AST；语法错误抛出 :class:`ParseError`。"""
    if len(text) > MAX_CONDITION_LEN:
        raise ParseError(f"条件长度超过 {MAX_CONDITION_LEN} 字符上限", 0)
    tokens = tokenize(text)
    if not tokens:
        raise ParseError("条件为空", 0)
    return _Parser(tokens).run()


class _Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def run(self):
        node = self.parse_or()
        rest = self._peek()
        if rest is not None:
            raise ParseError(f"表达式结束后存在多余记号 {rest.text!r}", rest.pos)
        return node

    def _peek(self) -> Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _advance(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse_or(self):
        node = self.parse_and()
        while self._peek() is not None and self._peek().kind == "OR":
            self._advance()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_unary()
        while self._peek() is not None and self._peek().kind == "AND":
            self._advance()
            node = ("and", node, self.parse_unary())
        return node

    def parse_unary(self):
        tok = self._peek()
        if tok is None:
            raise ParseError("表达式不完整：此处应为变量、'!' 或 '('", self.tokens[-1].pos + len(self.tokens[-1].text))
        if tok.kind == "NOT":
            self._advance()
            return ("not", self.parse_unary())
        if tok.kind == "LPAREN":
            self._advance()
            nxt = self._peek()
            if nxt is not None and nxt.kind == "RPAREN":
                raise ParseError("空括号：括号内缺少条件", nxt.pos)
            node = self.parse_or()
            closing = self._peek()
            if closing is None:
                raise ParseError("括号不配对：缺少 ')'", self.tokens[-1].pos + len(self.tokens[-1].text))
            if closing.kind != "RPAREN":
                raise ParseError(f"括号不配对：此处应为 ')' 而非 {closing.text!r}", closing.pos)
            self._advance()
            return node
        if tok.kind == "IDENT":
            self._advance()
            return ("var", tok.text)
        raise ParseError(f"此处应为变量、'!' 或 '('，而非 {tok.text!r}", tok.pos)


def collect_vars(ast) -> list[str]:
    """按出现顺序收集 AST 中引用的全部变量（去重）。"""
    seen: dict[str, None] = {}

    def walk(node):
        kind = node[0]
        if kind == "var":
            seen.setdefault(node[1])
        elif kind == "not":
            walk(node[1])
        else:
            walk(node[1])
            walk(node[2])

    walk(ast)
    return list(seen)
