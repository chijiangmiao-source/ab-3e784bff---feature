import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app import parser


class TokenizeTest(unittest.TestCase):
    def test_operators_and_idents(self):
        kinds = [t.kind for t in parser.tokenize("!a & b_2 | (c) && d || e")]
        self.assertEqual(
            kinds,
            ["NOT", "IDENT", "AND", "IDENT", "OR", "LPAREN", "IDENT",
             "RPAREN", "AND", "IDENT", "OR", "IDENT"],
        )

    def test_illegal_character(self):
        with self.assertRaises(parser.ParseError):
            parser.tokenize("a $ b")


class ParseTest(unittest.TestCase):
    def test_precedence_not_and_or(self):
        # !a & b | c  =>  or(and(not(a), b), c)
        ast = parser.parse("!a & b | c")
        self.assertEqual(ast[0], "or")
        self.assertEqual(ast[1], ("and", ("not", ("var", "a")), ("var", "b")))
        self.assertEqual(ast[2], ("var", "c"))

    def test_parentheses_override(self):
        ast = parser.parse("a & (b | !c)")
        self.assertEqual(ast[0], "and")
        self.assertEqual(ast[2][0], "or")

    def test_double_negation(self):
        self.assertEqual(parser.parse("!!a"), ("not", ("not", ("var", "a"))))

    def test_empty_condition(self):
        with self.assertRaises(parser.ParseError):
            parser.parse("   ")

    def test_trailing_operator_is_incomplete(self):
        with self.assertRaises(parser.ParseError) as ctx:
            parser.parse("a &")
        self.assertIn("不完整", str(ctx.exception))

    def test_unbalanced_paren(self):
        with self.assertRaises(parser.ParseError) as ctx:
            parser.parse("(a | b")
        self.assertIn(")", str(ctx.exception))

    def test_empty_parens(self):
        with self.assertRaises(parser.ParseError):
            parser.parse("a & ()")

    def test_trailing_tokens(self):
        with self.assertRaises(parser.ParseError):
            parser.parse("a b")

    def test_collect_vars(self):
        ast = parser.parse("x & !y | (z & x)")
        self.assertEqual(parser.collect_vars(ast), ["x", "y", "z"])


if __name__ == "__main__":
    unittest.main()
