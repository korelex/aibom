"""The tolerant JSON reader: what editors accept (comments, trailing commas), exact line numbers, and refusal of bad input."""
import json
import unittest

from aibom_engine import jsonc


class Values(unittest.TestCase):
    def test_it_reads_everything_json_has(self):
        text = '{"a": [1, -2, 3.5, 1e3, -0.25E-2, true, false, null, "x"], "b": {"c": {}}, "d": []}'
        self.assertEqual(jsonc.loads(text), json.loads(text))

    def test_strings_keep_their_escapes_and_comment_markers(self):
        text = r'{"url": "http://host//path", "c": "/* not a comment */", "q": "say \"hi\"", "u": "é 😀", "t": "a\tb"}'
        self.assertEqual(jsonc.loads(text), json.loads(text))

    def test_numbers_and_big_values(self):
        self.assertEqual(jsonc.loads("123456789012345678901234567890"), 123456789012345678901234567890)
        self.assertEqual(jsonc.loads("[0, -0, 0.5]"), [0, 0, 0.5])

    def test_a_byte_order_mark_and_surrounding_space_are_ignored(self):
        self.assertEqual(jsonc.loads("﻿  \n {\"a\": 1} \n "), {"a": 1})

    def test_a_scalar_at_the_top_is_fine(self):
        self.assertEqual(jsonc.loads(" true "), True)
        self.assertEqual(jsonc.loads('"s"'), "s")


class Tolerance(unittest.TestCase):
    def test_line_and_block_comments_anywhere(self):
        text = '''// top
{ /* before key */ "a": 1, // after value
  /* multi
     line */ "b": [1, /* inside */ 2], // end
}
// bottom'''
        self.assertEqual(jsonc.loads(text), {"a": 1, "b": [1, 2]})

    def test_trailing_commas_in_objects_and_lists(self):
        self.assertEqual(jsonc.loads('{"a": [1, 2,], "b": {"c": 3,},}'), {"a": [1, 2], "b": {"c": 3}})

    def test_a_comment_at_the_very_end_without_a_newline(self):
        self.assertEqual(jsonc.loads('{"a": 1} // done'), {"a": 1})


class Lines(unittest.TestCase):
    def test_each_key_knows_its_line_even_after_comments_and_blank_lines(self):
        text = '''{
  // a comment
  "one": 1,

  /* a block
     comment */
  "two": {
    "inner": 2
  },
  "three": [
    {"deep": 3}
  ]
}'''
        v = jsonc.loads(text)
        self.assertEqual(v.lines, {"one": 3, "two": 7, "three": 10})
        self.assertEqual(v["two"].lines, {"inner": 8})
        self.assertEqual(v["three"][0].lines, {"deep": 11})

    def test_windows_line_endings_count_once(self):
        v = jsonc.loads('{\r\n"a": 1,\r\n"b": 2\r\n}')
        self.assertEqual(v.lines, {"a": 2, "b": 3})

    def test_a_key_after_a_multi_line_string_value_is_on_the_right_line(self):
        v = jsonc.loads('{"a": "x", "b": "y",\n"c": 3}')
        self.assertEqual(v.lines, {"a": 1, "b": 1, "c": 2})

    def test_a_repeated_key_keeps_the_last_value_and_its_line(self):
        v = jsonc.loads('{"a": 1,\n"a": 2}')
        self.assertEqual((v["a"], v.lines["a"]), (2, 2))

    def test_objects_are_dicts(self):
        self.assertIsInstance(jsonc.loads("{}"), dict)
        self.assertEqual(jsonc.loads("{}").lines, {})


class Refusals(unittest.TestCase):
    def bad(self, text, line=None):
        with self.assertRaises(jsonc.JsoncError) as ctx:
            jsonc.loads(text)
        if line is not None:
            self.assertEqual(ctx.exception.line, line, text)
        self.assertIsInstance(ctx.exception, ValueError)

    def test_broken_files_name_the_line(self):
        self.bad('{"a" 1}', 1)
        self.bad('{"a": 1\n"b": 2}', 2)
        self.bad('{\n"a": 1\n', 3)
        self.bad('[1, 2', 1)
        self.bad('{"a": 1} x', 1)
        self.bad('{a: 1}', 1)
        self.bad('{"a": 1,, "b": 2}', 1)
        self.bad('/* never closed', 1)
        self.bad('{"a": }', 1)
        self.bad('{"a": "unterminated}', 1)
        self.bad("", 1)
        self.bad("   // only a comment", 1)

    def test_invalid_numbers_and_words_are_refused(self):
        for text in ("nan", "[Infinity]", "[01]", "[1.]", "[+1]", "{'a': 1}", "[undefined]"):
            self.bad(text)

    def test_a_deeply_nested_file_is_refused_without_crashing(self):
        self.bad("[" * 10000)
        self.bad('{"a":' * 5000)

    def test_a_long_flat_file_is_not_slow_or_refused(self):
        text = "[" + ",".join(str(i) for i in range(200000)) + "]"
        self.assertEqual(len(jsonc.loads(text)), 200000)


if __name__ == "__main__":
    unittest.main()
