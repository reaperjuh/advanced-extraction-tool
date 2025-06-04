import unittest
import argparse # For creating mock args objects

# Functions and constants to be tested from log_analyzer.py
from log_analyzer import parse_log_line, is_log_line_visible, LOG_PRIORITIES

class TestLogAnalyzer(unittest.TestCase):

    def test_parse_log_line_valid_standard(self):
        line = "01-23 10:50:32.123 I/MyApp(12345): This is a log message"
        expected = {'date': '01-23', 'time': '10:50:32.123', 'priority': 'I', 'tag': 'MyApp', 'pid': '12345', 'message': 'This is a log message'}
        self.assertEqual(parse_log_line(line), expected)

    def test_parse_log_line_valid_different_priority_tag_pid(self):
        line = "02-26 13:45:01.456 D/MyCoolTag(54321): My detailed debug message with value 42"
        expected = {'date': '02-26', 'time': '13:45:01.456', 'priority': 'D', 'tag': 'MyCoolTag', 'pid': '54321', 'message': 'My detailed debug message with value 42'}
        self.assertEqual(parse_log_line(line), expected)

    def test_parse_log_line_valid_complex_message(self):
        line = "03-10 08:22:05.789 E/AndroidRuntime(9876): FATAL EXCEPTION: main\nProcess: com.example, PID: 9876"
        expected = {'date': '03-10', 'time': '08:22:05.789', 'priority': 'E', 'tag': 'AndroidRuntime', 'pid': '9876', 'message': 'FATAL EXCEPTION: main\nProcess: com.example, PID: 9876'}
        self.assertEqual(parse_log_line(line), expected)

    def test_parse_log_line_pid_with_spaces(self):
        line = "01-23 10:50:32.123 I/MyApp(  123  ): Message"
        expected = {'date': '01-23', 'time': '10:50:32.123', 'priority': 'I', 'tag': 'MyApp', 'pid': '123', 'message': 'Message'}
        self.assertEqual(parse_log_line(line), expected)

    def test_parse_log_line_malformed_no_priority(self):
        line = "01-23 10:50:32.123 /MyApp(12345): This is a log message"
        self.assertIsNone(parse_log_line(line))

    def test_parse_log_line_malformed_no_pid(self):
        line = "01-23 10:50:32.123 I/MyApp: This is a log message"
        self.assertIsNone(parse_log_line(line))

    def test_parse_log_line_empty_line(self):
        line = ""
        self.assertIsNone(parse_log_line(line))

    def test_parse_log_line_for_all_priorities(self):
        priorities = ['V', 'D', 'I', 'W', 'E', 'F']
        for prio in priorities:
            line = f"01-01 00:00:00.000 {prio}/TestTag(1000): Test message for priority {prio}"
            parsed = parse_log_line(line)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed['priority'], prio)

    # --- Tests for is_log_line_visible ---

    def setUp_args(self):
        """Helper to create a default args object."""
        return argparse.Namespace(
            min_priority=None,
            tag=None,
            pid=None,
            keyword=None,
            # These are not used by is_log_line_visible but might be in args
            input_file=None,
            output_csv=None,
            output_json=None,
            highlight_keyword=None
        )

    def test_visibility_no_filters(self):
        args = self.setUp_args()
        parsed_log = {'priority': 'I', 'tag': 'Test', 'pid': '123', 'message': 'Hello'}
        self.assertTrue(is_log_line_visible(parsed_log, args))

    def test_visibility_priority_filter_pass(self):
        args = self.setUp_args()
        args.min_priority = 'I'
        parsed_log_i = {'priority': 'I', 'tag': 'Test', 'pid': '123', 'message': 'Info'}
        parsed_log_w = {'priority': 'W', 'tag': 'Test', 'pid': '123', 'message': 'Warning'}
        self.assertTrue(is_log_line_visible(parsed_log_i, args))
        self.assertTrue(is_log_line_visible(parsed_log_w, args))

    def test_visibility_priority_filter_fail(self):
        args = self.setUp_args()
        args.min_priority = 'W'
        parsed_log_d = {'priority': 'D', 'tag': 'Test', 'pid': '123', 'message': 'Debug'}
        self.assertFalse(is_log_line_visible(parsed_log_d, args))

    def test_visibility_tag_filter_pass(self):
        args = self.setUp_args()
        args.tag = ['MyApp', 'OtherApp']
        parsed_log = {'priority': 'I', 'tag': 'MyApp', 'pid': '123', 'message': 'Hello'}
        self.assertTrue(is_log_line_visible(parsed_log, args))

    def test_visibility_tag_filter_fail(self):
        args = self.setUp_args()
        args.tag = ['MyApp']
        parsed_log = {'priority': 'I', 'tag': 'AnotherApp', 'pid': '123', 'message': 'Hello'}
        self.assertFalse(is_log_line_visible(parsed_log, args))

    def test_visibility_pid_filter_pass(self):
        args = self.setUp_args()
        args.pid = ['123', '456']
        parsed_log = {'priority': 'I', 'tag': 'Test', 'pid': '123', 'message': 'Hello'}
        self.assertTrue(is_log_line_visible(parsed_log, args))

    def test_visibility_pid_filter_fail(self):
        args = self.setUp_args()
        args.pid = ['789']
        parsed_log = {'priority': 'I', 'tag': 'Test', 'pid': '123', 'message': 'Hello'}
        self.assertFalse(is_log_line_visible(parsed_log, args))

    def test_visibility_keyword_filter_pass(self):
        args = self.setUp_args()
        args.keyword = ['Error', 'Important']
        parsed_log = {'priority': 'W', 'tag': 'System', 'pid': '100', 'message': 'This is an important message.'}
        self.assertTrue(is_log_line_visible(parsed_log, args))
        parsed_log_case = {'priority': 'E', 'tag': 'System', 'pid': '100', 'message': 'An ERROR occurred.'}
        self.assertTrue(is_log_line_visible(parsed_log_case, args))

    def test_visibility_keyword_filter_fail(self):
        args = self.setUp_args()
        args.keyword = ['Critical']
        parsed_log = {'priority': 'I', 'tag': 'Test', 'pid': '123', 'message': 'Just a normal message.'}
        self.assertFalse(is_log_line_visible(parsed_log, args))

    def test_visibility_all_filters_pass(self):
        args = self.setUp_args()
        args.min_priority = 'W'
        args.tag = ['System']
        args.pid = ['1000']
        args.keyword = ['alert']
        parsed_log = {'priority': 'W', 'tag': 'System', 'pid': '1000', 'message': 'System alert: check status.'}
        self.assertTrue(is_log_line_visible(parsed_log, args))

    def test_visibility_some_filters_fail(self):
        args = self.setUp_args()
        args.min_priority = 'I'
        args.tag = ['MyApp']
        args.keyword = ['success']
        # Fails on tag
        parsed_log = {'priority': 'I', 'tag': 'OtherApp', 'pid': '123', 'message': 'Operation was a success!'}
        self.assertFalse(is_log_line_visible(parsed_log, args))
        # Fails on keyword
        parsed_log_2 = {'priority': 'I', 'tag': 'MyApp', 'pid': '123', 'message': 'Operation pending.'}
        self.assertFalse(is_log_line_visible(parsed_log_2, args))
        # Fails on priority
        parsed_log_3 = {'priority': 'D', 'tag': 'MyApp', 'pid': '123', 'message': 'Debug success details.'}
        self.assertFalse(is_log_line_visible(parsed_log_3, args))

    def test_visibility_parsed_log_none(self):
        args = self.setUp_args()
        self.assertFalse(is_log_line_visible(None, args))


if __name__ == '__main__':
    unittest.main()
