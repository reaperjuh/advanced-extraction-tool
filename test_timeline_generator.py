import unittest
from unittest.mock import patch, MagicMock, mock_open
import datetime
import os
import argparse
import csv
import json
import io
import sys
import sqlite3 # For sqlite3.Error

# Functions and constants to be tested
from timeline_generator import (
    epoch_seconds_to_utc_datetime,
    epoch_milliseconds_to_utc_datetime,
    webkit_to_utc_datetime,
    logcat_timestamp_to_utc_datetime,
    parse_filesystem_metadata,
    parse_filter_datetime,
    setup_parser,
    parse_sms_mms_db,
    parse_calllog_db,
    parse_chrome_history_db,
    zoneinfo as actual_zoneinfo_module_from_script
)

# Helper to create mock SQLite rows (dictionaries)
def create_mock_row(data_dict):
    return data_dict

class TestTimelineGenerator(unittest.TestCase):

    def test_epoch_seconds_conversion(self):
        target_dt = datetime.datetime(2023, 3, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
        correct_epoch_seconds = target_dt.timestamp()
        self.assertEqual(epoch_seconds_to_utc_datetime(0), datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc))
        self.assertEqual(epoch_seconds_to_utc_datetime(correct_epoch_seconds), target_dt)
        self.assertIsNone(epoch_seconds_to_utc_datetime("invalid_string"))

    def test_epoch_milliseconds_conversion(self):
        target_dt = datetime.datetime(2023, 3, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
        correct_epoch_milliseconds = target_dt.timestamp() * 1000
        self.assertEqual(epoch_milliseconds_to_utc_datetime(0), datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc))
        self.assertEqual(epoch_milliseconds_to_utc_datetime(correct_epoch_milliseconds), target_dt)
        self.assertIsNone(epoch_milliseconds_to_utc_datetime("invalid_string"))

    def test_webkit_conversion(self):
        target_dt = datetime.datetime(2023, 3, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
        webkit_epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        correct_webkit_timestamp = (target_dt - webkit_epoch_start).total_seconds() * 1_000_000
        self.assertEqual(webkit_to_utc_datetime(correct_webkit_timestamp), target_dt)
        self.assertIsNone(webkit_to_utc_datetime("invalid_string"))

    @patch('timeline_generator.zoneinfo')
    def test_logcat_timestamp_conversion(self, mock_zoneinfo_module_patch):
        self.assertEqual(logcat_timestamp_to_utc_datetime("03-15", "12:00:00.123", 2023),
                         datetime.datetime(2023, 3, 15, 12, 0, 0, 123000, tzinfo=datetime.timezone.utc))

        def zoneinfo_constructor_side_effect(key):
            if key == "America/New_York":
                return datetime.timezone(datetime.timedelta(hours=-5), "America/New_York_Mock")
            elif key == "UTC":
                return datetime.timezone.utc
            else:
                if not (hasattr(mock_zoneinfo_module_patch, 'ZoneInfoNotFoundError') and
                        isinstance(mock_zoneinfo_module_patch.ZoneInfoNotFoundError, type) and
                        issubclass(mock_zoneinfo_module_patch.ZoneInfoNotFoundError, Exception)):
                    mock_zoneinfo_module_patch.ZoneInfoNotFoundError = type('MockZoneInfoNotFoundError', (Exception,), {})
                raise mock_zoneinfo_module_patch.ZoneInfoNotFoundError(f"Timezone {key} not found.")

        mock_zoneinfo_module_patch.ZoneInfo.side_effect = zoneinfo_constructor_side_effect

        self.assertEqual(logcat_timestamp_to_utc_datetime("03-15", "12:00:00.123", 2023, source_tz_str="America/New_York"),
                         datetime.datetime(2023, 3, 15, 17, 0, 0, 123000, tzinfo=datetime.timezone.utc))

        with patch('sys.stderr', new_callable=io.StringIO):
            result_fallback = logcat_timestamp_to_utc_datetime("03-15", "10:00:00.000", 2023, source_tz_str="Invalid/Timezone")
            self.assertEqual(result_fallback, datetime.datetime(2023, 3, 15, 10, 0, 0, 0, tzinfo=datetime.timezone.utc))

        with patch('timeline_generator.zoneinfo', None):
             self.assertEqual(logcat_timestamp_to_utc_datetime("03-15", "12:00:00.123", 2023, source_tz_str="America/New_York"),
                             datetime.datetime(2023, 3, 15, 12, 0, 0, 123000, tzinfo=datetime.timezone.utc))
        self.assertIsNone(logcat_timestamp_to_utc_datetime("03-15", "invalid_time", 2023))

    @patch('os.stat')
    def test_parse_filesystem_metadata(self, mock_os_stat):
        mock_stat_result_with_b = MagicMock()
        mock_stat_result_with_b.st_mtime = 1678881600
        mock_stat_result_with_b.st_atime = 1678881601
        mock_stat_result_with_b.st_ctime = 1678881602
        mock_stat_result_with_b.st_birthtime = 1678881599
        mock_stat_result_with_b.st_size = 1024
        mock_stat_result_with_b.st_mode = 0o755
        filepath = "/test/dummy_file.txt"
        mock_os_stat.return_value = mock_stat_result_with_b
        events_all_with_b = parse_filesystem_metadata(filepath, "m,a,c,b")
        self.assertEqual(len(events_all_with_b), 4)
        self.assertTrue(any(e['event_type'] == 'File Created (Birth)' for e in events_all_with_b))

        mock_stat_no_btime = MagicMock(spec=['st_mtime', 'st_atime', 'st_ctime', 'st_size', 'st_mode'])
        mock_stat_no_btime.st_mtime = 1678881600; mock_stat_no_btime.st_atime = 1678881601
        mock_stat_no_btime.st_ctime = 1678881602; mock_stat_no_btime.st_size = 1024
        mock_stat_no_btime.st_mode = 0o755
        mock_os_stat.return_value = mock_stat_no_btime
        events_all_no_b = parse_filesystem_metadata(filepath, "m,a,c,b")
        self.assertEqual(len(events_all_no_b), 3)
        self.assertFalse(any(e['event_type'] == 'File Created (Birth)' for e in events_all_no_b))

        mock_os_stat.side_effect = OSError("Permission denied")
        with patch('timeline_generator.verbose_flag_for_parsers', True), \
             patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
            # parse_filesystem_metadata uses the global verbose_flag_for_parsers directly
            events_error = parse_filesystem_metadata(filepath, "m")
            self.assertEqual(len(events_error), 0)
            self.assertIn(f"Error stating file '{filepath}': Permission denied", mock_stderr.getvalue())

    def test_parse_filter_datetime(self):
        self.assertEqual(parse_filter_datetime("2023-03-15"), datetime.datetime(2023, 3, 15, 0, 0, 0))
        self.assertEqual(parse_filter_datetime("2023-03-15T12:30:00"), datetime.datetime(2023, 3, 15, 12, 30, 0))
        with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
            self.assertIsNone(parse_filter_datetime("invalid-date"))
            self.assertIn("Error: Invalid date/time format for filter 'invalid-date'", mock_stderr.getvalue())

    def test_setup_parser(self):
        parser = setup_parser()
        args = parser.parse_args(['./inputdir', '--output', 'out.csv', '--fs-timestamps', 'm,a', '--start-date', '2023-01-01'])
        self.assertEqual(args.input_dir, './inputdir'); self.assertEqual(args.output, 'out.csv')
        self.assertEqual(args.fs_timestamps, 'm,a'); self.assertEqual(args.start_date, '2023-01-01')
        args_defaults = parser.parse_args(['./inputdir'])
        self.assertEqual(args_defaults.output, 'timeline.csv'); self.assertEqual(args_defaults.fs_timestamps, "m,c,a,b")

    # --- Tests for SQLite Parsers ---
    @patch('sqlite3.connect')
    def test_parse_sms_mms_db_valid_data(self, mock_sqlite_connect):
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite_connect.return_value = mock_conn
        sms_rows = [
            create_mock_row({'address': '12345', 'date': 1678881600000, 'date_sent': 0, 'type': 1, 'body': 'Hello', 'sub_id': 1, 'thread_id': 1}),
            create_mock_row({'address': '67890', 'date': 1678881700000, 'date_sent': 1678881690000, 'type': 2, 'body': 'Hi there', 'sub_id': 1, 'thread_id': 2}),
        ]
        mms_rows = [
            create_mock_row({'_id': 1, 'thread_id': 3, 'date': 1678881800, 'date_sent': 1678881790, 'msg_box': 1, 'sub': 'Subject MMS', 'ct_l': None}),
        ]
        mock_cursor.execute.side_effect = [None, None]
        mock_cursor.fetchall.side_effect = [sms_rows, mms_rows]
        events = parse_sms_mms_db("dummy_sms.db", verbose=False)
        self.assertEqual(len(events), 5)
        sms_event = next(e for e in events if e['event_type'] == 'SMS Received')
        self.assertEqual(sms_event['short_description'], 'SMS Received - From/To: 12345')
        mms_event = next(e for e in events if e['event_type'] == 'MMS Received' and e['source_name'] == 'mmssms.db (mms table)')
        self.assertEqual(mms_event['short_description'], 'MMS Received - Subject: Subject MMS')

    @patch('sqlite3.connect')
    def test_parse_calllog_db_valid_data(self, mock_sqlite_connect):
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite_connect.return_value = mock_conn
        call_rows = [
            create_mock_row({'name': 'John Doe', 'number': '1234567890', 'date': 1678881600000, 'duration': 60, 'type': 1, 'geocoded_location': 'New York', 'countryiso': 'US'}),
        ]
        mock_cursor.fetchall.return_value = call_rows
        events = parse_calllog_db("dummy_calllog.db", verbose=False)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_type'], 'Call Incoming')

    @patch('sqlite3.connect')
    def test_parse_chrome_history_db_valid_data(self, mock_sqlite_connect):
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite_connect.return_value = mock_conn
        history_rows = [
            create_mock_row({'id':1, 'url': 'http://example.com', 'title': 'Example Site', 'visit_count': 5, 'last_visit_time': 13323364800000000}),
        ]
        mock_cursor.fetchall.return_value = history_rows
        events = parse_chrome_history_db("dummy_history.db", verbose=False)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_type'], 'URL Visited (Last)')

    @patch('sqlite3.connect') # Innermost mock passed first
    # @patch('timeline_generator.verbose_flag_for_parsers', True) # Outermost mock passed last
    def test_sqlite_parsers_sqlite_error(self, mock_sqlite_connect_arg):
        with patch('timeline_generator.verbose_flag_for_parsers', True), \
             patch('sys.stderr', new_callable=io.StringIO) as mock_stderr_arg:

            mock_sqlite_connect_arg.side_effect = sqlite3.Error("Cannot connect to DB")

            # Pass verbose=True directly to the parsers for testing their internal print statements
            self.assertEqual(parse_sms_mms_db("error.db", verbose=True), [])
            self.assertIn("Error connecting to or reading SMS/MMS DB error.db: Cannot connect to DB", mock_stderr_arg.getvalue())

            mock_stderr_arg.seek(0); mock_stderr_arg.truncate(0)
            self.assertEqual(parse_calllog_db("error.db", verbose=True), [])
            self.assertIn("Error connecting to or reading Call Log DB error.db: Cannot connect to DB", mock_stderr_arg.getvalue())

            mock_stderr_arg.seek(0); mock_stderr_arg.truncate(0)
            self.assertEqual(parse_chrome_history_db("error.db", verbose=True), [])
            self.assertIn("Error connecting to or reading Chrome History DB error.db: Cannot connect to DB", mock_stderr_arg.getvalue())

    @patch('sqlite3.connect')
    def test_sqlite_parsers_empty_db(self, mock_sqlite_connect):
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite_connect.return_value = mock_conn
        mock_cursor.fetchall.return_value = []

        self.assertEqual(parse_sms_mms_db("empty.db"), [])
        self.assertEqual(parse_calllog_db("empty.db"), [])
        self.assertEqual(parse_chrome_history_db("empty.db"), [])

if __name__ == '__main__':
    unittest.main()
