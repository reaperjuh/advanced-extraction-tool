import unittest
from unittest.mock import patch, MagicMock, mock_open
import datetime
import os
import argparse
import csv
import json
import io
import sys

# Functions and constants to be tested
from timeline_generator import (
    epoch_seconds_to_utc_datetime,
    epoch_milliseconds_to_utc_datetime,
    webkit_to_utc_datetime,
    logcat_timestamp_to_utc_datetime,
    parse_filesystem_metadata,
    parse_filter_datetime,
    setup_parser,
    zoneinfo as actual_zoneinfo_module_from_script # Import to check its actual state
)

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
        # This argument `mock_zoneinfo_module_patch` is the MagicMock replacing `timeline_generator.zoneinfo`

        # Test UTC (default)
        self.assertEqual(logcat_timestamp_to_utc_datetime("03-15", "12:00:00.123", 2023),
                         datetime.datetime(2023, 3, 15, 12, 0, 0, 123000, tzinfo=datetime.timezone.utc))

        # Setup side effect for the ZoneInfo class *on the mock module*
        def zoneinfo_constructor_side_effect(key):
            if key == "America/New_York":
                return datetime.timezone(datetime.timedelta(hours=-5), "America/New_York_Mock")
            elif key == "UTC": # Should ideally not be called if source_tz_str.upper() == 'UTC'
                return datetime.timezone.utc
            else:
                # This exception needs to be an instance of the exception type
                # that `except zoneinfo.ZoneInfoNotFoundError:` in the SCRIPT will catch.
                # During the test, `zoneinfo` in the SCRIPT is `mock_zoneinfo_module_patch`.
                # So we need to raise `mock_zoneinfo_module_patch.ZoneInfoNotFoundError`.
                # We ensure this attribute exists on the mock and is an exception type.
                if not hasattr(mock_zoneinfo_module_patch, 'ZoneInfoNotFoundError') or \
                   not isinstance(mock_zoneinfo_module_patch.ZoneInfoNotFoundError, type) or \
                   not issubclass(mock_zoneinfo_module_patch.ZoneInfoNotFoundError, Exception):
                    # If not correctly set up (e.g. if actual_zoneinfo_module_from_script was None,
                    # and the mock didn't get this attribute properly from spec)
                    # then create a dummy exception for the mock to use.
                    mock_zoneinfo_module_patch.ZoneInfoNotFoundError = type('MockZoneInfoNotFoundError', (Exception,), {})
                raise mock_zoneinfo_module_patch.ZoneInfoNotFoundError(f"Timezone {key} not found.")

        # mock_zoneinfo_module_patch is the mock for the module.
        # Its 'ZoneInfo' attribute (the class) is automatically a MagicMock.
        # We set the side_effect on this class mock.
        mock_zoneinfo_module_patch.ZoneInfo.side_effect = zoneinfo_constructor_side_effect

        # Test with a specific timezone ("America/New_York")
        self.assertEqual(logcat_timestamp_to_utc_datetime("03-15", "12:00:00.123", 2023, source_tz_str="America/New_York"),
                         datetime.datetime(2023, 3, 15, 17, 0, 0, 123000, tzinfo=datetime.timezone.utc))

        # Test with invalid timezone string - should be caught and fall back to UTC
        with patch('sys.stderr', new_callable=io.StringIO): # Suppress potential warning print
            result_fallback = logcat_timestamp_to_utc_datetime("03-15", "10:00:00.000", 2023, source_tz_str="Invalid/Timezone")
            self.assertEqual(result_fallback, datetime.datetime(2023, 3, 15, 10, 0, 0, 0, tzinfo=datetime.timezone.utc))

        # Test the path where 'timeline_generator.zoneinfo' is None in the script
        # This simulates the try-except for zoneinfo import failing in the script.
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

        # Simulate st_birthtime NOT existing by using spec that excludes it
        mock_stat_no_btime = MagicMock(spec=['st_mtime', 'st_atime', 'st_ctime', 'st_size', 'st_mode'])
        mock_stat_no_btime.st_mtime = 1678881600
        mock_stat_no_btime.st_atime = 1678881601
        mock_stat_no_btime.st_ctime = 1678881602
        mock_stat_no_btime.st_size = 1024
        mock_stat_no_btime.st_mode = 0o755
        mock_os_stat.return_value = mock_stat_no_btime

        events_all_no_b = parse_filesystem_metadata(filepath, "m,a,c,b")
        self.assertEqual(len(events_all_no_b), 3)
        self.assertFalse(any(e['event_type'] == 'File Created (Birth)' for e in events_all_no_b))

        mock_os_stat.side_effect = OSError("Permission denied")
        with patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
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
        self.assertEqual(args.input_dir, './inputdir')
        self.assertEqual(args.output, 'out.csv')
        self.assertEqual(args.fs_timestamps, 'm,a')
        self.assertEqual(args.start_date, '2023-01-01')

        args_defaults = parser.parse_args(['./inputdir'])
        self.assertEqual(args_defaults.output, 'timeline.csv')
        self.assertEqual(args_defaults.fs_timestamps, "m,c,a,b")

    def test_date_filtering_logic(self):
        events = [
            {'timestamp_utc': datetime.datetime(2023, 1, 10, 12, 0, 0, tzinfo=datetime.timezone.utc)},
            {'timestamp_utc': datetime.datetime(2023, 1, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)},
            {'timestamp_utc': datetime.datetime(2023, 1, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)},
            {'timestamp_utc': None}
        ]
        start_date = datetime.datetime(2023, 1, 15, 0, 0, 0)
        end_date = datetime.datetime(2023, 1, 19, 23, 59, 59)

        filtered_start = [e for e in events if e['timestamp_utc'] and e['timestamp_utc'].replace(tzinfo=None) >= start_date]
        self.assertEqual(len(filtered_start), 2)

        filtered_end = [e for e in events if e['timestamp_utc'] and e['timestamp_utc'].replace(tzinfo=None) <= end_date]
        self.assertEqual(len(filtered_end), 2)

        filtered_combined = [
            e for e in events if e['timestamp_utc'] and \
            (not start_date or e['timestamp_utc'].replace(tzinfo=None) >= start_date) and \
            (not end_date or e['timestamp_utc'].replace(tzinfo=None) <= end_date)
        ]
        self.assertEqual(len(filtered_combined), 1)
        self.assertEqual(filtered_combined[0]['timestamp_utc'], events[1]['timestamp_utc'])

    def test_sorting_logic(self):
        events = [
            {'timestamp_utc': datetime.datetime(2023, 1, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)},
            {'timestamp_utc': None},
            {'timestamp_utc': datetime.datetime(2023, 1, 10, 12, 0, 0, tzinfo=datetime.timezone.utc)},
        ]
        expected_sorted_timestamps = [
            None,
            datetime.datetime(2023, 1, 10, 12, 0, 0, tzinfo=datetime.timezone.utc),
            datetime.datetime(2023, 1, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)
        ]
        events.sort(key=lambda e: e['timestamp_utc'] if e['timestamp_utc'] else datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))
        sorted_timestamps = [e['timestamp_utc'] for e in events]
        self.assertEqual(sorted_timestamps, expected_sorted_timestamps)

    def test_output_formatting_conceptual(self):
        event = {
            'timestamp_utc': datetime.datetime(2023, 3, 15, 12, 0, 0, tzinfo=datetime.timezone.utc),
            'source_type': 'File System', 'event_type': 'File Modified',
            'short_description': 'file.txt (M)', 'full_path': '/abs/path/to/file.txt',
            'source_name': 'file.txt', 'details': {'size': 100, 'mode': '755'}
        }
        ts_iso = event['timestamp_utc'].isoformat()
        details_json = json.dumps(event['details'])
        csv_row = [ts_iso, event['source_type'], event['event_type'], event['short_description'],
                   event['full_path'], event['source_name'], details_json]
        self.assertEqual(len(csv_row), 7)

        txt_line = f"{ts_iso} | {event['source_type']:<15} | {event['event_type']:<25} | {event['short_description']:<50} | Path: {event['full_path']} | Details: {details_json}\n"
        self.assertIn("File System", txt_line)

        event_copy = event.copy(); event_copy['timestamp_utc'] = ts_iso
        jsonl_line = json.dumps(event_copy) + '\n'
        self.assertIn("\"source_type\": \"File System\"", jsonl_line)

if __name__ == '__main__':
    unittest.main()
