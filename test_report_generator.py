import unittest
from unittest.mock import patch, MagicMock, mock_open
import os
import argparse
import html
import sqlite3 # For sqlite3.Error and for type hinting if needed
import datetime # For timestamp helpers, though report generator might re-implement simple ones

# Functions and constants to be tested
from report_generator import (
    html_escape,
    setup_parser,
    gather_device_info,
    gather_key_files_status,
    gather_communications_summary,
    gather_browsing_summary,
    generate_html_table,
    generate_html_section,
    generate_device_info_html,
    generate_key_files_status_html,
    generate_communications_summary_html,
    generate_browsing_summary_html,
    # Timestamp helpers are also used internally by gather_* functions
    epoch_milliseconds_to_datetime,
    epoch_seconds_to_datetime,
    webkit_to_datetime,
    format_timestamp_for_report
)

# Helper to create mock SQLite rows (dictionaries)
def create_mock_row(data_dict):
    return data_dict

class TestReportGenerator(unittest.TestCase):

    def test_html_escape(self):
        self.assertEqual(html_escape("<hello & world>"), "&lt;hello &amp; world&gt;")
        self.assertEqual(html_escape("No escaping needed"), "No escaping needed")
        self.assertEqual(html_escape(123), "123")

    def test_setup_parser(self):
        parser = setup_parser()
        args = parser.parse_args(['./input_data', '--output', 'my_report.html', '--title', 'My Report', '--max-sample-items', '10'])
        self.assertEqual(args.input_dir, './input_data')
        self.assertEqual(args.output, 'my_report.html')
        self.assertEqual(args.title, 'My Report')
        self.assertEqual(args.max_sample_items, 10)

        # Test default max_sample_items
        args_default_samples = parser.parse_args(['./input_data'])
        self.assertEqual(args_default_samples.max_sample_items, 5)
        self.assertIsNone(args_default_samples.output) # Output has a default in main, not parser
        self.assertIsNone(args_default_samples.title)


    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists')
    @patch('os.path.getsize')
    def test_gather_device_info(self, mock_getsize, mock_exists, mock_open_file):
        # Scenario 1: Both files exist and have content
        mock_exists.return_value = True
        mock_getsize.return_value = 100 # Non-zero size
        properties_content = "[ro.product.model]: [TestModel]\n[ro.product.manufacturer]: [TestManu]\n[ro.build.id]: [TB123]"
        packages_content = "package:com.example.app1\npackage:com.example.app2"
        mock_open_file.side_effect = [
            mock_open(read_data=properties_content).return_value,
            mock_open(read_data=packages_content).return_value
        ]

        info = gather_device_info("dummy_dir")
        self.assertEqual(info['properties']['ro.product.model'], 'TestModel')
        self.assertEqual(info['installed_packages_count'], 2)
        self.assertNotIn('properties_status', info)
        self.assertNotIn('packages_status', info)

        # Scenario 2: Files not found
        mock_exists.return_value = False
        info_not_found = gather_device_info("dummy_dir")
        self.assertEqual(info_not_found['properties_status'], 'File not found')
        self.assertEqual(info_not_found['packages_status'], 'File not found')

        # Scenario 3: Properties file found but empty relevant props
        mock_exists.return_value = True
        mock_getsize.return_value = 10 # Non-zero size
        mock_open_file.side_effect = [mock_open(read_data="[other.prop]: [value]").return_value]
        info_empty_props = gather_device_info("dummy_dir")
        self.assertEqual(info_empty_props['properties_status'], "File found but no matching important properties extracted or format error.")


    @patch('os.path.getsize')
    @patch('os.listdir')
    @patch('os.path.isdir')
    @patch('os.path.isfile')
    @patch('os.path.exists')
    def test_gather_key_files_status(self, mock_exists, mock_isfile, mock_isdir, mock_listdir, mock_getsize):
        # Setup mock return values
        def path_side_effect(path):
            if "mmssms.db" in path: # File
                return True
            if "DCIM" in path: # Dir
                return True
            return False # Others not found
        mock_exists.side_effect = path_side_effect

        def isfile_side_effect(path):
            return "mmssms.db" in path
        mock_isfile.side_effect = isfile_side_effect

        def isdir_side_effect(path):
            return "DCIM" in path
        mock_isdir.side_effect = isdir_side_effect

        mock_listdir.return_value = ["img1.jpg", "img2.jpg"] # For DCIM
        mock_getsize.return_value = 1024 # For mmssms.db

        statuses = gather_key_files_status("dummy_dir")

        sms_status = next(s for s in statuses if s['name'] == 'SMS_MMS DB')
        dcim_status = next(s for s in statuses if s['name'] == 'DCIM Storage')
        contacts_status = next(s for s in statuses if s['name'] == 'Contacts DB')

        self.assertIn("Found (File, 1024 bytes)", sms_status['status'])
        self.assertIn("Found (Directory, 2 items)", dcim_status['status'])
        self.assertEqual(contacts_status['status'], "Not found")

    @patch('sqlite3.connect')
    def test_gather_communications_summary(self, mock_sqlite_connect):
        mock_cursor_sms = MagicMock()
        mock_cursor_calls = MagicMock()
        mock_conn_sms = MagicMock()
        mock_conn_calls = MagicMock()

        # Configure sms/mms db
        mock_conn_sms.cursor.return_value = mock_cursor_sms
        sms_counts_data = [create_mock_row({'type': 1, 'count': 10}), create_mock_row({'type': 2, 'count': 5})]
        sms_samples_data = [create_mock_row({'address': '123', 'date': 1678881600000, 'type': 1, 'body': 'SMS body'})]
        mms_counts_data = [create_mock_row({'msg_box': 1, 'count': 2})]
        mms_samples_data = [create_mock_row({'_id': 1, 'date': 1678881800, 'msg_box': 1, 'sub': 'MMS Sub'})]

        # Configure calllog db
        mock_conn_calls.cursor.return_value = mock_cursor_calls
        call_counts_data = [create_mock_row({'type': 1, 'count': 7}), create_mock_row({'type': 2, 'count': 3})]
        call_samples_data = [create_mock_row({'name': 'Caller', 'number': '555', 'date': 1678881900000, 'duration': 30, 'type': 1})]

        def connect_side_effect(path_uri, uri=True):
            if "mmssms.db" in path_uri:
                mock_cursor_sms.fetchall.side_effect = [sms_counts_data, sms_samples_data, mms_counts_data, mms_samples_data]
                return mock_conn_sms
            elif "calllog.db" in path_uri:
                mock_cursor_calls.fetchall.side_effect = [call_counts_data, call_samples_data]
                return mock_conn_calls
            raise sqlite3.Error("Unknown DB path for mock")
        mock_sqlite_connect.side_effect = connect_side_effect

        with patch('os.path.exists', return_value=True): # Assume DBs exist
            summary = gather_communications_summary("dummy_dir", max_sample_items=1)

        self.assertEqual(summary['sms']['counts']['received'], 10)
        self.assertEqual(len(summary['sms']['samples']), 1)
        self.assertEqual(summary['mms']['counts']['received'], 2)
        self.assertEqual(len(summary['mms']['samples']), 1)
        self.assertEqual(summary['calls']['counts']['Incoming'], 7)
        self.assertEqual(len(summary['calls']['samples']), 1)

    @patch('sqlite3.connect')
    def test_gather_browsing_summary(self, mock_sqlite_connect):
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_sqlite_connect.return_value = mock_conn

        url_count_data = create_mock_row({'count': 150})
        visit_sum_data = create_mock_row({'sum_visits': 300})
        top_sites_data = [create_mock_row({'url': 'top1.com', 'title': 'Top 1', 'visit_count': 50})]
        recent_sites_data = [create_mock_row({'url': 'recent1.com', 'title': 'Recent 1', 'last_visit_time': 13323364800000000})]

        mock_cursor.fetchone.side_effect = [url_count_data, visit_sum_data] # For COUNT and SUM
        mock_cursor.fetchall.side_effect = [top_sites_data, recent_sites_data] # For top and recent lists

        with patch('os.path.exists', return_value=True): # Assume History DB exists
            summary = gather_browsing_summary("dummy_dir", max_sample_items=1)

        self.assertEqual(summary['chrome_history']['total_urls'], 150)
        self.assertEqual(summary['chrome_history']['total_visits'], 300)
        self.assertEqual(len(summary['chrome_history']['top_sites']), 1)
        self.assertEqual(summary['chrome_history']['top_sites'][0]['url'], 'top1.com')
        self.assertEqual(len(summary['chrome_history']['recent_sites']), 1)
        self.assertEqual(summary['chrome_history']['recent_sites'][0]['url'], 'recent1.com')

    def test_generate_html_table(self):
        headers = ["Col1", "Col2"]
        rows = [["r1c1", "r1c2"], ["r2<c1>", "r2&c2"]]
        html = generate_html_table(headers, rows)
        self.assertIn("<th>Col1</th>", html)
        self.assertIn("<td>r1c1</td>", html)
        self.assertIn("<td>r2&lt;c1&gt;</td>", html) # Check escaping
        self.assertIn("<td>r2&amp;c2</td>", html)

    def test_generate_html_section(self):
        html = generate_html_section("Test Title", "<p>Content</p>", "test-id")
        self.assertIn("<div class='section' id='test-id'>", html)
        self.assertIn("<h2>Test Title</h2>", html)
        self.assertIn("<p>Content</p>", html)

    def test_generate_device_info_html(self):
        device_data = {'properties': {'ro.product.model': 'Pixel Test'}, 'installed_packages_count': 10}
        html = generate_device_info_html(device_data)
        self.assertIn("<h3>Device Properties</h3>", html)
        self.assertIn("<td>ro.product.model</td><td>Pixel Test</td>", html)
        self.assertIn("<strong>Installed Packages Count:</strong> 10", html)

        device_data_error = {'properties_status': 'File not found', 'packages_status': 'File not found'}
        html_error = generate_device_info_html(device_data_error)
        self.assertIn("Device Properties: <span class='error'>File not found</span>", html_error)

    def test_generate_key_files_status_html(self):
        key_files_data = [{'name': 'SMS DB', 'path': 'User Data/mmssms.db', 'status': 'Found (File, 100 bytes)'}]
        html = generate_key_files_status_html(key_files_data)
        self.assertIn("<td>SMS DB</td>", html)
        self.assertIn("<span class='filename'>User Data/mmssms.db</span>", html)
        self.assertIn("<span class='status-found'>Found (File, 100 bytes)</span>", html)

    def test_generate_communications_summary_html(self):
        comm_summary = {
            'sms': {'status': 'Processed', 'counts': {'received': 5}, 'samples': [{'date': '2023-01-01', 'type': 'Recv', 'address': '123', 'body': 'Hi'}]},
            'calls': {'status': 'Processed', 'counts': {'Incoming': 2}, 'samples': [{'date': '2023-01-02', 'type': 'In', 'name': 'John', 'number':'555', 'duration':10}]}
        }
        html = generate_communications_summary_html(comm_summary, 1)
        self.assertIn("<h3>SMS Summary</h3>", html)
        self.assertIn("<td>Hi</td>", html)
        self.assertIn("<h3>Call Log Summary</h3>", html)
        self.assertIn("<td>John</td>", html)

    def test_generate_browsing_summary_html(self):
        browsing_summary = {
            'chrome_history': {'status': 'Processed', 'total_urls': 10, 'total_visits': 20,
                               'top_sites': [{'url': 'example.com', 'title': 'Example', 'visit_count': 5}],
                               'recent_sites': [{'url': 'test.com', 'title': 'Test', 'last_visit_time': '2023-01-01'}]}
        }
        html = generate_browsing_summary_html(browsing_summary, 1)
        self.assertIn("<h3>Chrome History Summary</h3>", html)
        self.assertIn("<td>Example</td>", html) # From top_sites
        self.assertIn("<a href='test.com' target='_blank'>test.com</a>", html) # From recent_sites

if __name__ == '__main__':
    unittest.main()
