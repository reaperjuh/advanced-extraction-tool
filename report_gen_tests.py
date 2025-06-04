import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import os
import argparse
import html
import sqlite3 # For sqlite3.Error
import datetime
import sys
import io
import re

from report_generator import (
    setup_parser, html_escape, format_timestamp_for_report,
    epoch_milliseconds_to_datetime, epoch_seconds_to_datetime, webkit_to_datetime,
    gather_device_info, gather_key_files_status,
    gather_communications_summary, gather_browsing_summary,
    generate_html_table, generate_html_section,
    generate_device_info_html, generate_key_files_status_html,
    generate_communications_summary_html, generate_browsing_summary_html
)

def create_mock_row(data_dict):
    return data_dict

class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.mock_args = argparse.Namespace(
            input_dir="dummy_input_dir", output=None, title=None, max_sample_items=5
        )
        self.verbose_patcher = patch('report_generator.verbose_flag_for_parsers', False)
        self.mock_verbose_global = self.verbose_patcher.start()
        self.addCleanup(self.verbose_patcher.stop)

    def test_html_escape_functionality(self):
        self.assertEqual(html_escape("test"), "test", "String with no special chars should remain unchanged.")
        self.assertEqual(html_escape("<tag>"), "&lt;tag&gt;", "Less-than and greater-than should be escaped.")
        self.assertEqual(html_escape(" 'quotes' & \"more\""), " &#x27;quotes&#x27; &amp; &quot;more&quot;", "Quotes and ampersand should be escaped.")
        self.assertEqual(html_escape(None), "", "None input should return an empty string.")
        self.assertEqual(html_escape(123), "123", "Integer input should be converted to string.")
        self.assertEqual(html_escape(["list", "item"]), "[&#x27;list&#x27;, &#x27;item&#x27;]", "Single quotes in list str representation should be escaped.")


    def test_format_timestamp_for_report(self):
        dt_aware = datetime.datetime(2023, 1, 15, 10, 30, 0, tzinfo=datetime.timezone.utc)
        self.assertEqual(format_timestamp_for_report(dt_aware), "2023-01-15 10:30:00 UTC")

        dt_naive = datetime.datetime(2023, 1, 15, 10, 30, 0)
        self.assertEqual(format_timestamp_for_report(dt_naive), "2023-01-15 10:30:00 UTC")

        self.assertEqual(format_timestamp_for_report(None), "N/A", "None input should return 'N/A'.")
        self.assertEqual(format_timestamp_for_report("not a datetime"), "not a datetime", "Non-datetime input should be stringified.")

    def test_internal_timestamp_converters(self):
        dt_expected = datetime.datetime(2023, 3, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
        ms_timestamp = dt_expected.timestamp() * 1000
        self.assertEqual(epoch_milliseconds_to_datetime(ms_timestamp), dt_expected)
        self.assertIsNone(epoch_milliseconds_to_datetime(None))
        self.assertIsNone(epoch_milliseconds_to_datetime(0))

        s_timestamp = dt_expected.timestamp()
        self.assertEqual(epoch_seconds_to_datetime(s_timestamp), dt_expected)
        self.assertIsNone(epoch_seconds_to_datetime(None))
        self.assertIsNone(epoch_seconds_to_datetime(0))

        webkit_epoch_start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        webkit_us_timestamp = (dt_expected - webkit_epoch_start).total_seconds() * 1_000_000
        self.assertEqual(webkit_to_datetime(webkit_us_timestamp), dt_expected)
        self.assertIsNone(webkit_to_datetime(None))
        self.assertIsNone(webkit_to_datetime(0))


    def test_setup_parser_functionality(self):
        parser = setup_parser()
        args = parser.parse_args(["input_path", "--output", "out.html", "--title", "T", "--max-sample-items", "3"])
        self.assertEqual(args.input_dir, "input_path")
        self.assertEqual(args.output, "out.html")
        self.assertEqual(args.title, "T")
        self.assertEqual(args.max_sample_items, 3)
        args_defaults = parser.parse_args(["input_path"])
        self.assertIsNone(args_defaults.output)
        self.assertEqual(args_defaults.max_sample_items, 5)

    @patch('os.path.getsize')
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_gather_device_info_logic(self, mock_open_func, mock_exists, mock_getsize):
        props_content = "[ro.product.model]: [Pixel Test]\n[ro.build.version.release]: [13]\n[unwanted.prop]: [some_value]"
        pkgs_content_raw = "package:/data/app/com.app1/base.apk=com.app1\npackage:/data/app/com.app2/base.apk=com.app2\npackage:/data/app/com.app3/base.apk=com.app3"

        def open_side_effect_success(filepath, *args, **kwargs):
            if "device_properties.txt" in filepath: return io.StringIO(props_content)
            elif "installed_packages.txt" in filepath: return io.StringIO(pkgs_content_raw)
            raise FileNotFoundError(filepath)

        with self.subTest("Successful parsing"):
            mock_exists.side_effect = None; mock_exists.return_value = True
            mock_getsize.return_value = 100
            mock_open_func.side_effect = open_side_effect_success
            result = gather_device_info("dummy_input_dir")
            self.assertEqual(result['properties'].get('ro.product.model'), 'Pixel Test')
            self.assertNotIn('unwanted.prop', result['properties'])
            self.assertEqual(result['installed_packages_count'], 3)
            self.assertNotIn('properties_status', result)
            self.assertNotIn('packages_status', result)

        with self.subTest("Files not found"):
            mock_exists.side_effect = None; mock_exists.return_value = False
            mock_open_func.side_effect = FileNotFoundError("Simulated")
            result = gather_device_info("dummy_input_dir")
            self.assertEqual(result['properties_status'], 'File not found')
            self.assertEqual(result['packages_status'], 'File not found')

        with self.subTest("Partial files (props found, pkgs not)"):
            mock_exists.side_effect = lambda path: "device_properties.txt" in path
            mock_getsize.return_value = 100
            mock_open_func.side_effect = open_side_effect_success
            result = gather_device_info("dummy_input_dir")
            self.assertNotIn('properties_status', result)
            self.assertEqual(result['packages_status'], 'File not found')

        with self.subTest("Empty files"):
            mock_exists.side_effect = None
            mock_exists.return_value = True
            mock_getsize.return_value = 0
            mock_open_func.side_effect = lambda f, *a, **kw: io.StringIO("")
            result = gather_device_info("dummy_input_dir")
            self.assertEqual(result['properties_status'], "File found but empty.")
            self.assertEqual(result['packages_status'], "File found but empty.")

    @patch('os.path.getsize')
    @patch('os.listdir')
    @patch('os.path.isdir')
    @patch('os.path.isfile')
    @patch('os.path.exists')
    def test_gather_key_files_status_scenarios(self, mock_exists, mock_isfile, mock_isdir, mock_listdir, mock_getsize):
        path_file_txt = os.path.join("dummy_input_dir", "Category1", "File.txt")
        path_adir = os.path.join("dummy_input_dir", "Category2", "ADir")
        path_missing_dat = os.path.join("dummy_input_dir", "Category3", "Missing.dat")
        test_key_artifacts_for_patch = {
            "Test File": os.path.join("Category1", "File.txt"),
            "Test Dir": os.path.join("Category2", "ADir"),
            "Missing File": os.path.join("Category3", "Missing.dat")
        }
        def exists_side_effect(path):
            if path == path_file_txt: return True
            if path == path_adir: return True
            if path == path_missing_dat: return False
            return False
        mock_exists.side_effect = exists_side_effect
        mock_isfile.side_effect = lambda path: path == path_file_txt
        mock_isdir.side_effect = lambda path: path == path_adir
        mock_listdir.return_value = ["item1", "item2"]; mock_getsize.return_value = 100
        with patch.dict('report_generator.KEY_ARTIFACT_PATHS', test_key_artifacts_for_patch, clear=True):
            statuses = gather_key_files_status("dummy_input_dir")
        s_map = {s['name']: s for s in statuses}
        self.assertEqual(len(statuses), 3)
        self.assertEqual(s_map["Test File"]['status'], "Found (File, 100 bytes)")
        self.assertEqual(s_map["Test Dir"]['status'], "Found (Directory, 2 items)")
        self.assertEqual(s_map["Missing File"]['status'], "Not found")

    @patch('os.path.exists')
    @patch('sqlite3.connect')
    def test_gather_communications_summary_logic(self, mock_sqlite_connect, mock_os_exists):
        mock_cursor = MagicMock(); mock_conn = MagicMock(); mock_conn.cursor.return_value = mock_cursor
        with self.subTest("Successful data parsing"):
            mock_os_exists.return_value = True; mock_sqlite_connect.return_value = mock_conn; mock_sqlite_connect.side_effect = None
            sms_c=[create_mock_row({'type':1,'count':2}),create_mock_row({'type':2,'count':1})]; sms_s=[create_mock_row({'address':'123','date':1000,'type':1,'body':'sms1'})]
            mms_c=[create_mock_row({'msg_box':1,'count':1})]; mms_s=[create_mock_row({'_id':1,'date':2000,'msg_box':1,'sub':'mms1'})]
            call_c=[create_mock_row({'type':1,'count':3}),create_mock_row({'type':2,'count':2})]; call_s=[create_mock_row({'name':'N','number':'Num','date':3000,'duration':60,'type':1})]
            mock_cursor.fetchall.side_effect = [sms_c,sms_s,mms_c,mms_s,call_c,call_s]
            summary = gather_communications_summary("dummy_input_dir",1)
            self.assertEqual(summary['sms']['status'], "Processed (R: 2, S: 1)"); self.assertEqual(summary['calls']['counts']['In'], 3)
        with self.subTest("DB not found"):
            mock_os_exists.return_value = False; mock_sqlite_connect.side_effect = None
            summary = gather_communications_summary("dummy_input_dir", 1)
            self.assertEqual(summary['sms']['status'], 'Not found'); self.assertEqual(summary['calls']['status'], 'Not found')
        with self.subTest("SQLite Error on connect"):
            mock_os_exists.return_value = True; mock_sqlite_connect.side_effect = sqlite3.Error("db error")
            with patch('report_generator.verbose_flag_for_parsers', True), patch('sys.stderr', new_callable=io.StringIO) as mock_stderr:
                summary = gather_communications_summary("dummy_input_dir", 1)
                self.assertIn("Error: db error", summary['sms']['status']); self.assertIn("Error: db error", summary['calls']['status'])
                self.assertIn(f"Error processing SMS/MMS DB {os.path.join('dummy_input_dir', 'User Data', 'mmssms.db')}: db error", mock_stderr.getvalue())
                self.assertIn(f"Error processing CallLog DB {os.path.join('dummy_input_dir', 'User Data', 'calllog.db')}: db error", mock_stderr.getvalue())

    @patch('os.path.exists')
    @patch('sqlite3.connect')
    def test_gather_browsing_summary_logic(self, mock_sqlite_connect, mock_os_exists):
        mock_cursor=MagicMock(); mock_conn=MagicMock(); mock_conn.cursor.return_value=mock_cursor; mock_sqlite_connect.return_value=mock_conn
        with self.subTest("Successful parsing"):
            mock_os_exists.return_value=True; mock_sqlite_connect.side_effect=None
            mock_cursor.fetchone.side_effect=[create_mock_row({'count':10}),create_mock_row({'sum_visits':25})]
            mock_cursor.fetchall.side_effect=[[create_mock_row({'url':'t.com','title':'T','visit_count':5})],[create_mock_row({'url':'r.com','title':'R','last_visit_time':13323364800000000})]]
            summary=gather_browsing_summary("dummy_input_dir",1)
            self.assertEqual(summary['chrome_history']['status'],"Processed (URLs: 10, Visits: 25)")
            self.assertEqual(len(summary['chrome_history']['top_sites']),1)

    def test_generate_html_table_basic(self):
        headers = ["Col1", "Col2"]; rows_data = [["R1C1", "R1C2"], ["R2C1 <script>", "R2C2"]]
        html_out = generate_html_table(headers, rows_data)
        self.assertTrue(html_out.startswith("<table class=''>"))
        self.assertIn("<thead><tr><th>Col1</th><th>Col2</th></tr></thead>", html_out)
        self.assertIn("<tbody>", html_out); self.assertIn("<td>R1C1</td>", html_out); self.assertIn("<td>R2C1 &lt;script&gt;</td>", html_out)
        self.assertTrue(html_out.endswith("</tbody>\n</table>"))

    def test_generate_html_table_empty(self):
        html_out = generate_html_table(["H1"], [])
        self.assertIn("<tbody>\n</tbody>\n</table>", html_out)

    def test_generate_html_table_with_class(self):
        self.assertIn("<table class='custom-class'>", generate_html_table([], [], "custom-class"))

    def test_generate_html_section_basic(self):
        html_out = generate_html_section("Title", "<p>Content</p>", "id1")
        self.assertIn("<div class='section' id='id1'>", html_out)
        self.assertIn("<h2>Title</h2>", html_out)
        self.assertIn("<p>Content</p>\n</div>", html_out)

    def test_generate_device_info_html_content(self):
        data = {'properties':{'model':'Pixel X'},'installed_packages_count':10}
        html_out = generate_device_info_html(data)
        self.assertIn("<h3>Device Properties</h3>", html_out); self.assertIn("<td>model</td><td>Pixel X</td>", html_out)
        self.assertIn("<strong>Installed Packages Count:</strong> 10", html_out)
        data_err = {'properties_status':'Err','packages_status':'Err', 'installed_packages_count':0}
        html_out_err = generate_device_info_html(data_err)
        self.assertIn("<span class='error'>Err</span>", html_out_err)

    def test_generate_key_files_status_html_content(self):
        data = [{'name':'SMS','path':'p1','status':'Found (File)'},{'name':'DCIM','path':'p2','status':'Not found'}]
        html_out = generate_key_files_status_html(data)
        self.assertIn("<td>SMS</td>", html_out); self.assertIn("<span class='filename'>p1</span>", html_out); self.assertIn("status-found", html_out)
        self.assertIn("<td>DCIM</td>", html_out); self.assertIn("<span class='filename'>p2</span>", html_out); self.assertIn("status-not-found", html_out)

    def test_generate_communications_summary_html_content(self):
        data = {'sms':{'status':'OK','counts':{'received':1},'samples':[{'date':'d','type':'t','address':'a','body':'b'}]},
                'mms':{'status':'OK','counts':{'sent':1},'samples':[{'date':'d','type':'t','subject':'s','id':1}]},
                'calls':{'status':'OK','counts':{'In':1},'samples':[{'date':'d','type':'t','name':'n','number':'nu','duration':10}]}}
        html_out = generate_communications_summary_html(data, 1)
        self.assertIn("<h3>SMS Summary</h3>", html_out); self.assertIn("<td>b</td>", html_out)
        self.assertIn("<h3>MMS Summary</h3>", html_out); self.assertIn("<td>s</td>", html_out)
        self.assertIn("<h3>Call Log Summary</h3>", html_out); self.assertIn("<td>n</td>", html_out)

    def test_generate_browsing_summary_html_content(self):
        data = {'chrome_history':{'status':'Processed','total_urls':1,'total_visits':1,
                                  'top_sites':[{'url':'u','title':'t','visit_count':1}],
                                  'recent_sites':[{'url':'u2','title':'t2','last_visit_time':'lt'}]}}
        html_out = generate_browsing_summary_html(data,1)
        self.assertIn("<h3>Chrome History Summary</h3>",html_out); self.assertIn("<td>t</td>",html_out); self.assertIn("<td>t2</td>",html_out)
        self.assertIn("<a href='u2'",html_out)

if __name__ == '__main__':
    unittest.main()
