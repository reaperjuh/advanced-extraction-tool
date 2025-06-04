import unittest
from unittest.mock import patch, MagicMock, mock_open
import argparse
import subprocess
import os

# Import functions and variables from artifact_extractor
from artifact_extractor import (
    get_device_serial,
    extract_artifact,
    run_extraction,
    setup_arg_parser,
    ARTIFACTS_DB # Direct import for inspection/patching
)

# Store original ARTIFACTS_DB for tests that need a clean slate or specific modifications
ORIGINAL_ARTIFACTS_DB = {k: v.copy() for k, v in ARTIFACTS_DB.items()}


class TestArtifactExtractor(unittest.TestCase):

    def setUp(self):
        self.mock_adb_exe_path = "/mock/path/to/adb.exe"
        self.adb_exe_patcher = patch('artifact_extractor.ADB_EXE', self.mock_adb_exe_path)
        self.adb_exe_patcher.start()
        self.addCleanup(self.adb_exe_patcher.stop)


    @patch('subprocess.run')
    @patch('builtins.print')
    def test_get_device_serial(self, mock_print, mock_subprocess_run):
        self.assertEqual(get_device_serial(specified_serial="test_serial_01", adb_exe_path=self.mock_adb_exe_path), "test_serial_01")
        mock_subprocess_run.assert_not_called()

        mock_subprocess_run.return_value = MagicMock(stdout="List of devices attached\n\n", returncode=0)
        self.assertIsNone(get_device_serial(adb_exe_path=self.mock_adb_exe_path))
        mock_print.assert_any_call("Error: No Android devices found.")

        mock_subprocess_run.return_value = MagicMock(stdout="List of devices attached\nserial123\tdevice\n", returncode=0)
        self.assertEqual(get_device_serial(adb_exe_path=self.mock_adb_exe_path), "serial123")

        mock_subprocess_run.return_value = MagicMock(stdout="List of devices attached\nserial123\tdevice\nserial456\tdevice\n", returncode=0)
        self.assertIsNone(get_device_serial(adb_exe_path=self.mock_adb_exe_path))
        mock_print.assert_any_call("Error: Multiple devices connected. Please specify one using --device SERIAL:")

        mock_subprocess_run.return_value = MagicMock(stdout="List of devices attached\nserial789\toffline\n", returncode=0)
        self.assertIsNone(get_device_serial(adb_exe_path=self.mock_adb_exe_path))

        mock_subprocess_run.return_value = MagicMock(stderr="adb server failed", returncode=1)
        self.assertIsNone(get_device_serial(adb_exe_path=self.mock_adb_exe_path))
        mock_print.assert_any_call("Error running 'adb devices': adb server failed")

        mock_subprocess_run.side_effect = FileNotFoundError
        self.assertIsNone(get_device_serial(adb_exe_path=self.mock_adb_exe_path))
        mock_print.assert_any_call(f"Error: ADB executable not found at '{self.mock_adb_exe_path}' when trying to list devices.")


    @patch('artifact_extractor.find_adb_exe')
    @patch('artifact_extractor.get_device_serial')
    @patch('artifact_extractor.extract_artifact')
    @patch('builtins.print')
    @patch('os.makedirs')
    def test_run_extraction_artifact_selection(self, mock_os_makedirs, mock_print, mock_extract_artifact, mock_get_device_serial, mock_find_adb):
        mock_find_adb.return_value = self.mock_adb_exe_path
        mock_get_device_serial.return_value = 'test_serial_mocked'

        args_list = argparse.Namespace(output="out", list_artifacts=True, all=False, artifacts=None, device=None, verbose=False)
        with patch.dict('artifact_extractor.ARTIFACTS_DB', ORIGINAL_ARTIFACTS_DB, clear=True):
            run_extraction(args_list)
        mock_print.assert_any_call("\nAvailable artifacts:")
        self.assertTrue(any(f"contacts_db: {ORIGINAL_ARTIFACTS_DB['contacts_db']['display_name']}" in call.args[0] for call in mock_print.call_args_list if call.args and "contacts_db" in call.args[0] ))
        mock_extract_artifact.assert_not_called()
        mock_os_makedirs.assert_not_called()

        mock_extract_artifact.reset_mock(); mock_os_makedirs.reset_mock(); mock_print.reset_mock()
        args_all = argparse.Namespace(output="out", list_artifacts=False, all=True, artifacts=None, device=None, verbose=False)
        test_db_all = {"test_art1": {"display_name": "Test Art 1", "category":"C1"}, "test_art2": {"display_name": "Test Art 2", "category":"C2"}}
        with patch.dict('artifact_extractor.ARTIFACTS_DB', test_db_all, clear=True):
            run_extraction(args_all)
            self.assertEqual(mock_extract_artifact.call_count, len(test_db_all))
            called_artifact_keys_all = sorted([call[0][0] for call in mock_extract_artifact.call_args_list])
            self.assertEqual(called_artifact_keys_all, sorted(test_db_all.keys()))
            mock_os_makedirs.assert_any_call(os.path.join(args_all.output, mock_get_device_serial.return_value), exist_ok=True)

        mock_extract_artifact.reset_mock(); mock_os_makedirs.reset_mock(); mock_print.reset_mock()
        test_db_specific = {"art1": {"category":"C1"}, "art2": {"category":"C1"}, "art3": {"category":"C1"}}
        with patch.dict('artifact_extractor.ARTIFACTS_DB', test_db_specific, clear=True):
            args_specific = argparse.Namespace(output="out", list_artifacts=False, all=False, artifacts="art1,art3", device=None, verbose=False)
            run_extraction(args_specific)
            self.assertEqual(mock_extract_artifact.call_count, 2)
            called_artifact_keys_specific = sorted([call[0][0] for call in mock_extract_artifact.call_args_list])
            self.assertEqual(called_artifact_keys_specific, ['art1', 'art3'])
            mock_os_makedirs.assert_any_call(os.path.join(args_specific.output, mock_get_device_serial.return_value), exist_ok=True)

        mock_extract_artifact.reset_mock(); mock_os_makedirs.reset_mock(); mock_print.reset_mock()
        with patch.dict('artifact_extractor.ARTIFACTS_DB', ORIGINAL_ARTIFACTS_DB, clear=True):
            args_none = argparse.Namespace(output="out", list_artifacts=False, all=False, artifacts=None, device=None, verbose=False)
            run_extraction(args_none)
            mock_extract_artifact.assert_not_called()
            mock_os_makedirs.assert_not_called()
        mock_print.assert_any_call("No artifacts specified. Use --artifacts KEY1,KEY2 or --all. Use --list-artifacts to see keys.")

    # Removed @patch('artifact_extractor.VERBOSE', True)
    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    @patch('artifact_extractor.execute_adb_command')
    @patch('builtins.print')
    def test_extract_artifact_file_type(self, mock_print, mock_execute_adb, mock_open_file, mock_os_makedirs): # Removed mock_verbose_patch
        with patch('artifact_extractor.VERBOSE', True): # Context manager for VERBOSE
            mock_execute_adb.return_value = MagicMock(returncode=0, stdout="Pulled: 1 file", stderr="")
            artifact_info = {"display_name": "Test File", "category": "Test Category", "type": "file", "paths": ["/data/test.txt"], "requires_root": True}
            result = extract_artifact("test_file", artifact_info, "/output/device1", "serial1")
            self.assertTrue(result)
            mock_os_makedirs.assert_called_with(os.path.join("/output/device1", "Test Category"), exist_ok=True)
            mock_execute_adb.assert_called_with(['pull', '/data/test.txt', os.path.join("/output/device1", "Test Category", "test.txt")], "serial1")
            mock_print.assert_any_call("Note: This artifact typically requires root access.")

            mock_execute_adb.reset_mock()
            mock_print.reset_mock() # Reset print mock as well
            mock_execute_adb.side_effect = [MagicMock(returncode=1, stderr="No such file"), MagicMock(returncode=0, stderr="")]
            artifact_info_multi = {"display_name": "Multi Path File", "category": "Cat", "type": "file", "paths": ["/data/nonexistent.txt", "/data/existent.txt"]}
            result_multi = extract_artifact("multi_file", artifact_info_multi, "/output/dev", "s1")
            self.assertTrue(result_multi)
            self.assertEqual(mock_execute_adb.call_count, 2)
            mock_execute_adb.assert_called_with(['pull', '/data/existent.txt', os.path.join("/output/dev", "Cat", "existent.txt")], "s1")

            mock_execute_adb.reset_mock(); mock_execute_adb.side_effect = None
            mock_print.reset_mock()
            mock_execute_adb.return_value = MagicMock(returncode=1, stderr="Permission denied")
            result_fail = extract_artifact("fail_file", artifact_info_multi, "/output/dev", "s1")
            self.assertFalse(result_fail); self.assertEqual(mock_execute_adb.call_count, 2)

    # Removed @patch('artifact_extractor.VERBOSE', True)
    @patch('os.makedirs')
    @patch('artifact_extractor.execute_adb_command')
    def test_extract_artifact_directory_type(self, mock_execute_adb, mock_os_makedirs): # Removed mock_verbose_patch
        with patch('artifact_extractor.VERBOSE', True): # Context manager for VERBOSE
            mock_execute_adb.return_value = MagicMock(returncode=0)
            artifact_info = {"display_name": "Test Dir", "category": "Test Dirs", "type": "directory", "paths": ["/sdcard/TestDir"]}
            result = extract_artifact("test_dir", artifact_info, "/output/device1", "serial1")
            self.assertTrue(result)
            mock_os_makedirs.assert_called_with(os.path.join("/output/device1", "Test Dirs"), exist_ok=True)
            mock_execute_adb.assert_called_with(['pull', '/sdcard/TestDir', os.path.join("/output/device1", "Test Dirs")], "serial1")

    # Removed @patch('artifact_extractor.VERBOSE', True)
    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    @patch('artifact_extractor.execute_adb_command')
    def test_extract_artifact_command_type(self, mock_execute_adb, mock_open_file, mock_os_makedirs): # Removed mock_verbose_patch
        with patch('artifact_extractor.VERBOSE', True): # Context manager for VERBOSE
            mock_execute_adb.return_value = MagicMock(returncode=0, stdout="command output here")
            artifact_info = {"display_name": "Test Command", "category": "Commands", "type": "command", "command_str": "shell ls /", "output_file": "ls_output.txt"}
            result = extract_artifact("test_cmd", artifact_info, "/output/device1", "serial1")
            self.assertTrue(result)
            mock_os_makedirs.assert_called_with(os.path.join("/output/device1", "Commands"), exist_ok=True)
            mock_execute_adb.assert_called_with(['shell', 'ls', '/'], "serial1")
            mock_open_file.assert_called_once_with(os.path.join("/output/device1", "Commands", "ls_output.txt"), 'w', encoding='utf-8')
            mock_open_file().write.assert_called_once_with("command output here")

            mock_execute_adb.reset_mock(); mock_open_file.reset_mock()
            mock_execute_adb.return_value = MagicMock(returncode=1, stderr="command failed")
            result_fail = extract_artifact("test_cmd_fail", artifact_info, "/output/device1", "serial1")
            self.assertFalse(result_fail)

    def test_setup_arg_parser(self):
        parser = setup_arg_parser()
        args = parser.parse_args(['--output', 'my_out', '--all', '--verbose'])
        self.assertEqual(args.output, 'my_out'); self.assertTrue(args.all); self.assertTrue(args.verbose)

        args_specific = parser.parse_args(['--output', 'o', '--artifacts', 'a,b,c', '--device', 's1'])
        self.assertEqual(args_specific.artifacts, 'a,b,c'); self.assertEqual(args_specific.device, 's1')

if __name__ == '__main__':
    unittest.main()
