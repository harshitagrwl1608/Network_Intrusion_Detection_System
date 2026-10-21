import os
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.blocklist import atomic_write_text, download_blocklist, load_blocklist


class TestBlocklistPathHandling(unittest.TestCase):
    def test_download_accepts_bare_filename_without_network_access(self):
        response = Mock()
        response.text = "198.51.100.1\n"
        response.raise_for_status.return_value = None
        old_cwd = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.chdir(tmp)
                with patch("requests.get", return_value=response) as get:
                    self.assertTrue(download_blocklist("https://feed.invalid", "local.txt"))
                get.assert_called_once()
                with open("local.txt", encoding="utf-8") as feed:
                    self.assertEqual(feed.read(), response.text)
        finally:
            os.chdir(old_cwd)

    def test_malformed_empty_csv_rows_do_not_abort_blocklist_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "feed.txt")
            with open(path, "w", encoding="utf-8") as feed:
                feed.write(",\n,,\n192.0.2.1,metadata\n")
            result = load_blocklist(path, url=None)
        self.assertEqual(result.exact, {"192.0.2.1"})
        self.assertEqual(result.networks, [])

    def test_updater_accepts_bare_filename(self):
        updater_dir = os.path.join(PROJECT_DIR, "data")
        if updater_dir not in sys.path:
            sys.path.insert(0, updater_dir)
        import update_blocklist

        old_cwd = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.chdir(tmp)
                update_blocklist.write_blocklist("local.txt", {"192.0.2.1"})
                with open("local.txt", encoding="utf-8") as feed:
                    self.assertIn("192.0.2.1\n", feed.read())
        finally:
            os.chdir(old_cwd)

    def test_failed_atomic_replace_preserves_existing_file_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "feed.txt")
            with open(path, "w", encoding="utf-8") as feed:
                feed.write("known-good\n")
            with patch("engine.blocklist.os.replace", side_effect=OSError("simulated replace failure")):
                with self.assertRaises(OSError):
                    atomic_write_text(path, "replacement\n")
            with open(path, encoding="utf-8") as feed:
                self.assertEqual(feed.read(), "known-good\n")
            self.assertEqual(os.listdir(tmp), ["feed.txt"])

    def test_successful_atomic_replace_preserves_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "feed.txt")
            with open(path, "w", encoding="utf-8") as feed:
                feed.write("old\n")
            os.chmod(path, 0o640)
            atomic_write_text(path, "new\n")
            with open(path, encoding="utf-8") as feed:
                self.assertEqual(feed.read(), "new\n")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o640)


if __name__ == "__main__":
    unittest.main()
