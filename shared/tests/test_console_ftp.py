"""shared/tools/console_ftp.py against a stand-in server: a listing's files without its folders, and a
fetch that copies what's wanted and deletes nothing."""
import ftplib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import console_ftp  # noqa: E402

FILES = {"/reports": {"connection-test-1.txt": b"report", "notes.txt": b"other"},
         "/logs": {"vitals.log": b"log", "vitals.log.old": b"old", "vitals-app.log": b"app"}}


class Server:
    def __init__(self):
        self.folder = None
        self.commands = []

    def cwd(self, folder):
        if folder not in FILES:
            raise ftplib.error_perm("550 no")
        self.folder = folder

    def retrlines(self, command, each):
        self.commands.append(command)
        each("drwxrwxrwx 1 root root 512 Nov 09 12:00 a folder")
        for name, data in FILES[self.folder].items():
            each(f"-rw-rw-rw- 1 root root {len(data)} Nov 09 12:00 {name}")

    def retrbinary(self, command, write):
        self.commands.append(command)
        write(FILES[self.folder][command.split(" ", 1)[1]])


class ConsoleFtpTests(unittest.TestCase):
    def test_listing_gives_files_only(self):
        self.assertEqual(console_ftp.listing(Server(), "/reports"), {"connection-test-1.txt": 6, "notes.txt": 5})

    def test_listing_of_a_missing_folder(self):
        self.assertIsNone(console_ftp.listing(Server(), "/none"))

    def test_fetch_copies_what_is_wanted_and_deletes_nothing(self):
        server = Server()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "fetched"
            console_ftp.fetch(server, [("/reports", ("connection-test-",), True), ("/none", ("x",), True),
                                       ("/logs", ("vitals.log", "vitals-app.log"), True)], str(target), temporary)
            self.assertEqual(sorted(path.name for path in target.iterdir()),
                             ["connection-test-1.txt", "vitals-app.log", "vitals.log", "vitals.log.old"])
            self.assertEqual((target / "vitals-app.log").read_bytes(), b"app")
        self.assertTrue(all(command.startswith(("LIST", "RETR")) for command in server.commands))


if __name__ == "__main__":
    unittest.main()
