"""shared/tools/editor_setup.py's rewriting: a console build's command line turned into one this
machine's clang reads, with the project's paths and the SDK's where they are here."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import editor_setup  # noqa: E402

REPO = str(editor_setup.REPOSITORY)
SDK = Path("/here/sdk")
PS3 = editor_setup.CONSOLES["ps3"]
VITA = editor_setup.CONSOLES["vita"]


class EditorSetupTests(unittest.TestCase):
    def test_keeps_only_what_says_how_the_file_reads(self):
        kept = editor_setup.kept_arguments(["gcc", "-DA=1", "-D", "B", "-UC", "-Ione", "-I", "two", "-isystem", "/s", "-include/x.h",
                                            "-std=gnu11", "-O2", "-mcpu=cell", "-Werror", "-o", "out.o", "-c", "file.c"])
        self.assertEqual(kept, [("-D", "A=1"), ("-D", "B"), ("-U", "C"), ("-I", "one"), ("-I", "two"), ("-isystem", "/s"),
                                ("-include", "/x.h"), ("-std=gnu11", None)])

    def test_paths_on_this_machine(self):
        self.assertEqual(editor_setup.mapped("/src/ps3/a.c", "/src", SDK), REPO + "/ps3/a.c")
        self.assertEqual(editor_setup.mapped("/opt/sdk/x/../inc", "/src", SDK), "/here/sdk/opt/sdk/inc")
        self.assertEqual(editor_setup.mapped(REPO + "/vita/a.c", None, SDK), REPO + "/vita/a.c")
        self.assertEqual(editor_setup.mapped("relative/inc", "/src", SDK), "relative/inc")

    def test_a_ps3_entry(self):
        entry = {"directory": "/src/ps3/build/x", "file": "/src/ps3/a.c",
                 "command": 'gcc -DNAME=\\"v\\" -I/src/ps3/common -isystem /opt/s/simd -include/src/ps3/build/x/stamp.h -mcpu=cell -c /src/ps3/a.c'}
        result = editor_setup.rewritten(entry, PS3, SDK, ["/opt/sys"], ["__PPU__=1"])
        arguments = result["arguments"]
        self.assertEqual(result["file"], REPO + "/ps3/a.c")
        self.assertEqual(result["directory"], REPO + "/ps3/build/x")
        self.assertIn("--target=powerpc-unknown-elf", arguments)
        self.assertIn("-nostdinc", arguments)
        self.assertIn('-DNAME="v"', arguments)
        self.assertIn(REPO + "/ps3/common", arguments)
        self.assertIn("/here/sdk/opt/s/simd", arguments)
        self.assertIn(REPO + "/ps3/build/x/stamp.h", arguments)
        self.assertIn("/here/sdk/opt/sys", arguments)
        self.assertIn("-D__PPU__=1", arguments)
        self.assertNotIn("-mcpu=cell", arguments)
        self.assertEqual(arguments[-2:], ["-c", REPO + "/ps3/a.c"])

    def test_a_define_naming_a_project_file(self):
        entry = {"directory": "/src/ps3", "file": "/src/ps3/a.c", "arguments": ["cc", '-DCONFIG="/src/ps3/config.h"', "a.c"]}
        self.assertIn(f'-DCONFIG="{REPO}/ps3/config.h"', editor_setup.rewritten(entry, PS3, SDK, [], [])["arguments"])

    def test_a_vita_entry_keeps_its_paths(self):
        entry = {"directory": REPO + "/vita/build/x", "file": REPO + "/vita/a.c", "arguments": ["gcc", "-I" + REPO + "/vita/inc", "-c", "a.c"]}
        result = editor_setup.rewritten(entry, VITA, SDK, [], [])
        self.assertIn(REPO + "/vita/inc", result["arguments"])
        self.assertIn("--target=arm-none-eabi", result["arguments"])

    def test_an_entry_can_have_its_own_target(self):
        entry = {"directory": "/src/ps3", "file": "/src/ps3/k.c", "arguments": ["cc", "k.c"], "_target": ["--target=powerpc64-unknown-elf"]}
        self.assertIn("--target=powerpc64-unknown-elf", editor_setup.rewritten(entry, PS3, SDK, [], [])["arguments"])

    def test_the_compilers_answer(self):
        output = "x\n#include <...> search starts here:\n /a/b/../c\n /d\nEnd of search list.\n#define __vita__ 1\n#define EMPTY \n#define OTHER 2\n"
        folders, defines = editor_setup.parse_compiler(output, ["__vita__", "EMPTY", "ABSENT"])
        self.assertEqual(folders, ["/a/c", "/d"])
        self.assertEqual(defines, ["__vita__=1", "EMPTY"])

    def test_folders_inside_others_are_copied_once(self):
        self.assertEqual(editor_setup.without_nested(["/a/b", "/a", "/ab", "/a"]), ["/a", "/ab"])


if __name__ == "__main__":
    unittest.main()
