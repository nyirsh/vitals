"""shared/tools/make_app_art.py: each small image at its size and in the format its console takes, the
Vita's as 8-bit palette PNGs; and the font reader's answers for the text the art uses. The 1920x1080
background is left out, for time: it's drawn the same way."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import make_app_art  # noqa: E402


def header(path):
    data = path.read_bytes()
    return struct.unpack(">IIBB", data[16:26])


class AppArtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.title, cls.subtitle = make_app_art.Font(make_app_art.TITLE_FONT), make_app_art.Font(make_app_art.SUBTITLE_FONT)

    def test_the_small_images(self):
        with tempfile.TemporaryDirectory() as temporary, redirect_stdout(io.StringIO()):
            base = Path(temporary)
            pkg, sce = base / "pkg", base / "sce_sys"
            pkg.mkdir()
            (sce / "livearea" / "contents").mkdir(parents=True)
            make_app_art.ps3_wide_icon(pkg, self.title, self.subtitle)
            make_app_art.vita_background(sce)
            make_app_art.square_icon(pkg, sce, self.title, self.subtitle)
            make_app_art.vita_loading(sce, self.title, self.subtitle)
            make_app_art.vita_gate(sce, self.title, self.subtitle)
            self.assertEqual(header(sce / "pic0.png"), (960, 544, 8, 3))
            self.assertEqual(header(sce / "livearea" / "contents" / "startup.png"), (280, 158, 8, 3))
            self.assertEqual(header(pkg / "ICON0.PNG"), (320, 176, 8, 6))
            self.assertEqual(header(pkg / "ICON0-wide.PNG"), (320, 176, 8, 6))
            self.assertEqual(header(sce / "icon0.png"), (128, 128, 8, 3))
            background = sce / "livearea" / "contents" / "bg.png"
            self.assertEqual(header(background), (840, 500, 8, 3))
            # At most a 256-colour palette, as the LiveArea takes
            data = background.read_bytes()
            at = data.index(b"PLTE")
            self.assertLessEqual(struct.unpack(">I", data[at - 4:at])[0], 768)

    def test_the_same_drawing_gives_the_same_file(self):
        with tempfile.TemporaryDirectory() as temporary, redirect_stdout(io.StringIO()):
            base = Path(temporary)
            for name in ("one", "two"):
                (base / name).mkdir()
                make_app_art.ps3_wide_icon(base / name, self.title, self.subtitle)
            self.assertEqual((base / "one/ICON0-wide.PNG").read_bytes(), (base / "two/ICON0-wide.PNG").read_bytes())

    def test_the_fonts_have_the_text(self):
        for font in (self.title, self.subtitle):
            for character in "vitalsTLS Toolkit":
                glyph = font.glyph(ord(character))
                self.assertNotEqual(glyph, 0, character)
                self.assertGreater(font.advance(glyph), 0)
                if character != " ":
                    self.assertGreater(len(font.lines(glyph, 0.1, 0, 0)), 3, character)

    def test_a_kerned_pair(self):
        # "To" tucks the o under the T in a font with kerning
        self.assertLess(self.subtitle.kerning(self.subtitle.glyph(ord("T")), self.subtitle.glyph(ord("o"))), 0)

    def test_quantize_keeps_few_colours_as_they_are(self):
        pixels = [(1, 2, 3), (4, 5, 6), (1, 2, 3), (200, 0, 0)]
        palette, entry = make_app_art.quantize(pixels)
        rebuilt = {colour: tuple(palette[entry[colour] * 3:entry[colour] * 3 + 3]) for colour in set(pixels)}
        self.assertEqual(rebuilt, {colour: colour for colour in set(pixels)})


if __name__ == "__main__":
    unittest.main()
