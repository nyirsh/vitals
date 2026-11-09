#!/usr/bin/env python3
"""Draws both apps' art, so it's one design in one place, with nothing but Python and the fonts in
shared/assets/fonts: the PS3's PIC1.PNG (1920x1080, the XMB's background), PIC0.PNG (1000x560) and PIC2.PNG (310x250),
fully transparent, ICON0.PNG and ICON0-wide.PNG (320x176), and the
Vita's icon0.png (128x128), pic0.png (960x544, shown while it loads), and livearea/contents/bg.png
(840x500) and startup.png (280x158, the gate). The PS3's ICON0.PNG is the Vita's icon, whole, on a
transparent 320x176. The Vita's are 8-bit palette PNGs, which is what its LiveArea takes.

    shared/tools/make_app_art.py [--pkg FOLDER] [--sce-sys FOLDER]

make art at the top of the repository runs it; review and commit the images."""
import argparse
from array import array
from collections import Counter
import math
from pathlib import Path
import struct
import zlib

REPOSITORY = Path(__file__).resolve().parents[2]
FONTS = REPOSITORY / "shared" / "assets" / "fonts"
# Aileron, by Sora Sagano (dotcolon.net), which is CC0: no rights reserved
TITLE_FONT = FONTS / "Aileron-SemiBold.otf"
SUBTITLE_FONT = FONTS / "Aileron-Regular.otf"


def rgb(value):
    return ((value >> 16) / 255.0, ((value >> 8) & 255) / 255.0, (value & 255) / 255.0)


TOP, BOTTOM = rgb(0x0a1f41), rgb(0x066d78)
ICON_TOP, ICON_BOTTOM = rgb(0x123356), rgb(0x076d79)
MINT, WHITE, SUBTITLE = rgb(0x3ce5c7), rgb(0xf5fafc), rgb(0x9ce8dc)
GRID, GRID_ALPHA = rgb(0x409ab0), 0.22

# The heartbeat on the 840x500 layout: flat, a small bump, the spike, a wider bump, flat
HEARTBEAT = ((0, 349), (545, 349), (565, 333), (583, 350), (605, 350), (622, 375), (640, 210), (658, 410), (676, 350),
             (705, 350), (731, 318), (757, 350), (840, 350))
MITER_LIMIT = 10.0

# Where the Vita's text goes: (size, x, baseline) for the title and the subtitle, x being the middle it's
# centred on: the icon's, and the loading image's, centred on the screen at the gate's size
LOADING_TEXT = ((64.0, 481.0, 281.5), (22.0, 480.0, 309.5))
ICON_TEXT = ((38.42, 64.0, 69.5), (15.51, 63.0, 86.5))


# ---- OpenType: outlines (TrueType's or CFF's), advances and kerning, from the font's own tables ----

class Font:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        count = struct.unpack(">H", self.data[4:6])[0]
        self.tables = {}
        for i in range(count):
            tag, _, offset, length = struct.unpack(">4sIII", self.data[12 + i * 16:28 + i * 16])
            self.tables[tag.decode("latin1")] = (offset, length)
        head = self.tables["head"][0]
        self.units = self._u16(head + 18)
        self.long_loca = self._u16(head + 50) != 0
        self.glyph_count = self._u16(self.tables["maxp"][0] + 4)
        self.metric_count = self._u16(self.tables["hhea"][0] + 34)
        self.cmap = self._read_cmap()
        self.kerning_lookups = self._read_kerning_lookups()
        self.cff = self._read_cff() if "CFF " in self.tables else None

    def _u16(self, at):
        return struct.unpack(">H", self.data[at:at + 2])[0]

    def _i16(self, at):
        return struct.unpack(">h", self.data[at:at + 2])[0]

    def _u32(self, at):
        return struct.unpack(">I", self.data[at:at + 4])[0]

    def _read_cmap(self):
        base = self.tables["cmap"][0]
        records = [(self._u16(base + 4 + i * 8), self._u16(base + 6 + i * 8), self._u32(base + 8 + i * 8))
                   for i in range(self._u16(base + 2))]
        for platform, encoding in ((3, 10), (0, 4), (3, 1), (0, 3)):
            for p, e, offset in records:
                if (p, e) == (platform, encoding) and self._u16(base + offset) in (4, 12):
                    return base + offset
        raise SystemExit("The font has no Unicode character map this can read")

    def glyph(self, code):
        table = self.cmap
        if self._u16(table) == 12:
            for i in range(self._u32(table + 12)):
                start, end, first = struct.unpack(">III", self.data[table + 16 + i * 12:table + 28 + i * 12])
                if start <= code <= end:
                    return first + code - start
            return 0
        segments = self._u16(table + 6) // 2
        for i in range(segments):
            end = self._u16(table + 14 + i * 2)
            if code > end:
                continue
            start = self._u16(table + 16 + segments * 2 + i * 2)
            if code < start:
                return 0
            delta = self._u16(table + 16 + segments * 4 + i * 2)
            at = table + 16 + segments * 6 + i * 2
            offset = self._u16(at)
            if offset == 0:
                return (code + delta) & 0xffff
            index = self._u16(at + offset + (code - start) * 2)
            return (index + delta) & 0xffff if index else 0
        return 0

    def advance(self, glyph):
        base = self.tables["hmtx"][0]
        return self._u16(base + min(glyph, self.metric_count - 1) * 4)

    def lines(self, glyph, scale, x_origin, y_origin):
        """The glyph's outline as straight lines, in pixels with y going down"""
        if self.cff is not None:
            return self._cff_lines(glyph, scale, x_origin, y_origin)
        return flatten(self.contours(glyph), scale, x_origin, y_origin)

    def _cff_index(self, at):
        """The (start, end) of each entry of the CFF INDEX at at, and where the INDEX ends"""
        count = self._u16(at)
        if count == 0:
            return [], at + 2
        size = self.data[at + 2]
        offsets = [int.from_bytes(self.data[at + 3 + i * size:at + 3 + (i + 1) * size], "big") for i in range(count + 1)]
        base = at + 3 + (count + 1) * size - 1
        return [(base + offsets[i], base + offsets[i + 1]) for i in range(count)], base + offsets[count]

    def _cff_dict(self, start, end):
        values, stack, p = {}, [], start
        while p < end:
            b = self.data[p]
            p += 1
            if b <= 21:
                if b == 12:
                    b = 1200 + self.data[p]
                    p += 1
                values[b] = stack
                stack = []
            elif b == 28:
                stack.append(self._i16(p))
                p += 2
            elif b == 29:
                stack.append(struct.unpack(">i", self.data[p:p + 4])[0])
                p += 4
            elif b == 30:
                while self.data[p] & 15 != 15 and self.data[p] >> 4 != 15:
                    p += 1
                p += 1
                stack.append(0)
            elif b <= 246:
                stack.append(b - 139)
            elif b <= 250:
                stack.append((b - 247) * 256 + self.data[p] + 108)
                p += 1
            else:
                stack.append(-(b - 251) * 256 - self.data[p] - 108)
                p += 1
        return values

    def _read_cff(self):
        base = self.tables["CFF "][0]
        _, at = self._cff_index(base + self.data[base + 2])
        tops, at = self._cff_index(at)
        _, at = self._cff_index(at)
        global_subrs, _ = self._cff_index(at)
        top = self._cff_dict(*tops[0])
        charstrings, _ = self._cff_index(base + top[17][0])
        local_subrs = []
        if 18 in top:
            size, offset = top[18]
            private = self._cff_dict(base + offset, base + offset + size)
            if 19 in private:
                local_subrs, _ = self._cff_index(base + offset + private[19][0])
        return charstrings, global_subrs, local_subrs

    def _cff_lines(self, glyph, scale, x_origin, y_origin):
        """Runs the glyph's Type 2 charstring, for its outline: hints are read past"""
        charstrings, global_subrs, local_subrs = self.cff
        lines = []
        state = {"x": 0, "y": 0, "stems": 0, "width_read": False, "open": None, "done": False}
        stack = []

        def place():
            return x_origin + state["x"] * scale, y_origin - state["y"] * scale

        def close():
            if state["open"] is not None and state["open"][0] != place():
                lines.append((place(), state["open"][0]))
            state["open"] = None

        def move(dx, dy):
            close()
            state["x"] += dx
            state["y"] += dy
            state["open"] = (place(),)

        def line(dx, dy):
            start = place()
            state["x"] += dx
            state["y"] += dy
            lines.append((start, place()))

        def curve(dx1, dy1, dx2, dy2, dx3, dy3):
            p0 = place()
            state["x"] += dx1
            state["y"] += dy1
            p1 = place()
            state["x"] += dx2
            state["y"] += dy2
            p2 = place()
            state["x"] += dx3
            state["y"] += dy3
            p3, previous = place(), p0
            for step in range(1, 17):
                t = step / 16
                u = 1 - t
                point = tuple(u * u * u * p0[c] + 3 * u * u * t * p1[c] + 3 * u * t * t * p2[c] + t * t * t * p3[c] for c in range(2))
                lines.append((previous, point))
                previous = point

        def take_width(expected_odd):
            if not state["width_read"]:
                state["width_read"] = True
                if expected_odd:
                    del stack[0]

        def bias(subrs):
            return 107 if len(subrs) < 1240 else 1131 if len(subrs) < 33900 else 32768

        def run(start, end):
            p = start
            while p < end and not state["done"]:
                b = self.data[p]
                p += 1
                if b >= 32 or b == 28:
                    if b == 28:
                        stack.append(self._i16(p))
                        p += 2
                    elif b <= 246:
                        stack.append(b - 139)
                    elif b <= 250:
                        stack.append((b - 247) * 256 + self.data[p] + 108)
                        p += 1
                    elif b <= 254:
                        stack.append(-(b - 251) * 256 - self.data[p] - 108)
                        p += 1
                    else:
                        stack.append(struct.unpack(">i", self.data[p:p + 4])[0] / 65536)
                        p += 4
                    continue
                if b in (1, 3, 18, 23):
                    take_width(len(stack) % 2 == 1)
                    state["stems"] += len(stack) // 2
                    stack.clear()
                elif b in (19, 20):
                    take_width(len(stack) % 2 == 1)
                    state["stems"] += len(stack) // 2
                    stack.clear()
                    p += (state["stems"] + 7) // 8
                elif b == 21:
                    take_width(len(stack) > 2)
                    move(stack[0], stack[1])
                    stack.clear()
                elif b == 22:
                    take_width(len(stack) > 1)
                    move(stack[0], 0)
                    stack.clear()
                elif b == 4:
                    take_width(len(stack) > 1)
                    move(0, stack[0])
                    stack.clear()
                elif b == 5:
                    for i in range(0, len(stack) - 1, 2):
                        line(stack[i], stack[i + 1])
                    stack.clear()
                elif b in (6, 7):
                    horizontal = b == 6
                    for value in stack:
                        line(value, 0) if horizontal else line(0, value)
                        horizontal = not horizontal
                    stack.clear()
                elif b == 8:
                    for i in range(0, len(stack) - 5, 6):
                        curve(*stack[i:i + 6])
                    stack.clear()
                elif b == 24:
                    for i in range(0, len(stack) - 2, 6):
                        curve(*stack[i:i + 6])
                    line(stack[-2], stack[-1])
                    stack.clear()
                elif b == 25:
                    i = 0
                    while i + 6 < len(stack):
                        line(stack[i], stack[i + 1])
                        i += 2
                    curve(*stack[i:i + 6])
                    stack.clear()
                elif b == 26:
                    i, dx = 0, 0
                    if len(stack) % 4 == 1:
                        dx, i = stack[0], 1
                    while i + 3 < len(stack):
                        curve(dx, stack[i], stack[i + 1], stack[i + 2], 0, stack[i + 3])
                        dx, i = 0, i + 4
                    stack.clear()
                elif b == 27:
                    i, dy = 0, 0
                    if len(stack) % 4 == 1:
                        dy, i = stack[0], 1
                    while i + 3 < len(stack):
                        curve(stack[i], dy, stack[i + 1], stack[i + 2], stack[i + 3], 0)
                        dy, i = 0, i + 4
                    stack.clear()
                elif b in (30, 31):
                    horizontal, i = b == 31, 0
                    while i + 3 < len(stack):
                        last = stack[i + 4] if len(stack) - i == 5 else 0
                        if horizontal:
                            curve(stack[i], 0, stack[i + 1], stack[i + 2], last, stack[i + 3])
                        else:
                            curve(0, stack[i], stack[i + 1], stack[i + 2], stack[i + 3], last)
                        horizontal, i = not horizontal, i + 4
                    stack.clear()
                elif b in (10, 29):
                    subrs = local_subrs if b == 10 else global_subrs
                    run(*subrs[int(stack.pop()) + bias(subrs)])
                elif b == 11:
                    return
                elif b == 14:
                    take_width(len(stack) in (1, 5))
                    state["done"] = True
                else:
                    raise SystemExit(f"Glyph {glyph} uses a CFF operator this doesn't read: {b}")

        run(*charstrings[glyph])
        close()
        return lines

    def contours(self, glyph):
        """A TrueType glyph's outlines, each a list of (x, y, on_curve)"""
        loca = self.tables["loca"][0]
        if self.long_loca:
            start, end = self._u32(loca + glyph * 4), self._u32(loca + glyph * 4 + 4)
        else:
            start, end = self._u16(loca + glyph * 2) * 2, self._u16(loca + glyph * 2 + 2) * 2
        if start == end:
            return []
        at = self.tables["glyf"][0] + start
        count = self._i16(at)
        return self._simple(at, count) if count >= 0 else self._composite(at + 10)

    def _simple(self, at, count):
        ends = [self._u16(at + 10 + i * 2) for i in range(count)]
        total = ends[-1] + 1 if ends else 0
        p = at + 10 + count * 2
        p += 2 + self._u16(p)
        flags = []
        while len(flags) < total:
            flag = self.data[p]
            p += 1
            flags.append(flag)
            if flag & 8:
                flags.extend([flag] * self.data[p])
                p += 1
        coordinates = []
        for short, same in ((2, 16), (4, 32)):
            value, values = 0, []
            for flag in flags:
                if flag & short:
                    value += self.data[p] if flag & same else -self.data[p]
                    p += 1
                elif not flag & same:
                    value += self._i16(p)
                    p += 2
                values.append(value)
            coordinates.append(values)
        contours, first = [], 0
        for end in ends:
            contours.append([(coordinates[0][i], coordinates[1][i], flags[i] & 1 != 0) for i in range(first, end + 1)])
            first = end + 1
        return contours

    def _composite(self, p):
        contours = []
        while True:
            flags, glyph = self._u16(p), self._u16(p + 2)
            p += 4
            if flags & 1:
                dx, dy = self._i16(p), self._i16(p + 2)
                p += 4
            else:
                dx, dy = struct.unpack(">bb", self.data[p:p + 2])
                p += 2
            a, b, c, d = 1.0, 0.0, 0.0, 1.0
            if flags & 8:
                a = d = self._i16(p) / 16384
                p += 2
            elif flags & 0x40:
                a, d = self._i16(p) / 16384, self._i16(p + 2) / 16384
                p += 4
            elif flags & 0x80:
                a, b, c, d = (self._i16(p + i * 2) / 16384 for i in range(4))
                p += 8
            for contour in self.contours(glyph):
                contours.append([(a * x + c * y + dx, b * x + d * y + dy, on) for x, y, on in contour])
            if not flags & 0x20:
                return contours

    def _coverage(self, at, glyph):
        if self._u16(at) == 1:
            for i in range(self._u16(at + 2)):
                if self._u16(at + 4 + i * 2) == glyph:
                    return i
            return None
        for i in range(self._u16(at + 2)):
            start, end, index = struct.unpack(">HHH", self.data[at + 4 + i * 6:at + 10 + i * 6])
            if start <= glyph <= end:
                return index + glyph - start
        return None

    def _class(self, at, glyph):
        if self._u16(at) == 1:
            first = self._u16(at + 2)
            return self._u16(at + 6 + (glyph - first) * 2) if first <= glyph < first + self._u16(at + 4) else 0
        for i in range(self._u16(at + 2)):
            start, end, value = struct.unpack(">HHH", self.data[at + 4 + i * 6:at + 10 + i * 6])
            if start <= glyph <= end:
                return value
        return 0

    def _read_kerning_lookups(self):
        """The subtables of GPOS's kern feature that kern pairs"""
        if "GPOS" not in self.tables:
            return []
        gpos = self.tables["GPOS"][0]
        features, lookups = gpos + self._u16(gpos + 6), gpos + self._u16(gpos + 8)
        for i in range(self._u16(features)):
            if self.data[features + 2 + i * 6:features + 6 + i * 6] != b"kern":
                continue
            feature = features + self._u16(features + 6 + i * 6)
            subtables = []
            for j in range(self._u16(feature + 2)):
                lookup = lookups + self._u16(lookups + 2 + self._u16(feature + 4 + j * 2) * 2)
                kind = self._u16(lookup)
                for k in range(self._u16(lookup + 4)):
                    subtable = lookup + self._u16(lookup + 6 + k * 2)
                    if kind == 9:
                        if self._u16(subtable + 2) != 2:
                            continue
                        subtables.append(subtable + self._u32(subtable + 4))
                    elif kind == 2:
                        subtables.append(subtable)
            return subtables
        return []

    @staticmethod
    def _value_size(value_format):
        return bin(value_format).count("1") * 2

    def _x_advance(self, at, value_format):
        if not value_format & 4:
            return 0
        return self._i16(at + bin(value_format & 3).count("1") * 2)

    def kerning(self, left, right):
        for subtable in self.kerning_lookups:
            index = self._coverage(subtable + self._u16(subtable + 2), left)
            if index is None:
                continue
            format1, format2 = self._u16(subtable + 4), self._u16(subtable + 6)
            size1, size2 = self._value_size(format1), self._value_size(format2)
            if self._u16(subtable) == 1:
                pairs = subtable + self._u16(subtable + 10 + index * 2)
                for i in range(self._u16(pairs)):
                    at = pairs + 2 + i * (2 + size1 + size2)
                    if self._u16(at) == right:
                        return self._x_advance(at + 2, format1)
                continue
            first = self._class(subtable + self._u16(subtable + 8), left)
            second = self._class(subtable + self._u16(subtable + 10), right)
            per_class = self._u16(subtable + 14)
            at = subtable + 16 + (first * per_class + second) * (size1 + size2)
            return self._x_advance(at, format1)
        return 0


def flatten(contours, scale, x_origin, y_origin):
    """Straight lines for the glyph's outlines, in pixels with y going down"""
    lines = []

    def place(point):
        return x_origin + point[0] * scale, y_origin - point[1] * scale

    for contour in contours:
        points = []
        for i, point in enumerate(contour):
            following = contour[(i + 1) % len(contour)]
            points.append(point)
            if not point[2] and not following[2]:
                points.append(((point[0] + following[0]) / 2, (point[1] + following[1]) / 2, True))
        first_on = next((i for i, p in enumerate(points) if p[2]), None)
        if first_on is None:
            continue
        points = points[first_on:] + points[:first_on]
        previous = place(points[0])
        i, n = 1, len(points)
        while i <= n:
            current = points[i % n]
            if current[2]:
                end = place(current)
                lines.append((previous, end))
                previous = end
                i += 1
                continue
            control, end = place(current), place(points[(i + 1) % n])
            for step in range(1, 13):
                t = step / 12
                u = 1 - t
                point = (u * u * previous[0] + 2 * u * t * control[0] + t * t * end[0],
                         u * u * previous[1] + 2 * u * t * control[1] + t * t * end[1])
                lines.append((previous, point) if step == 1 else (last, point))
                last = point
            previous = end
            i += 2
    return lines


def coverage_of(lines):
    """How much of each pixel the outlines cover, exactly: (left, top, width, height, values)"""
    xs = [p[0] for line in lines for p in line]
    ys = [p[1] for line in lines for p in line]
    left, top = math.floor(min(xs)), math.floor(min(ys))
    width, height = math.ceil(max(xs)) - left + 2, math.ceil(max(ys)) - top + 1
    values = [0.0] * (width * height + 2)
    for (x0, y0), (x1, y1) in lines:
        if y0 == y1:
            continue
        direction = 1.0
        if y0 > y1:
            x0, y0, x1, y1, direction = x1, y1, x0, y0, -1.0
        x0, x1, y0, y1 = x0 - left, x1 - left, y0 - top, y1 - top
        slope = (x1 - x0) / (y1 - y0)
        x = x0
        for row in range(int(y0), min(height, math.ceil(y1))):
            start = row * width
            dy = min(row + 1, y1) - max(row, y0)
            following = x + slope * dy
            d = dy * direction
            low, high = (x, following) if x < following else (following, x)
            low_floor, high_ceil = math.floor(low), math.ceil(high)
            low_i, high_i = int(low_floor), int(high_ceil)
            if high_i <= low_i + 1:
                middle = 0.5 * (x + following) - low_floor
                values[start + low_i] += d - d * middle
                values[start + low_i + 1] += d * middle
            else:
                s = 1.0 / (high - low)
                low_f = low - low_floor
                a0 = 0.5 * s * (1 - low_f) * (1 - low_f)
                high_f = high - high_ceil + 1
                am = 0.5 * s * high_f * high_f
                values[start + low_i] += d * a0
                if high_i == low_i + 2:
                    values[start + low_i + 1] += d * (1 - a0 - am)
                else:
                    a1 = s * (1.5 - low_f)
                    values[start + low_i + 1] += d * (a1 - a0)
                    for column in range(low_i + 2, high_i - 1):
                        values[start + column] += d * s
                    a2 = a1 + (high_i - low_i - 3) * s
                    values[start + high_i - 1] += d * (1 - a2 - am)
                values[start + high_i] += d * am
            x = following
    total = 0.0
    for i in range(width * height):
        total += values[i]
        values[i] = min(abs(total), 1.0)
    return left, top, width, height, values


# ---- the canvas ----

class Canvas:
    def __init__(self, width, height, top, bottom):
        self.width, self.height = width, height
        self.pixels = array("d", bytes(width * height * 3 * 8))
        for y in range(height):
            t = (y + 0.5) / height
            colour = [top[c] + (bottom[c] - top[c]) * t for c in range(3)]
            self.pixels[y * width * 3:(y + 1) * width * 3] = array("d", colour * width)

    def blend(self, x, y, colour, alpha):
        if 0 <= x < self.width and 0 <= y < self.height:
            at = (y * self.width + x) * 3
            pixels = self.pixels
            pixels[at] += (colour[0] - pixels[at]) * alpha
            pixels[at + 1] += (colour[1] - pixels[at + 1]) * alpha
            pixels[at + 2] += (colour[2] - pixels[at + 2]) * alpha

    def grid(self, step_x, start_y, step_y, offset, width):
        def band(cell, middle):
            low, high = max(middle - width / 2, cell), min(middle + width / 2, cell + 1)
            return max(high - low, 0.0)

        def lines(length, start, step):
            covers, position = [0.0] * length, start + offset
            while position < length:
                for cell in range(max(math.floor(position - width), 0), min(math.ceil(position + width) + 1, length)):
                    covers[cell] += band(cell, position)
                position += step
            return covers

        across, down = lines(self.width, step_x, step_x), lines(self.height, start_y, step_y)
        for y in range(self.height):
            if down[y] > 0:
                for x in range(self.width):
                    self.blend(x, y, GRID, GRID_ALPHA * min(max(across[x], down[y]), 1.0))
            else:
                for x in range(self.width):
                    if across[x] > 0:
                        self.blend(x, y, GRID, GRID_ALPHA * min(across[x], 1.0))

    def heartbeat(self, scale_x, scale_y, shift, width):
        """A stroke with mitred bends: each piece's samples set, so overlapping pieces count once"""
        mask = {}

        def fill(corners):
            area = sum(a[0] * b[1] - b[0] * a[1] for a, b in zip(corners, corners[1:] + corners[:1]))
            sign = 1 if area >= 0 else -1
            edges = list(zip(corners, corners[1:] + corners[:1]))
            xs, ys = [p[0] for p in corners], [p[1] for p in corners]
            for y in range(max(math.floor(min(ys)), 0), min(math.ceil(max(ys)), self.height)):
                for x in range(max(math.floor(min(xs)), 0), min(math.ceil(max(xs)), self.width)):
                    bits = 0
                    for sample in range(64):
                        px, py = x + ((sample & 7) + 0.5) / 8, y + ((sample >> 3) + 0.5) / 8
                        if all(sign * ((b[0] - a[0]) * (py - a[1]) - (b[1] - a[1]) * (px - a[0])) >= 0 for a, b in edges):
                            bits |= 1 << sample
                    if bits:
                        mask[(x, y)] = mask.get((x, y), 0) | bits

        points = [(x * scale_x, y * scale_y + shift) for x, y in HEARTBEAT]
        half, normals = width / 2, []
        for a, b in zip(points, points[1:]):
            dx, dy = b[0] - a[0], b[1] - a[1]
            length = math.hypot(dx, dy)
            n = (-dy / length * half, dx / length * half)
            normals.append(n)
            fill([(a[0] + n[0], a[1] + n[1]), (b[0] + n[0], b[1] + n[1]), (b[0] - n[0], b[1] - n[1]), (a[0] - n[0], a[1] - n[1])])
        for i in range(1, len(points) - 1):
            p, a, b = points[i], normals[i - 1], normals[i]
            side = -1 if a[0] * b[1] - a[1] * b[0] > 0 else 1
            outer_a = (p[0] + side * a[0], p[1] + side * a[1])
            outer_b = (p[0] + side * b[0], p[1] + side * b[1])
            mx, my = a[0] + b[0], a[1] + b[1]
            squared = mx * mx + my * my
            if squared > 0 and 2 * half / math.sqrt(squared) <= MITER_LIMIT:
                extent = 2 * half * half / squared
                fill([p, outer_a, (p[0] + side * mx * extent, p[1] + side * my * extent), outer_b])
            else:
                fill([p, outer_a, outer_b])
        for (x, y), bits in mask.items():
            self.blend(x, y, MINT, bin(bits).count("1") / 64)

    def text(self, font, text, size, x, baseline, colour, centred=False):
        """text with its baseline at x, baseline (or centred on x); its width"""
        scale = size / font.units
        glyphs = [font.glyph(ord(c)) for c in text]
        advances = []
        for i, glyph in enumerate(glyphs):
            kern = font.kerning(glyph, glyphs[i + 1]) if i + 1 < len(glyphs) else 0
            advances.append((font.advance(glyph) + kern) * scale)
        width = sum(advances)
        pen = x - width / 2 if centred else x
        for glyph, advance in zip(glyphs, advances):
            lines = font.lines(glyph, scale, pen, baseline)
            if lines:
                left, top, w, h, values = coverage_of(lines)
                for row in range(h):
                    for column in range(w):
                        value = values[row * w + column]
                        if value > 0:
                            self.blend(left + column, top + row, colour, value)
            pen += advance
        return width

    def bytes_rgb(self):
        out = bytearray(self.width * self.height * 3)
        for i, value in enumerate(self.pixels):
            out[i] = max(0, min(255, int(math.floor(value * 255 + 0.5))))
        return out


# ---- PNG files ----

def chunk(kind, data):
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)


def write_png(path, width, height, colour_type, raw, palette=None):
    png = [b"\x89PNG\r\n\x1a\n", chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, colour_type, 0, 0, 0))]
    if palette is not None:
        png.append(chunk(b"PLTE", bytes(palette)))
    png += [chunk(b"IDAT", zlib.compress(bytes(raw), 9)), chunk(b"IEND", b"")]
    Path(path).write_bytes(b"".join(png))
    print(path)


def save_rgba(canvas, path, wide=None, tall=None, left=0, top=0):
    """All opaque, or placed at left, top on a transparent wide x tall"""
    wide, tall = wide or canvas.width, tall or canvas.height
    source = canvas.bytes_rgb()
    stride = wide * 4 + 1
    raw = bytearray(stride * tall)
    for y in range(canvas.height):
        row = (y + top) * stride + 1 + left * 4
        for x in range(canvas.width):
            at = (y * canvas.width + x) * 3
            raw[row + x * 4:row + x * 4 + 4] = bytes((source[at], source[at + 1], source[at + 2], 255))
    write_png(path, wide, tall, 6, raw)


def save_transparent(path, width, height):
    write_png(path, width, height, 6, bytearray((width * 4 + 1) * height))


def quantize(pixels):
    """Median cut to 256 colours, the same result every time: the palette and each colour's entry"""
    counts = Counter(pixels)

    def weight(box):
        return sum(counts[colour] for colour in box)

    def widest(box):
        ranges = [max(colour[c] for colour in box) - min(colour[c] for colour in box) for c in range(3)]
        channel = max(range(3), key=lambda c: (ranges[c], -c))
        return channel, ranges[channel]

    boxes = [sorted(counts)]
    while len(boxes) < 256:
        candidates = [(weight(box) * widest(box)[1] ** 2, -i) for i, box in enumerate(boxes) if len(box) > 1]
        if not candidates or max(candidates)[0] == 0:
            break
        index = -max(candidates)[1]
        box = boxes[index]
        channel = widest(box)[0]
        box = sorted(box, key=lambda colour: (colour[channel], colour))
        total, seen, split = weight(box), 0, 0
        while split < len(box) - 1 and (split == 0 or seen < total // 2):
            seen += counts[box[split]]
            split += 1
        boxes[index], low = box[:split], box[split:]
        boxes.append(low)
    palette, entry = [], {}
    for index, box in enumerate(boxes):
        total = weight(box)
        for c in range(3):
            palette.append((sum(colour[c] * counts[colour] for colour in box) + total // 2) // total)
        for colour in box:
            entry[colour] = index
    return palette, entry


def save_palette(canvas, path):
    source = canvas.bytes_rgb()
    pixels = [tuple(source[i:i + 3]) for i in range(0, len(source), 3)]
    palette, entry = quantize(pixels)
    stride = canvas.width + 1
    raw = bytearray(stride * canvas.height)
    for y in range(canvas.height):
        for x in range(canvas.width):
            raw[y * stride + 1 + x] = entry[pixels[y * canvas.width + x]]
    write_png(path, canvas.width, canvas.height, 3, raw, palette)


# ---- the art ----

def ps3_background(folder, title, subtitle):
    canvas = Canvas(1920, 1080, TOP, BOTTOM)
    sx, sy = 1920 / 840, 1080 / 500
    canvas.grid(40 * sx, 30 * sy, 40 * sy, 0, 2)
    canvas.heartbeat(sx, sy, 0, 8)
    width = canvas.text(title, "vitals", 210, 46 * sx, 458 * sy, WHITE)
    canvas.text(subtitle, "TLS Toolkit", 64, 46 * sx + width + 28, 458 * sy, SUBTITLE)
    save_rgba(canvas, folder / "PIC1.PNG")


def ps3_wide_icon(folder, title, subtitle):
    canvas = Canvas(320, 176, ICON_TOP, ICON_BOTTOM)
    canvas.text(title, "vitals", 92, 160, 98, WHITE, centred=True)
    canvas.text(subtitle, "TLS Toolkit", 34, 160, 146, SUBTITLE, centred=True)
    save_rgba(canvas, folder / "ICON0-wide.PNG")


def vita_background(folder):
    """The LiveArea's background: the grid and the heartbeat, no text"""
    canvas = Canvas(840, 500, TOP, BOTTOM)
    canvas.grid(40, 30, 40, 0.5, 1)
    canvas.heartbeat(1, 1, 1, 5)
    save_palette(canvas, folder / "livearea" / "contents" / "bg.png")


def square_icon(pkg, sce_sys, title, subtitle, layout=ICON_TEXT):
    """The Vita's icon, and the PS3's ICON0.PNG: the same icon on a transparent 320x176"""
    canvas = Canvas(128, 128, ICON_TOP, ICON_BOTTOM)
    canvas.text(title, "vitals", layout[0][0], layout[0][1], layout[0][2], WHITE, centred=True)
    canvas.text(subtitle, "TLS Toolkit", layout[1][0], layout[1][1], layout[1][2], SUBTITLE, centred=True)
    save_palette(canvas, sce_sys / "icon0.png")
    save_rgba(canvas, pkg / "ICON0.PNG", 320, 176, 96, 24)


def ps3_empty_overlays(folder):
    """The XMB's overlays for 16:9 and 4:3 screens, with nothing on them"""
    save_transparent(folder / "PIC0.PNG", 1000, 560)
    save_transparent(folder / "PIC2.PNG", 310, 250)


def vita_loading(folder, title, subtitle):
    """Shown full screen while the app loads: the LiveArea's background at the screen's size, with the
    text in the middle, at the gate's size"""
    canvas = Canvas(960, 544, TOP, BOTTOM)
    sx, sy = 960 / 840, 544 / 500
    canvas.grid(40 * sx, 30 * sy, 40 * sy, 0, 1)
    canvas.heartbeat(sx, sy, 1, 5 * sx)
    canvas.text(title, "vitals", LOADING_TEXT[0][0], LOADING_TEXT[0][1], LOADING_TEXT[0][2], WHITE, centred=True)
    canvas.text(subtitle, "TLS Toolkit", LOADING_TEXT[1][0], LOADING_TEXT[1][1], LOADING_TEXT[1][2], SUBTITLE, centred=True)
    save_palette(canvas, folder / "pic0.png")


def vita_gate(folder, title, subtitle):
    """The LiveArea's gate. The system puts its Start button along the bottom, so the text sits higher"""
    canvas = Canvas(280, 158, ICON_TOP, ICON_BOTTOM)
    canvas.text(title, "vitals", 64, 140, 78, WHITE, centred=True)
    canvas.text(subtitle, "TLS Toolkit", 22, 140, 106, SUBTITLE, centred=True)
    save_palette(canvas, folder / "livearea" / "contents" / "startup.png")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pkg", type=Path, default=REPOSITORY / "ps3" / "vitals-app" / "pkg")
    parser.add_argument("--sce-sys", type=Path, default=REPOSITORY / "psv" / "vitals-app" / "sce_sys")
    args = parser.parse_args()
    title, subtitle = Font(TITLE_FONT), Font(SUBTITLE_FONT)
    ps3_background(args.pkg, title, subtitle)
    ps3_wide_icon(args.pkg, title, subtitle)
    vita_background(args.sce_sys)
    square_icon(args.pkg, args.sce_sys, title, subtitle)
    ps3_empty_overlays(args.pkg)
    vita_loading(args.sce_sys, title, subtitle)
    vita_gate(args.sce_sys, title, subtitle)


if __name__ == "__main__":
    main()
