"""PS3 function NIDs: the first four bytes of SHA-1 over the name and Sony's fixed suffix, read
little-endian. Names come from the lists in names/ (one per line, # for comments)."""

import hashlib
import os
import struct

SUFFIX = bytes.fromhex("6759659904250490566427499489741A")
NAMES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "names")


def nid(name):
    return struct.unpack("<I", hashlib.sha1(name.encode() + SUFFIX).digest()[:4])[0]


def load_names(directory=NAMES_DIR):
    """{nid: name} from every names/*.txt"""
    names = {}
    for file_name in sorted(os.listdir(directory)):
        if not file_name.endswith(".txt"):
            continue
        with open(os.path.join(directory, file_name)) as file:
            for line in file:
                line = line.split("#", 1)[0].strip()
                if line:
                    names[nid(line)] = line
    return names
