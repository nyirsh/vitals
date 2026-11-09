#!/usr/bin/env python3
"""make editor: VS Code's code navigation and error checking without either SDK on this machine.

Both consoles build in Docker, so the headers and the compiler VS Code would ask are in the images.
This copies the headers the SDK's compiler searches out of the image into <console>/build/editor/sdk/,
and writes <console>/build/editor/compile_commands.json from the builds' own: every file's defines and
include folders, pointing at those headers, for this machine's clang to stand in for the console's
compiler (its target, and the SDK compiler's own defines, as the real one has them). Then it checks
that every file of the project finds its headers.

    shared/tools/editor_setup.py vita|ps3 [--image IMAGE]

Run it after building (make), and again after a new SDK image or new source files."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import shutil
import subprocess
import sys

REPOSITORY = Path(__file__).resolve().parents[2]
ENTRIES_FILE = "compile_commands.json"

CONSOLES = {
    "vita": {
        "compiler": "arm-vita-eabi-gcc",
        "shell": ["sh", "-lc"],
        "environment": "",
        "builds": ["vitals-boot-debug2", "vitals-ssl-debug2", "vitals-http-debug2", "vitals-browser-debug2", "vitals-app"],
        "target": ["--target=arm-none-eabi", "-mcpu=cortex-a9", "-mfpu=neon", "-mfloat-abi=hard", "-mthumb"],
        "own_defines": ["__vita__", "__USES_INITFINI__"],
        # The repository is at the same path inside the container
        "inside": None,
    },
    "ps3": {
        "compiler": "powerpc64-ps3-elf-gcc",
        "shell": ["bash", "-c"],
        "environment": "source /opt/ps3dk-src/scripts/env.sh >/dev/null; ",
        "builds": ["vitals-ssl-debug2", "vitals-http-debug2", "vitals-boot-debug2", "vitals-app"],
        # 32-bit pointers on a 64-bit CPU: the closest clang has
        "target": ["--target=powerpc-unknown-elf", "-maltivec"],
        "own_defines": ["__PPU__", "__CELLOS_LV2__", "__lv2ppu__", "__powerpc64__", "__PPC64__", "_LP32", "__POINTER_32BIT__"],
        "inside": "/src",
        # The copy's 32-bit pointers: GCC's way, which clang refuses, and clang's are 32-bit anyway
        "header_fixes": [("opt/ps3dk-src/stage/ps3dev/ps3dk/ppu/include/ppu-types.h",
                          r"(#define\s+ATTRIBUTE_PRXPTR)\s+__attribute__\(\(mode\(SI\)\)\)", r"\1")],
    },
}


def kept_arguments(arguments):
    """From a compiler's command line, what says how the file reads: (flag, value) pairs. Value is None
    for a flag that's whole, such as -std=gnu11"""
    kept = []
    i = 1
    while i < len(arguments):
        argument = arguments[i]
        i += 1
        for flag in ("-isystem", "-iquote", "-include", "-I", "-D", "-U"):
            if argument == flag:
                if i < len(arguments):
                    kept.append((flag, arguments[i]))
                    i += 1
                break
            if argument.startswith(flag):
                kept.append((flag, argument[len(flag):]))
                break
        else:
            if argument.startswith("-std="):
                kept.append((argument, None))
    return kept


def split_command(entry):
    return list(entry["arguments"]) if "arguments" in entry else shlex.split(entry["command"])


def outside_folders(entries, inside):
    """The include folders named that aren't the project's: they're the SDK's"""
    folders = set()
    for entry in entries:
        for flag, value in kept_arguments(split_command(entry)):
            if flag in ("-I", "-isystem", "-iquote") and value.startswith("/") and not is_project(value, inside):
                folders.add(posixpath.normpath(value))
    return folders


def is_project(path, inside):
    return path.startswith(str(REPOSITORY) + "/") or (inside is not None and path.startswith(inside + "/"))


def mapped(path, inside, sdk):
    """A path in a build's command line, as it is on this machine"""
    if not path.startswith("/"):
        return path
    if inside is not None and path.startswith(inside + "/"):
        return str(REPOSITORY) + path[len(inside):]
    if path.startswith(str(REPOSITORY) + "/"):
        return path
    return str(sdk) + posixpath.normpath(path)


def rewritten(entry, console, sdk, system_folders, defines):
    """entry as this machine's clang reads the file"""
    inside = console["inside"]
    arguments = ["clang"] + list(entry.get("_target", console["target"])) + ["-nostdinc"]
    for flag, value in kept_arguments(split_command(entry)):
        if value is None:
            arguments.append(flag)
        elif flag in ("-D", "-U"):
            # A define can name a file of the project, as Mbed TLS's configuration
            if inside is not None:
                value = value.replace(f'"{inside}/', f'"{REPOSITORY}/')
            arguments.append(flag + value)
        else:
            arguments.extend([flag, mapped(value, inside, sdk)])
    for folder in system_folders:
        arguments.extend(["-isystem", str(sdk) + folder])
    arguments.extend("-D" + define for define in defines)
    file = mapped(entry["file"], inside, sdk)
    arguments.extend(["-c", file])
    return {"directory": mapped(entry["directory"], inside, sdk), "file": file, "arguments": arguments}


def parse_compiler(output, names):
    """The search folders and the named defines from gcc -E -dM -v"""
    start = output.index("#include <...> search starts here:")
    end = output.index("End of search list.")
    folders = [posixpath.normpath(line.strip()) for line in output[start:end].splitlines()[1:]]
    found = dict(re.findall(r"^#define (\S+) ?(.*)$", output, re.M))
    return folders, [f"{name}={found[name]}" if found[name] else name for name in names if name in found]


def without_nested(folders):
    """folders, leaving out any inside another of them"""
    kept = []
    for folder in sorted(set(folders)):
        if not kept or not folder.startswith(kept[-1] + "/"):
            kept.append(folder)
    return kept


def in_image(image, console, command, **options):
    return subprocess.run(["docker", "run", "--rm", image] + console["shell"] + [console["environment"] + command], **options)


def copy_headers(image, console, folders, sdk):
    sdk.mkdir(parents=True, exist_ok=True)
    names = " ".join(shlex.quote(folder.lstrip("/")) for folder in without_nested(folders))
    with subprocess.Popen(["tar", "xf", "-", "-C", str(sdk)], stdin=subprocess.PIPE) as unpack:
        copied = in_image(image, console, f"tar chf - -C / {names}", stdout=unpack.stdin)
        unpack.stdin.close()
    if copied.returncode != 0 or unpack.returncode != 0:
        sys.exit("Couldn't copy the SDK's headers out of the image")


def fix_headers(console, sdk):
    """What only GCC reads, changed in the copy under build/; the image's are left as they are"""
    for name, pattern, replacement in console.get("header_fixes", []):
        path = sdk / name
        text, count = re.subn(pattern, replacement, path.read_text())
        if count != 1 and replacement not in text:
            print(f"  {name}: not as expected, left as it is")
            continue
        path.chmod(0o644)
        path.write_text(text)


def read_entries(name, console):
    root = REPOSITORY / name / "build"
    entries = []
    for build in console["builds"]:
        path = root / build / ENTRIES_FILE
        if not path.is_file():
            sys.exit(f"{path} is missing: run make first")
        entries.extend(json.loads(path.read_text()))
    return entries


def extra_entries(name, entries):
    """What the normal builds leave out. The PS3's DNS kernel plugin isn't built with CMake
    (tools/build_dns_plugin.sh), and its XMB code is only in the XMB=1 builds"""
    if name != "ps3":
        return []
    inside = CONSOLES[name]["inside"]
    ps3 = f"{inside}/ps3"
    plugin = ["cc", "-DVITALS_DEBUG=2", "-Ivitals-dns/src", "-I../shared/dns", "-I../shared/include", "-Icommon"]
    extra = [{"directory": ps3, "file": f"{ps3}/{file}", "arguments": plugin + [file], "_target": ["--target=powerpc64-unknown-elf"]}
             for file in ("vitals-dns/kernel/plugin.c", "vitals-dns/src/dns_rules.c")]
    boot = next((entry for entry in entries if entry["file"].endswith("vitals-boot/src/boot.c")), None)
    if boot is not None:
        extra.append({"directory": boot["directory"], "file": f"{ps3}/vitals-xmb/src/xmb.c",
                      "arguments": split_command(boot) + ["-DVITALS_XMB"]})
    return extra


def check_entry(entry):
    """How many headers this file can't find, and the first such message"""
    arguments = ["clang"] + [a for a in entry["arguments"][1:] if a != "-c"] + ["-fsyntax-only", "-ferror-limit=0", "-w"]
    result = subprocess.run(arguments, cwd=entry["directory"], capture_output=True, text=True)
    missing = [line for line in result.stderr.splitlines() if "file not found" in line]
    return entry["file"], missing


def check(entries):
    project = [entry for entry in entries if "/_deps/" not in entry["file"]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        results = list(pool.map(check_entry, project))
    failed = [(file, missing) for file, missing in results if missing]
    for file, missing in failed[:10]:
        print(f"  {os.path.relpath(file, REPOSITORY)}: {missing[0]}")
    print(f"{len(project) - len(failed)} of {len(project)} of the project's files find all their headers")
    return not failed


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("console", choices=CONSOLES)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    console = CONSOLES[args.console]
    if shutil.which("clang") is None:
        sys.exit("clang is needed, to stand in for the console's compiler")
    editor = REPOSITORY / args.console / "build" / "editor"
    sdk = editor / "sdk"
    compiler = in_image(args.image, console, f"{console['compiler']} -E -dM -v -x c /dev/null 2>&1",
                        capture_output=True, text=True)
    if compiler.returncode != 0:
        sys.exit(f"The image's compiler didn't run: {compiler.stdout[-400:]}{compiler.stderr[-400:]}")
    system_folders, defines = parse_compiler(compiler.stdout, console["own_defines"])
    entries = read_entries(args.console, console)
    entries += extra_entries(args.console, entries)
    copy_headers(args.image, console, system_folders + sorted(outside_folders(entries, console["inside"])), sdk)
    fix_headers(console, sdk)
    result = [rewritten(entry, console, sdk, system_folders, defines) for entry in entries]
    (editor / ENTRIES_FILE).write_text(json.dumps(result, indent=1) + "\n")
    print(f"{os.path.relpath(editor / ENTRIES_FILE, REPOSITORY)}: {len(result)} files")
    check(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
