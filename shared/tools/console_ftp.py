"""What both consoles' FTP tools do the same way (psv/tools/vita_comms.py, ps3/tools/ps3_comms.py):
the settings in .env, connecting, and copying files off the console without touching them."""

import ftplib
import os
import sys

REPOSITORY = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def release():
    """The release being built, from VERSION at the top of the repository"""
    with open(os.path.join(REPOSITORY, "VERSION"), encoding="utf-8") as file:
        return file.read().strip()


def fetched_folder(console):
    """Where what's brought back from a console goes: fetched/<console> at the top of the repository"""
    return os.path.join(REPOSITORY, "fetched", console)


def load_env():
    """.env's KEY=VALUE lines into the environment, where they aren't set already (# comments)"""
    try:
        # The repository's, both consoles' settings (.env.example)
        with open(os.path.join(REPOSITORY, ".env"), encoding="utf-8") as env:
            lines = env.read().splitlines()
    except FileNotFoundError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.startswith("export "):
            key = key[len("export "):]
        key = key.strip()
        if not os.environ.get(key):
            os.environ[key] = value.strip().strip("'\"")


def host(variable, console):
    value = os.environ.get(variable, "")
    if not value:
        sys.exit(f"{variable} isn't set: put {console}'s address in .env (cp .env.example .env)")
    return value


def connect(address, port, hint):
    # Replies after a listing can carry bytes that aren't UTF-8 (webMAN MOD's 0xb0, a degree sign)
    ftp = ftplib.FTP(encoding="latin1")
    try:
        ftp.connect(address, port, timeout=30)
    except OSError as error:
        sys.exit(f"{address}: {error} ({hint})")
    ftp.login()
    return ftp


def make_directory(ftp, path):
    try:
        ftp.mkd(path)
    except ftplib.error_perm:
        pass  # already there


def listing(ftp, folder):
    """The files in folder as {name: size}, without its folders; None when it isn't there. Both
    consoles' servers answer LIST as ls -l does: the name is the ninth field, and a folder's line
    starts with d. Leaves folder the current one"""
    lines = []
    try:
        ftp.cwd(folder)
        ftp.retrlines("LIST", lines.append)
    except ftplib.error_perm:
        return None
    files = {}
    for line in lines:
        fields = line.split(None, 8)
        if len(fields) < 9 or line.startswith("d"):
            continue
        try:
            files[fields[8]] = int(fields[4])
        except ValueError:
            files[fields[8]] = None
    return files


def fetch(ftp, wanted, target, root):
    """Each wanted file copied into target and left on the console. wanted: (folder, the name prefixes
    it takes, whether the folder may be missing). What comes back can hold PSN details, so target
    belongs in fetched_folder's, which isn't committed"""
    os.makedirs(target, exist_ok=True)
    count = 0
    for folder, prefixes, optional in wanted:
        files = listing(ftp, folder)
        if files is None:
            if not optional:
                print(f"{folder}: not there")
            continue
        for name in sorted(files):
            if not name.startswith(prefixes):
                continue
            local = os.path.join(target, name)
            with open(local, "wb") as out:
                ftp.retrbinary("RETR " + name, out.write)
            print(f"{folder}/{name} -> {os.path.relpath(local, root)}")
            count += 1
    print(f"{count} fetched" if count else "Nothing to fetch.")


def show_log(data, folder, name, root):
    """A log read off the console, saved as folder/name and printed. It can hold PSN details, so folder
    belongs in fetched_folder's, which isn't committed"""
    os.makedirs(folder, exist_ok=True)
    local = os.path.join(folder, name)
    with open(local, "wb") as file:
        file.write(data)
    sys.stdout.write(data.decode("latin1"))
    print(f"-- saved as {os.path.relpath(local, root)}")
