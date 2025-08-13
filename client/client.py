# client.py
#!/usr/bin/env python3
# client.py
# Minimal Python client matching node/main.go DomainTx format.
#
# Adds a pre-upload recursion check for .sml files:
# - Scans @include(...) and @fetch(...) references
# - Resolves referenced files under ./includes and ./content
# - Detects circular references and excessive depth, aborts upload if found

import os
import sys
import json
import time
import base64
import hashlib
import re
from pathlib import Path

import requests
from nacl.signing import SigningKey, VerifyKey
from collections import OrderedDict

# config / defaults
NODE = os.environ.get("SAMMAN_NODE", "http://127.0.0.1:7742")
KEYDIR = Path.home() / ".sammanet"
KEYDIR.mkdir(parents=True, exist_ok=True)
KEYFILE = KEYDIR / "keypair.json"

# directories used when resolving @include/@fetch targets locally
CONTENT_DIR = os.environ.get("SAMMAN_CONTENT_DIR", "./content")
INCLUDE_DIR = os.environ.get("SAMMAN_INCLUDE_DIR", "./includes")

# recursion guard
MAX_DEPTH = int(os.environ.get("SAMMAN_MAX_DEPTH", "10"))

# regex for directives
RE_INCLUDE = re.compile(r"@include\(\s*([^)]+?)\s*\)")
RE_FETCH = re.compile(r"@fetch\(\s*([^)]+?)\s*\)")

def genkeys():
    sk = SigningKey.generate()
    vk = sk.verify_key
    data = {
        "sk": base64.b64encode(bytes(sk)).decode(),
        "vk": base64.b64encode(bytes(vk)).decode()
    }
    KEYFILE.write_text(json.dumps(data))
    print("saved keys to", KEYFILE)

def loadkeys():
    if not KEYFILE.exists():
        print("no keys - run: client.py genkeys")
        sys.exit(1)
    d = json.loads(KEYFILE.read_text())
    sk = SigningKey(base64.b64decode(d["sk"]))
    vk = VerifyKey(base64.b64decode(d["vk"]))
    return sk, vk

def resolve_target_local(target):
    """
    Try to resolve a target string (from @include/@fetch) to a local path.
    Returns absolute path if found, or None.
    Resolution strategy:
      - If target is an absolute path and exists -> return it
      - Try INCLUDE_DIR/target
      - Try CONTENT_DIR/target
      - If target doesn't end with .sml, try appending .sml
      - Also try target as given (relative path)
    """
    t = target.strip()
    # if it's quoted like "foo" or 'foo', strip quotes
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        t = t[1:-1]

    candidates = []
    # absolute
    if os.path.isabs(t):
        candidates.append(t)
    # include & content directories
    candidates.append(os.path.join(INCLUDE_DIR, t))
    candidates.append(os.path.join(CONTENT_DIR, t))
    # raw relative path
    candidates.append(t)
    # try with .sml
    if not t.lower().endswith(".sml"):
        candidates.append(os.path.join(INCLUDE_DIR, t + ".sml"))
        candidates.append(os.path.join(CONTENT_DIR, t + ".sml"))
        candidates.append(t + ".sml")

    for c in candidates:
        if os.path.exists(c) and os.path.isfile(c):
            return os.path.abspath(c)
    return None

def detect_loops(filepath, visited=None, depth=0):
    """
    Recursively scan filepath for @include/@fetch loops.
    - filepath should be a local filesystem path.
    - visited is a set of absolute paths currently in the recursion stack.
    Returns None on success, or an error string on failure.
    """
    if visited is None:
        visited = set()

    if depth > MAX_DEPTH:
        return f"Maximum include/fetch depth of {MAX_DEPTH} exceeded starting from {filepath}"

    try:
        abspath = os.path.abspath(filepath)
    except Exception as e:
        return f"Invalid path {filepath}: {e}"

    if abspath in visited:
        return f"Circular reference detected at {filepath}"

    if not os.path.exists(abspath) or not os.path.isfile(abspath):
        return f"File not found: {filepath}"

    visited.add(abspath)
    try:
        with open(abspath, "r", encoding="utf-8") as f:
            data = f.read()
    except Exception as e:
        visited.remove(abspath)
        return f"Error reading {filepath}: {e}"

    # find includes
    for m in RE_INCLUDE.findall(data):
        tgt = m.strip()
        resolved = resolve_target_local(tgt)
        if resolved is None:
            visited.remove(abspath)
            return f"Include target not found locally: {tgt} (referenced from {filepath})"
        err = detect_loops(resolved, visited, depth + 1)
        if err:
            visited.remove(abspath)
            return err

    # find fetches
    for m in RE_FETCH.findall(data):
        tgt = m.strip()
        # try to resolve locally; if not found, we treat it as external CID and can't expand further.
        resolved = resolve_target_local(tgt)
        if resolved is not None:
            err = detect_loops(resolved, visited, depth + 1)
            if err:
                visited.remove(abspath)
                return err
        else:
            # Not found locally: assume it's a CID or remote reference; we can't expand, but that's okay.
            # However, if the token matches a file we've already visited by name (e.g., user used same name),
            # attempt to detect trivial collision:
            synthetic = f"cid:{tgt}"
            if synthetic in visited:
                visited.remove(abspath)
                return f"Circular reference detected via CID-like token {tgt}"
            # otherwise continue
            pass

    visited.remove(abspath)
    return None

def upload(path):
    # If it's an .sml file, pre-scan for loops/includes/fetches
    if path.lower().endswith(".sml"):
        err = detect_loops(path)
        if err:
            print(f"[ERROR] Upload aborted: {err}")
            sys.exit(1)

    # proceed with upload
    with open(path, "rb") as fh:
        b = fh.read()
    try:
        r = requests.post(f"{NODE}/upload", data=b, timeout=10)
    except Exception as e:
        print(f"[ERROR] Upload failed: {e}")
        sys.exit(1)

    print(r.status_code, r.text)
    try:
        print("json:", r.json())
    except:
        pass

def register(domain, content_cid=""):
    sk, vk = loadkeys()

    # Build transaction with Go struct field order
    tx = OrderedDict([
        ("type", "domain_reg"),
        ("domain", domain),
        ("owner_pub", base64.b64encode(bytes(vk)).decode()),
        ("content_cid", content_cid),
        ("timestamp", int(time.time())),
        ("nonce", int(time.time() * 1000)),
        ("sig", "")
    ])

    # Encode in exact Go encoding/json style: field order preserved, no spaces after commas/colons
    msg = json.dumps(tx, separators=(",", ":")).encode()

    # Sign the canonical byte sequence
    sig = sk.sign(msg).signature
    tx["sig"] = base64.b64encode(sig).decode()

    try:
        r = requests.post(f"{NODE}/register", json=tx, timeout=10)
    except Exception as e:
        print(f"[ERROR] Register failed: {e}")
        return
    print("register:", r.status_code, r.text)
    
def resolve(domain):
    try:
        r = requests.get(f"{NODE}/resolve?domain={domain}", timeout=10)
    except Exception as e:
        print(f"[ERROR] Resolve failed: {e}")
        return
    print("resolve:", r.status_code, r.text)
    if r.status_code == 200:
        print(json.dumps(r.json(), indent=2))

def fetch(cid):
    try:
        r = requests.get(f"{NODE}/fetch?cid={cid}", timeout=20)
    except Exception as e:
        print(f"[ERROR] Fetch failed: {e}")
        return
    print("fetch:", r.status_code)
    print(r.text[:1000])

def help():
    print("usage: client.py genkeys | upload <path> | register <domain> [cid] | resolve <domain> | fetch <cid>")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        help(); sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "genkeys":
        genkeys()
    elif cmd == "upload":
        if len(sys.argv) < 3:
            help(); sys.exit(1)
        upload(sys.argv[2])
    elif cmd == "register":
        if len(sys.argv) < 3:
            help(); sys.exit(1)
        domain = sys.argv[2]
        cid = sys.argv[3] if len(sys.argv) > 3 else ""
        register(domain, cid)
    elif cmd == "resolve":
        if len(sys.argv) < 3:
            help(); sys.exit(1)
        resolve(sys.argv[2])
    elif cmd == "fetch":
        if len(sys.argv) < 3:
            help(); sys.exit(1)
        fetch(sys.argv[2])
    else:
        help()
