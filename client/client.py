# client.py
#!/usr/bin/env python3
# client.py
# Minimal Python client matching node/main.go DomainTx format.
#
# Adds a multi-node failover for decentralization: reads SAMMAN_NODES
# (comma-separated) and tries each node for operations: upload, register, resolve, fetch.
# Keeps existing signing/format logic.

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

# support multi-node failover for decentralization
SAMMAN_NODES_ENV = os.environ.get("SAMMAN_NODES")
if not SAMMAN_NODES_ENV:
    SAMMAN_NODES_ENV = os.environ.get("SAMMAN_NODE", NODE)
SAMMAN_NODES = [s.strip() for s in SAMMAN_NODES_ENV.split(",") if s.strip()]
IPFS_NODES_ENV = os.environ.get("IPFS_NODES", "")
if IPFS_NODES_ENV:
    IPFS_NODES = [s.strip() for s in IPFS_NODES_ENV.split(",") if s.strip()]
else:
    IPFS_NODES = []

def ipfs_add_bytes_via_nodes(data: bytes):
    last_err = None
    if not IPFS_NODES:
        return None, None
    for node in IPFS_NODES:
        try:
            url = node.rstrip("/") + "/api/v0/add"
            files = {"file": ("content", data)}
            resp = requests.post(url, files=files, timeout=5)
            if resp.status_code >= 200 and resp.status_code < 300:
                try:
                    j = resp.json()
                except Exception:
                    j = {}
                cid = j.get("Hash") or j.get("HashBytes")
                if cid:
                    return cid, None
        except Exception as e:
            last_err = e
            continue
    return None, last_err or Exception("IPFS add failed")

# New: fetch via IPFS cat
def ipfs_cat_bytes_via_nodes(cid):
    last_err = None
    if not IPFS_NODES:
        return None, None
    for node in IPFS_NODES:
        try:
            url = node.rstrip("/") + "/api/v0/cat?arg=" + cid
            resp = requests.get(url, timeout=5)
            if resp.status_code >= 200 and resp.status_code < 300:
                return resp.content, None
        except Exception as e:
            last_err = e
            continue
    return None, last_err or Exception("IPFS cat failed")

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
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        t = t[1:-1]
    candidates = []
    if os.path.isabs(t):
        candidates.append(t)
    candidates.append(os.path.join(INCLUDE_DIR, t))
    candidates.append(os.path.join(CONTENT_DIR, t))
    candidates.append(t)
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
    Returns None on success or string error.
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
    for m in RE_FETCH.findall(data):
        tgt = m.strip()
        resolved = resolve_target_local(tgt)
        if resolved is not None:
            err = detect_loops(resolved, visited, depth + 1)
            if err:
                visited.remove(abspath)
                return err
        else:
            synthetic = f"cid:{tgt}"
            if synthetic in visited:
                visited.remove(abspath)
                return f"Circular reference detected via CID-like token {tgt}"
    visited.remove(abspath)
    return None

def upload(path):
    if path.lower().endswith(".sml"):
        err = detect_loops(path)
        if err:
            print(f"[ERROR] Upload aborted: {err}")
            sys.exit(1)
    with open(path, "rb") as fh:
        b = fh.read()
    try:
        # try multi-node upload
        for base in SAMMAN_NODES:
            url = base.rstrip("/") + "/upload?cid="
            resp = requests.post(url, data=b, timeout=10, headers={"Content-Type":"application/octet-stream"})
            if 200 <= resp.status_code < 300:
                print(resp.status_code, resp.text)
                try:
                    print("json:", resp.json())
                except Exception:
                    pass
                break
        else:
            raise Exception("all nodes failed")
    except Exception as e:
        print(f"[ERROR] Upload failed: {e}")
        sys.exit(1)

def register(domain, content_cid=""):
    sk, vk = loadkeys()
    tx = OrderedDict([
        ("type", "domain_reg"),
        ("domain", domain),
        ("owner_pub", base64.b64encode(bytes(vk)).decode()),
        ("content_cid", content_cid),
        ("timestamp", int(time.time())),
        ("nonce", int(time.time() * 1000)),
        ("sig", "")
    ])
    msg = json.dumps(tx, separators=(",", ":")).encode()
    sig = sk.sign(msg).signature
    tx["sig"] = base64.b64encode(sig).decode()
    try:
        for base in SAMMAN_NODES:
            url = base.rstrip("/") + "/register"
            resp = requests.post(url, json=tx, timeout=10)
            if 200 <= resp.status_code < 300:
                print("register:", resp.status_code, resp.text)
                return
        raise Exception("all nodes failed")
    except Exception as e:
        print(f"[ERROR] Register failed: {e}")
        return

def resolve(domain):
    try:
        for base in SAMMAN_NODES:
            url = base.rstrip("/") + "/resolve?domain=" + domain
            resp = requests.get(url, timeout=10)
            if 200 <= resp.status_code < 300:
                print("resolve:", resp.status_code, resp.text)
                try:
                    print(json.dumps(resp.json(), indent=2))
                except Exception:
                    pass
                return
        raise Exception("all nodes failed")
    except Exception as e:
        print(f"[ERROR] Resolve failed: {e}")
        return

def fetch(cid):
    # Try IPFS first if configured
    if IPFS_NODES:
        data, err = ipfs_cat_bytes_via_nodes(cid)
        if data is not None and err is None:
            print("ipfs_fetch:", cid, "size", len(data))
            try:
                s = data.decode("utf-8", errors="ignore")
            except Exception:
                s = str(data)
            print(s[:1000])
            return
    try:
        for base in SAMMAN_NODES:
            url = base.rstrip("/") + "/fetch?cid=" + cid
            resp = requests.get(url, timeout=20)
            if 200 <= resp.status_code < 300:
                print("fetch:", resp.status_code)
                print(resp.text[:1000])
                return
        raise Exception("all nodes failed")
    except Exception as e:
        print(f"[ERROR] Fetch failed: {e}")
        return

def publish_protocol(pm_type, cid=None, data=None):
    sk, vk = loadkeys()
    pub = base64.b64encode(bytes(vk)).decode()
    pm = OrderedDict([
        ("type", pm_type),
        ("cid", cid or ""),
        ("data", data or ""),
        ("pub", pub),
        ("timestamp", int(time.time())),
        ("sig", "")
    ])
    for base in SAMMAN_NODES:
        url = base.rstrip("/") + "/protocol/publish"
        resp = requests.post(url, json=pm, timeout=10)
        if resp.status_code >= 200 and resp.status_code < 300:
            try:
                return resp.json()
            except Exception:
                return {"status": "ok"}
    return {"error": "all nodes failed"}

def help():
    print("usage: client.py genkeys | upload <path> | register <domain> [cid] | resolve <domain> | fetch <cid> | publish-protocol <Type> [CID] [Data]")

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
    elif cmd == "publish-protocol":
        if len(sys.argv) < 3:
            help(); sys.exit(1)
        pm_type = sys.argv[2]
        cid = sys.argv[3] if len(sys.argv) > 3 else ""
        data = sys.argv[4] if len(sys.argv) > 4 else ""
        publish_protocol(pm_type, cid, data)
    else:
        help()
