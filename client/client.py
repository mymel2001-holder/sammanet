#!/usr/bin/env python3
# client.py
# Minimal Python client matching node/main.go DomainTx format.

import os
import sys
import json
import time
import base64
import hashlib
from pathlib import Path

import requests
from nacl.signing import SigningKey, VerifyKey

NODE = os.environ.get("SAMMAN_NODE", "http://127.0.0.1:8080")
KEYDIR = Path.home() / ".sammanet"
KEYDIR.mkdir(parents=True, exist_ok=True)
KEYFILE = KEYDIR / "keypair.json"

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

def upload(path):
    with open(path, "rb") as fh:
        b = fh.read()
    r = requests.post(f"{NODE}/upload", data=b)
    print(r.status_code, r.text)
    try:
        print("json:", r.json())
    except:
        pass

def register(domain, content_cid=""):
    sk, vk = loadkeys()
    tx = {
        "type": "domain_reg",
        "domain": domain,
        "owner_pub": base64.b64encode(bytes(vk)).decode(),
        "content_cid": content_cid,
        "timestamp": int(time.time()),
        "nonce": int(time.time() * 1000)
    }
    # sign tx (signature over JSON with empty sig)
    tx_copy = dict(tx)
    tx_copy["sig"] = ""
    msg = json.dumps(tx_copy, separators=(",", ":"), sort_keys=True).encode()
    sig = sk.sign(msg).signature
    tx["sig"] = base64.b64encode(sig).decode()
    r = requests.post(f"{NODE}/register", json=tx)
    print("register:", r.status_code, r.text)

def resolve(domain):
    r = requests.get(f"{NODE}/resolve?domain={domain}")
    print("resolve:", r.status_code, r.text)
    if r.status_code == 200:
        print(json.dumps(r.json(), indent=2))

def fetch(cid):
    r = requests.get(f"{NODE}/fetch?cid={cid}")
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
        upload(sys.argv[2])
    elif cmd == "register":
        domain = sys.argv[2]
        cid = sys.argv[3] if len(sys.argv) > 3 else ""
        register(domain, cid)
    elif cmd == "resolve":
        resolve(sys.argv[2])
    elif cmd == "fetch":
        fetch(sys.argv[2])
    else:
        help()
