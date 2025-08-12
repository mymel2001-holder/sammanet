# Sammanet

Sammanet is a decentralized, TOR-based, Markdown-like content network with custom scripting via WASM, a free-form domain system, and blockchain-like verification.

## Features

- GitHub-Markdown-like webpages, with optional `<script>` and `<style>` support.
- Secure sandboxed scripting via WASM.
- All communication over TOR protocol (planned).
- Custom free-form domains: `my.melody`, `sammanet.hoteles`, `daredevil`, etc.
- Python-based client.
- Go-based decentralized node.
- Blockchain-like verification to avoid domain conflicts.
- All FOSS.

## Prerequisites

- Go 1.22+
- Python 3.10+
- NodeJS + npm (if building an Electron browser, optional)
- TOR (optional for now)

## Install Node

"""
git clone https://example.com/sammanet
cd sammanet/node
go mod tidy
go build -o sammanet-node main.go
"""

## Run Node

"""
./sammanet-node
"""

The node will start on `localhost:8080`.

## Install Client

"""
pip install pynacl requests
"""

## Client Commands

Register a domain:

"""
python client.py register my.melody
"""

Upload content:

"""
python client.py upload page.html
"""

Resolve a domain:

"""
python client.py resolve my.melody
"""

Fetch content by CID:

"""
python client.py fetch <CID>
"""

## WASM Scripting

1. Create an AssemblyScript or Rust-based WASM script with a `main` function.
2. Compile to `.wasm`.
3. Upload the `.wasm` file as content. The node will detect and run it on fetch.

Example (AssemblyScript):

"""
export function main(): i32 {
  return 42;
}
"""

Compile:

"""
asc script.ts --target release --outFile script.wasm
"""

Upload:

"""
python client.py upload script.wasm
"""

Fetch:

"""
python client.py fetch <CID>
"""

Expected output:

"""
42
"""

## License

MIT
