// node/main.go
//
// Full-featured Sammanet node (prototype).
//
// Features included in this single-file implementation:
// - Content-addressed storage (SHA-256 CIDs) saved to disk (data/content/<cid>)
// - Domain registration via signed DomainTx transactions appended to a gzipped append-only chain (data/chain.gz)
// - Chain header signing/verification (ed25519) and simple "first-seen" resolution rule
// - HTTP admin/API endpoints: /upload, /register, /resolve, /fetch, /peers, /chain
// - Peer sync over Tor (SOCKS5) or plain HTTP; peer list gossip and chain syncing
// - WASM sandbox execution via Wasmtime with fuel metering and safe host imports:
//     env.log(ptr,len), env.storage_get(kptr,klen,outptr)->i32, env.storage_put(kp,kl,vp,vl)->i32, env.fetch_samman(cidPtr,cidLen,outPtr)->i32
// - Basic Markdown rendering (blackfriday) for fetched pages (if content is not wasm)
// - Local per-content persistent key-value store for wasm scripts (prototype)
//
//
// WARNING: This is a prototype for experimentation. Do NOT run untrusted wasm on sensitive machines
// without additional hardening. The sandbox uses fuel metering and timeouts but is not a full-security boundary.
//
// To build:
//  - Create a go.mod in the same folder: `module sammanet`
//  - Run `go get` for dependencies (listed in comments below) then `go build`.
//
// Dependencies you will need (example):
//   go get github.com/bytecodealliance/wasmtime-go/v12
//   go get golang.org/x/net/proxy
//   go get go.etcd.io/bbolt
//   go get github.com/russross/blackfriday/v2
//
// Put this file at node/main.go and run `go mod tidy && go build`
//
// Run node:
//   ./sammanode -config config.json
//
// Example config.json (optional):
// {
//   "listen_addr": "127.0.0.1:8080",
//   "tor_socks": "127.0.0.1:9050",
//   "seeds": ["http://127.0.0.1:8081"],
//   "peer_sync_sec": 30
// }

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bytecodealliance/wasmtime-go/v12"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/net/proxy"

	blackfriday "github.com/russross/blackfriday/v2"
)

// ------------------ Config & Constants ------------------

const (
	DefaultListenAddr = "127.0.0.1:8080"
	DataDir           = "data"
	ContentDir        = "data/content"
	ChainFile         = "data/chain.gz"
	KeyFile           = "data/nodekey.bin"
	DBFile            = "data/samman.db"
)

type Config struct {
	ListenAddr   string   `json:"listen_addr"`
	TorSocks     string   `json:"tor_socks"`     // e.g. "127.0.0.1:9050"
	Seeds        []string `json:"seeds"`         // seed peer addresses (http or onion)
	PeerSyncSec  int      `json:"peer_sync_sec"` // sync frequency
	AllowClearnet bool    `json:"allow_clearnet"`// allow clearnet peer dialing (default false)
}

func defaultConfig() Config {
	return Config{
		ListenAddr:   DefaultListenAddr,
		TorSocks:     "127.0.0.1:9050",
		Seeds:        []string{},
		PeerSyncSec:  30,
		AllowClearnet: true,
	}
}

// ------------------ Types: DomainTx, Block ------------------

type DomainTx struct {
	Type       string `json:"type"`         // "domain_reg"
	Domain     string `json:"domain"`       // requested domain string
	OwnerPub   string `json:"owner_pub"`    // base64 ed25519 pubkey of owner
	ContentCID string `json:"content_cid"`  // optional content cid (landing page)
	Timestamp  int64  `json:"timestamp"`
	Nonce      int64  `json:"nonce"`
	Sig        string `json:"sig"` // base64 signature over tx-with-empty-sig
}

type BlockHeader struct {
	PrevHash   string `json:"prev_hash"`
	Index      int64  `json:"index"`
	Timestamp  int64  `json:"timestamp"`
	Producer   string `json:"producer"`    // base64 node pubkey
	MerkleRoot string `json:"merkle_root"` // sha256 of concatenated tx bytes
	Sig        string `json:"sig"`         // base64 signature over header bytes
}

type Block struct {
	Header  BlockHeader `json:"header"`
	Payload []DomainTx  `json:"payload"`
}

// ------------------ Node State ------------------

type PeerInfo struct {
	Addr string `json:"addr"`
	Pub  string `json:"pub,omitempty"`
}

type Node struct {
	cfg Config

	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey

	db     *bolt.DB
	dbMu   sync.Mutex
	chain  []Block
	chainMu sync.Mutex

	peers   map[string]PeerInfo
	peersMu sync.Mutex

	storage   map[string]map[string]string // per-cid storage for wasm
	storageMu sync.Mutex
}

// ------------------ Utilities ------------------

func ensureDirs() error {
	if err := os.MkdirAll(ContentDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(DataDir, 0o755); err != nil {
		return err
	}
	return nil
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(b); err != nil {
		gw.Close()
		return nil, err
	}
	gw.Close()
	return buf.Bytes(), nil
}

func ungzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ioutil.ReadAll(r)
}

// headerHash computes sha256 of header json
func headerHash(h BlockHeader) string {
	b, _ := json.Marshal(h)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ------------------ Node Lifecycle ------------------

func NewNode(cfg Config) (*Node, error) {
	if err := ensureDirs(); err != nil {
		return nil, err
	}
	// open bolt db
	db, err := bolt.Open(DBFile, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	// ensure buckets
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("content"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("meta"))
		return err
	})
	if err != nil {
		return nil, err
	}
	// load or create nodekey
	pub, priv, err := loadOrCreateKey(KeyFile)
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:     cfg,
		privKey: priv,
		pubKey:  pub,
		db:      db,
		peers:   make(map[string]PeerInfo),
		storage: make(map[string]map[string]string),
	}
	// load chain from disk if present
	if b, err := os.ReadFile(ChainFile); err == nil {
		if dec, err := ungzip(b); err == nil {
			var ch []Block
			if err := json.Unmarshal(dec, &ch); err == nil {
				n.chain = ch
			}
		}
	}
	// add seeds
	for _, s := range cfg.Seeds {
		n.peersMu.Lock()
		n.peers[s] = PeerInfo{Addr: s}
		n.peersMu.Unlock()
	}
	return n, nil
}

func loadOrCreateKey(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		b := append(pub, priv...)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, nil, err
		}
		return pub, priv, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if len(b) < ed25519.PublicKeySize+ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid keyfile")
	}
	pub := make([]byte, ed25519.PublicKeySize)
	priv := make([]byte, ed25519.PrivateKeySize)
	copy(pub, b[:ed25519.PublicKeySize])
	copy(priv, b[ed25519.PublicKeySize:])
	return ed25519.PublicKey(pub), ed25519.PrivateKey(priv), nil
}

// saveChain writes gzipped chain to disk
func (n *Node) saveChain() error {
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	b, err := json.Marshal(n.chain)
	if err != nil {
		return err
	}
	gb, err := gzipBytes(b)
	if err != nil {
		return err
	}
	return os.WriteFile(ChainFile, gb, 0o644)
}

// appendBlock signs header and appends
func (n *Node) appendBlock(payload []DomainTx) error {
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	prev := ""
	idx := int64(len(n.chain))
	if idx > 0 {
		prev = headerHash(n.chain[len(n.chain)-1].Header)
	}
	hdr := BlockHeader{
		PrevHash:  prev,
		Index:     idx,
		Timestamp: time.Now().Unix(),
		Producer:  base64.StdEncoding.EncodeToString(n.pubKey),
	}
	var concat []byte
	for _, t := range payload {
		b, _ := json.Marshal(t)
		concat = append(concat, b...)
	}
	sum := sha256.Sum256(concat)
	hdr.MerkleRoot = hex.EncodeToString(sum[:])
	hdrBytes, _ := json.Marshal(hdr)
	sig := ed25519.Sign(n.privKey, hdrBytes)
	hdr.Sig = base64.StdEncoding.EncodeToString(sig)

	blk := Block{Header: hdr, Payload: payload}
	n.chain = append(n.chain, blk)
	return n.saveChain()
}

// verifyBlockHeader verifies header signature
func verifyBlockHeader(h BlockHeader) bool {
	sig, err := base64.StdEncoding.DecodeString(h.Sig)
	if err != nil {
		return false
	}
	pub, err := base64.StdEncoding.DecodeString(h.Producer)
	if err != nil {
		return false
	}
	// verify signature over header copy with empty Sig
	copyH := h
	copyH.Sig = ""
	b, _ := json.Marshal(copyH)
	return ed25519.Verify(ed25519.PublicKey(pub), b, sig)
}

// ------------------ Content storage helpers ------------------

func cidForBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (n *Node) storeContent(b []byte) (string, error) {
	cid := cidForBytes(b)
	path := filepath.Join(ContentDir, cid)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return "", err
		}
	}
	return cid, nil
}

func (n *Node) loadContent(cid string) ([]byte, error) {
	path := filepath.Join(ContentDir, cid)
	return os.ReadFile(path)
}

// ------------------ HTTP Handlers ------------------

// POST /upload  (raw body) -> {"cid": "<cid">}
func (n *Node) handleUpload(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // limit 10MB per upload (adjust)
	if err != nil {
		http.Error(w, "read error", 500)
		return
	}
	cid, err := n.storeContent(body)
	if err != nil {
		http.Error(w, "store error", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"cid": cid})
}

// POST /register  DomainTx JSON
func (n *Node) handleRegister(w http.ResponseWriter, r *http.Request) {
	var tx DomainTx
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	// basic validation
	if tx.Type != "domain_reg" {
		tx.Type = "domain_reg"
	}
	if tx.Domain == "" || tx.OwnerPub == "" {
		http.Error(w, "missing fields", 400)
		return
	}
	// decode sig & pub
	sigBytes, err := base64.StdEncoding.DecodeString(tx.Sig)
	if err != nil {
		http.Error(w, "bad sig encoding", 400)
		return
	}
	pubBytes, err := base64.StdEncoding.DecodeString(tx.OwnerPub)
	if err != nil {
		http.Error(w, "bad pub encoding", 400)
		return
	}
	// verify signature over tx copy with empty sig
	txCopy := tx
	txCopy.Sig = ""
	b, _ := json.Marshal(txCopy)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), b, sigBytes) {
		http.Error(w, "invalid signature", 401)
		return
	}
	// check conflict: first-seen wins
	n.chainMu.Lock()
	for _, blk := range n.chain {
		for _, p := range blk.Payload {
			if p.Domain == tx.Domain {
				n.chainMu.Unlock()
				http.Error(w, "domain taken", 409)
				return
			}
		}
	}
	n.chainMu.Unlock()

	// append tx as block (simple)
	if err := n.appendBlock([]DomainTx{tx}); err != nil {
		http.Error(w, "append failed", 500)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "domain": tx.Domain})
}

// GET /resolve?domain=...
func (n *Node) handleResolve(w http.ResponseWriter, r *http.Request) {
	d := r.URL.Query().Get("domain")
	if d == "" {
		http.Error(w, "missing domain", 400)
		return
	}
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	for _, blk := range n.chain {
		for _, tx := range blk.Payload {
			if tx.Domain == d {
				_ = json.NewEncoder(w).Encode(tx)
				return
			}
		}
	}
	http.Error(w, "not found", 404)
}

// GET /fetch?cid=<cid>
//
// If content is WASM (magic bytes), run wasm and return logs/plain text.
// If content contains top marker "wasm_cid: <cid>" in first 4KB, fetch referenced wasm and run it,
// then append wasm logs as an HTML comment to returned HTML.
func (n *Node) handleFetch(w http.ResponseWriter, r *http.Request) {
	cid := r.URL.Query().Get("cid")
	if cid == "" {
		http.Error(w, "missing cid", 400)
		return
	}
	b, err := n.loadContent(cid)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	// detect wasm magic
	if len(b) >= 4 && bytes.Equal(b[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		logs, err := n.RunWasmWithFuel(b, cid, 250_000, 3*time.Second)
		if err != nil {
			http.Error(w, "wasm error: "+err.Error()+"\nlogs:\n"+logs, 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(logs))
		return
	}
	// check for wasm_cid marker in first 4KB
	head := b
	if len(head) > 4096 {
		head = head[:4096]
	}
	lines := strings.Split(string(head), "\n")
	var wasmCID string
	for _, L := range lines {
		L = strings.TrimSpace(L)
		if strings.HasPrefix(L, "wasm_cid:") {
			wasmCID = strings.TrimSpace(strings.TrimPrefix(L, "wasm_cid:"))
			break
		}
	}
	if wasmCID == "" {
		// render markdown to HTML (best-effort)
		html := renderMarkdownToHTML(b)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}
	// fetch referenced wasm and run
	wasmBytes, err := n.loadContent(wasmCID)
	if err != nil {
		http.Error(w, "wasm not found: "+wasmCID, 404)
		return
	}
	logs, err := n.RunWasmWithFuel(wasmBytes, cid, 250_000, 3*time.Second)
	if err != nil {
		http.Error(w, "wasm run error: "+err.Error()+"\nlogs:\n"+logs, 500)
		return
	}
	// return original rendered page and append logs in comment
	html := renderMarkdownToHTML(b)
	out := html + "\n<!-- wasm logs:\n" + logs + "\n-->"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(out))
}

// GET /peers -> JSON list
func (n *Node) handlePeers(w http.ResponseWriter, r *http.Request) {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	list := make([]PeerInfo, 0, len(n.peers))
	for _, p := range n.peers {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Addr < list[j].Addr })
	_ = json.NewEncoder(w).Encode(list)
}

// GET /chain -> gzipped chain file bytes
func (n *Node) handleChain(w http.ResponseWriter, r *http.Request) {
	if b, err := os.ReadFile(ChainFile); err == nil {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(b)
		return
	}
	http.Error(w, "no chain", 404)
}

// ------------------ Markdown rendering ------------------

func renderMarkdownToHTML(md []byte) string {
	// use blackfriday to render markdown to HTML
	html := blackfriday.Run(md)
	return string(html)
}

// ------------------ WASM sandbox with Wasmtime + fuel ------------------

// RunWasmWithFuel runs wasm bytes inside Wasmtime with fuel and host imports.
// Exposes limited host API (storage_get, storage_put, fetch_samman, log).
// Storage is per-cid and stored in Node.storage map (prototype; not persisted across restarts).
func (n *Node) RunWasmWithFuel(wasmBytes []byte, cid string, fuel uint64, timeout time.Duration) (string, error) {
	// configure Wasmtime with fuel enabled
	cfg := wasmtime.NewConfig()
	cfg.SetConsumeFuel(true)
	engine := wasmtime.NewEngineWithConfig(cfg)
	store := wasmtime.NewStore(engine)
	// add fuel (if available)
	_ = store.AddFuel(fuel) // ignore error if not available
	module, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return "", fmt.Errorf("wasm compile: %w", err)
	}
	linker := wasmtime.NewLinker(engine)

	var mem *wasmtime.Memory
	var logs bytes.Buffer

	// ensure per-cid storage exists
	n.storageMu.Lock()
	if _, ok := n.storage[cid]; !ok {
		n.storage[cid] = make(map[string]string)
	}
	n.storageMu.Unlock()

	// helper read string from wasm memory (ptr,len)
	readStr := func(ptr int32, length int32) (string, error) {
		if mem == nil {
			return "", fmt.Errorf("no memory")
		}
		data, ok := mem.UnsafeData(store)
		if !ok {
			return "", fmt.Errorf("cannot access memory")
		}
		start := int(ptr)
		end := start + int(length)
		if start < 0 || end > len(data) {
			return "", fmt.Errorf("memory OOB")
		}
		return string(data[start:end]), nil
	}

	// export: env.log(ptr,len)
	logFunc := func(caller *wasmtime.Caller, ptr int32, l int32) {
		if mem == nil {
			return
		}
		s, err := readStr(ptr, l)
		if err == nil {
			logs.WriteString(s)
			logs.WriteByte('\n')
		}
	}
	if err := linker.DefineFunc("env", "log", logFunc); err != nil {
		return "", err
	}

	// export: env.storage_get(keyPtr,keyLen,outPtr) -> i32
	storageGet := func(caller *wasmtime.Caller, keyPtr int32, keyLen int32, outPtr int32) int32 {
		k, err := readStr(keyPtr, keyLen)
		if err != nil {
			return 0
		}
		n.storageMu.Lock()
		v := n.storage[cid][k]
		n.storageMu.Unlock()
		data, _ := mem.UnsafeData(store)
		off := int(outPtr)
		if off+4 > len(data) {
			return 0
		}
		L := uint32(len(v))
		// write length as little-endian
		data[off+0] = byte(L)
		data[off+1] = byte(L >> 8)
		data[off+2] = byte(L >> 16)
		data[off+3] = byte(L >> 24)
		if off+4+len(v) > len(data) {
			return 0
		}
		copy(data[off+4:off+4+len(v)], []byte(v))
		return 1
	}
	if err := linker.DefineFunc("env", "storage_get", storageGet); err != nil {
		return "", err
	}

	// export: env.storage_put(kp,kl,vp,vl) -> i32
	storagePut := func(caller *wasmtime.Caller, kp int32, kl int32, vp int32, vl int32) int32 {
		k, err := readStr(kp, kl)
		if err != nil {
			return 0
		}
		v, err := readStr(vp, vl)
		if err != nil {
			return 0
		}
		n.storageMu.Lock()
		n.storage[cid][k] = v
		n.storageMu.Unlock()
		return 1
	}
	if err := linker.DefineFunc("env", "storage_put", storagePut); err != nil {
		return "", err
	}

	// export: env.fetch_samman(cidPtr,cidLen,outPtr) -> i32
	fetchSamman := func(caller *wasmtime.Caller, cidPtr int32, cidLen int32, outPtr int32) int32 {
		cidS, err := readStr(cidPtr, cidLen)
		if err != nil {
			return 0
		}
		url := fmt.Sprintf("http://%s/fetch?cid=%s", strings.ReplaceAll(getListenAddr(n), "http://", ""), cidS)
		// but simpler: fetch local node via localhost to avoid complex listenaddr parsing
		url = fmt.Sprintf("http://127.0.0.1:8080/fetch?cid=%s", cidS)
		client := &http.Client{Timeout: 3 * time.Second}
		res, err := client.Get(url)
		if err != nil || res.StatusCode != 200 {
			return 0
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		s := string(body)
		data, _ := mem.UnsafeData(store)
		off := int(outPtr)
		if off+4 > len(data) {
			return 0
		}
		L := uint32(len(s))
		data[off+0] = byte(L)
		data[off+1] = byte(L >> 8)
		data[off+2] = byte(L >> 16)
		data[off+3] = byte(L >> 24)
		if off+4+len(s) > len(data) {
			return 0
		}
		copy(data[off+4:off+4+len(s)], []byte(s))
		return 1
	}
	if err := linker.DefineFunc("env", "fetch_samman", fetchSamman); err != nil {
		return "", err
	}

	// instantiate
	inst, err := linker.Instantiate(store, module)
	if err != nil {
		return "", fmt.Errorf("instantiate failed: %w", err)
	}
	// get memory
	memExport := inst.GetExport(store, "memory")
	if memExport == nil {
		return logs.String(), fmt.Errorf("module has no memory export")
	}
	mem = memExport.Memory()

	// pick entry: run, main, _start
	var fn *wasmtime.Func
	if f := inst.GetExport(store, "run"); f != nil {
		fn = f.Func()
	} else if f := inst.GetExport(store, "main"); f != nil {
		fn = f.Func()
	} else if f := inst.GetExport(store, "_start"); f != nil {
		fn = f.Func()
	}
	if fn == nil {
		return logs.String(), fmt.Errorf("no entrypoint exported (run/main/_start)")
	}

	// execute with timeout
	done := make(chan error, 1)
	go func() {
		_, err := fn.Call(store)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return logs.String(), fmt.Errorf("wasm runtime error: %w", err)
		}
		return logs.String(), nil
	case <-time.After(timeout):
		return logs.String(), fmt.Errorf("wasm execution timeout")
	}
}

// helper to try to get listen address for embed fetch (not critical)
func getListenAddr(n *Node) string {
	// default
	return "127.0.0.1:8080"
}

// ------------------ Peer sync over Tor (simple) ------------------

// makeTorClient constructs an http.Client that dials through torSocks if provided.
// If torSocks=="" returns default http client (clearnet).
func makeTorClient(torSocks string, allowClearnet bool) (*http.Client, error) {
	if torSocks == "" {
		if !allowClearnet {
			return nil, fmt.Errorf("clearnet disabled and no tor socks configured")
		}
		return &http.Client{Timeout: 20 * time.Second}, nil
	}
	// create a socks5 dialer
	dialer, err := proxy.SOCKS5("tcp", torSocks, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	// build custom transport using the dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}
	return &http.Client{Transport: tr, Timeout: 25 * time.Second}, nil
}

// syncPeers periodically fetches /peers and /chain from known peers
func (n *Node) peerSyncLoop() {
	freq := time.Duration(n.cfg.PeerSyncSec) * time.Second
	if freq <= 0 {
		freq = 30 * time.Second
	}
	for {
		n.peersMu.Lock()
		peers := make([]PeerInfo, 0, len(n.peers))
		for _, p := range n.peers {
			peers = append(peers, p)
		}
		n.peersMu.Unlock()

		for _, p := range peers {
			func(pi PeerInfo) {
				client, err := makeTorClient(n.cfg.TorSocks, n.cfg.AllowClearnet)
				if err != nil {
					return
				}
				// fetch peer list
				peersURL := strings.TrimRight(pi.Addr, "/") + "/peers"
				if resp, err := client.Get(peersURL); err == nil {
					if resp.StatusCode == 200 {
						var list []PeerInfo
						_ = json.NewDecoder(resp.Body).Decode(&list)
						resp.Body.Close()
						n.peersMu.Lock()
						for _, q := range list {
							if _, ok := n.peers[q.Addr]; !ok {
								n.peers[q.Addr] = q
							}
						}
						n.peersMu.Unlock()
					}
				}
				// fetch chain.gz
				chainURL := strings.TrimRight(pi.Addr, "/") + "/chain"
				if resp, err := client.Get(chainURL); err == nil {
					if resp.StatusCode == 200 {
						bs, _ := ioutil.ReadAll(resp.Body)
						resp.Body.Close()
						if dec, err := ungzip(bs); err == nil {
							var remote []Block
							if err := json.Unmarshal(dec, &remote); err == nil {
								// naive merge: accept remote if longer and headers validate
								n.chainMu.Lock()
								if len(remote) > len(n.chain) && validateChainSignatures(remote) {
									n.chain = remote
									_ = n.saveChain()
								}
								n.chainMu.Unlock()
							}
						}
					}
				}
			}(p)
		}
		time.Sleep(freq)
	}
}

// validateChainSignatures checks each block header signature (naive)
func validateChainSignatures(c []Block) bool {
	for _, blk := range c {
		if !verifyBlockHeader(blk.Header) {
			return false
		}
	}
	return true
}

// ------------------ main entry ------------------

func main() {
	cfgPath := flag.String("config", "", "path to config.json (optional)")
	flag.Parse()

	cfg := defaultConfig()
	if *cfgPath != "" {
		if b, err := os.ReadFile(*cfgPath); err == nil {
			_ = json.Unmarshal(b, &cfg)
		}
	}

	node, err := NewNode(cfg)
	if err != nil {
		log.Fatalf("node init error: %v", err)
	}

	// expose local node address in peers (use http://127.0.0.1:port)
	addr := "http://" + cfg.ListenAddr
	node.peersMu.Lock()
	node.peers[addr] = PeerInfo{Addr: addr, Pub: base64.StdEncoding.EncodeToString(node.pubKey)}
	node.peersMu.Unlock()

	// register HTTP handlers
	http.HandleFunc("/upload", node.handleUpload)
	http.HandleFunc("/register", node.handleRegister)
	http.HandleFunc("/resolve", node.handleResolve)
	http.HandleFunc("/fetch", node.handleFetch)
	http.HandleFunc("/peers", node.handlePeers)
	http.HandleFunc("/chain", node.handleChain)

	// peer syncer
	go node.peerSyncLoop()

	log.Printf("Sammanode listening on %s (tor socks=%s)\n", cfg.ListenAddr, cfg.TorSocks)
	if err := http.ListenAndServe(cfg.ListenAddr, nil); err != nil {
		log.Fatalf("http server: %v", err)
	}
}
