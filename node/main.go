package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	ipfsapi "github.com/ipfs/go-ipfs-api"

	"github.com/bytecodealliance/wasmtime-go/v12"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/net/proxy"

	blackfriday "github.com/russross/blackfriday/v2"
	"github.com/microcosm-cc/bluemonday"
)
var protocolMessages []ProtocolMessage
var protocolMu sync.Mutex

// ------------------ Config & Constants ------------------

const (
	DefaultListenAddr = ":7742"
	DataDir           = "data"
	ContentDir        = "data/content"
	ChainFile         = "data/chain.gz"
	KeyFile           = "data/nodekey.bin"
	DBFile            = "data/samman.db"

	// directory used for resolving @include local files (matches client defaults)
	IncludeDir = "includes"

	// recursion guard for includes
	MaxIncludeDepth = 10
)

type DomainConfig struct {
	ContentDir string `json:"contentDir"`
}
type Config struct {
	ListenAddr    string                `json:"listen_addr"`
	TorSocks      string                `json:"tor_socks"`      // e.g. "127.0.0.1:9050"
	Seeds         []string              `json:"seeds"`          // seed peer addresses (http or onion)
	PeerSyncSec   int                   `json:"peer_sync_sec"`  // sync frequency
	AllowClearnet bool                  `json:"allow_clearnet"` // allow clearnet peer dialing (default false)
	Domains       map[string]DomainConfig `json:"domains"`
}
func defaultConfig() Config {
	return Config{
		ListenAddr:    DefaultListenAddr,
		TorSocks:      "127.0.0.1:9050",
		Seeds:         []string{},
		PeerSyncSec:   30,
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

	ipfs    *ipfsapi.Shell
	db      *bolt.DB
	dbMu    sync.Mutex
	chain   []Block
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
	// include dir is where authors commonly keep local includes
	if err := os.MkdirAll(IncludeDir, 0o755); err != nil {
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
	db, err := bolt.Open(DBFILEorDefault(), 0o600, &bolt.Options{Timeout: 1 * time.Second})
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
	// lazy ipfs client initialization (IPFS MVP)
	n.ipfs = ipfsapi.NewShell("http://127.0.0.1:5001")

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

// DB path helper (keeps original constant if present)
func DBFILEorDefault() string {
	if DBFile != "" {
		return DBFile
	}
	return "data/samman.db"
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

func (n *Node) storeContent(b []byte, host string) (string, error) {
	cid := cidForBytes(b)
	// Determine domain root
	root := ContentDir
	dom := domainFromHost(host)
	if domCfg, ok := n.cfg.Domains[dom]; ok && domCfg.ContentDir != "" {
		root = filepath.Join(ContentDir, domCfg.ContentDir)
	}
	// Ensure root dir exists
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(root, cid)
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

// ------------------ SML parsing & upload pre-checks (built-in) ------------------

 // directive regexes (used both for validation & parsing)
var (
	reInclude    = regexp.MustCompile(`@include\s*\(\s*([^)]+)\s*\)`)
	reFetch      = regexp.MustCompile(`@fetch\s*\(\s*([^)]+)\s*\)`)
	reWasmScript = regexp.MustCompile(`(?is)<script\s+[^>]*lang\s*=\s*"(?:wasm|WASM)"[^>]*src\s*=\s*"(wasm_cid:[^"]+)"[^>]*>.*?</script>`)
	reStyle      = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
)

 // Resolve a target like the Python client: absolute, includes/, data/content/, raw, with .sml
 func resolveTargetLocal(target string) string {
 	t := strings.TrimSpace(target)
 	if (strings.HasPrefix(t, "\"") && strings.HasSuffix(t, "\"")) || (strings.HasPrefix(t, "'") && strings.HasSuffix(t, "'")) {
 		t = t[1 : len(t)-1]
 	}
 	cands := []string{}
 	if filepath.IsAbs(t) {
 		cands = append(cands, t)
 	}
 	cands = append(cands, filepath.Join(IncludeDir, t))
 	cands = append(cands, filepath.Join(ContentDir, t))
 	cands = append(cands, t)
 	if !strings.HasSuffix(strings.ToLower(t), ".sml") {
 		cands = append(cands, filepath.Join(IncludeDir, t+".sml"))
 		cands = append(cands, filepath.Join(ContentDir, t+".sml"))
 		cands = append(cands, t+".sml")
 	}
 	for _, c := range cands {
 		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
 			ab, _ := filepath.Abs(c)
 			return ab
 		}
 	}
 	return ""
 }

 // detectLoopsFromPath scans a file recursively for @include/@fetch loops and missing includes.
 // visited map holds currently-in-stack keys (absolute paths and optional synthetic tokens).
 func detectLoopsFromPath(path string, visited map[string]bool, depth int) error {
 	if visited == nil {
 		visited = make(map[string]bool)
 	}
 	if depth > MaxIncludeDepth {
 		return fmt.Errorf("maximum include/fetch depth of %d exceeded starting from %s", MaxIncludeDepth, path)
 	}
 	ab, err := filepath.Abs(path)
 	if err != nil {
 		return fmt.Errorf("invalid path %s: %v", path, err)
 	}
 	if visited[ab] {
 		return fmt.Errorf("circular reference detected at %s", path)
 	}
 	fi, err := os.Stat(ab)
 	if err != nil || fi.IsDir() {
 		return fmt.Errorf("file not found: %s", path)
 	}
 	visited[ab] = true
 	defer func() {
 		delete(visited, ab)
 	}()

 	data, err := os.ReadFile(ab)
 	if err != nil {
 		return fmt.Errorf("error reading %s: %v", path, err)
 	}
 	s := string(data)
 	// includes
 	for _, m := range reInclude.FindAllStringSubmatch(s, -1) {
 		if len(m) < 2 {
 			return fmt.Errorf("malformed include in %s", path)
 		}
 		tgt := m[1]
 		resolved := resolveTargetLocal(tgt)
 		if resolved == "" {
 			return fmt.Errorf("include target not found locally: %s (referenced from %s)", tgt, path)
 		}
 		if err := detectLoopsFromPath(resolved, visited, depth+1); err != nil {
 			return err
 		}
 	}
 	// fetches
 	for _, m := range reFetch.FindAllStringSubmatch(s, -1) {
 		if len(m) < 2 {
 			return fmt.Errorf("malformed fetch in %s", path)
 		}
 		tgt := m[1]
 		resolved := resolveTargetLocal(tgt)
 		if resolved != "" {
 			if err := detectLoopsFromPath(resolved, visited, depth+1); err != nil {
 				return err
 			}
 		} else {
 			// Not found locally: treat as CID/external. We can't expand it here,
 			// but detect trivial synthetic cycles if the synthetic token is already in visited.
 			synth := "cid:" + tgt
 			if visited[synth] {
 				return fmt.Errorf("circular reference detected via CID-like token %s", tgt)
 			}
 			// don't add permanently (no further expansion)
 		}
 	}
 	return nil
 }

 // checkSMLBytes writes bytes to a temp file and runs loop detection if it looks like SML.
 func checkSMLBytes(b []byte) error {
 	s := string(b)
 	if !strings.Contains(s, "@include(") && !strings.Contains(s, "@fetch(") {
 		return nil
 	}
 	cid := cidForBytes(b)
 	tmp := filepath.Join(os.TempDir(), "samman_sml_"+cid+".sml")
 	if err := os.WriteFile(tmp, b, 0o600); err != nil {
 		return fmt.Errorf("temp write failed: %v", err)
 	}
 	defer os.Remove(tmp)
 	if err := detectLoopsFromPath(tmp, nil, 0); err != nil {
 		return err
 	}
 	return nil
 }

 // ------------------ SML parser (inlined) ------------------

 // ParseOptions provide callbacks for resolving @fetch and @include and control options.
 type ParseOptions struct {
 	// FetchByCID should return raw bytes for a CID (e.g., wasm or other content).
 	// If nil, @fetch directives will be left as an explanatory comment.
 	FetchByCID func(cid string) ([]byte, error)

 	// IncludeResolver should return raw SML/markdown bytes for include(domain/path).
 	// If nil, @include directives will be replaced with a comment noting unresolved include.
 	IncludeResolver func(domainPath string) ([]byte, error)

 	// AllowInlineHTML toggles whether small inline HTML tags are allowed (default true).
 	AllowInlineHTML bool
 }

 // default policy: allow inline HTML and style blocks
 func defaultPolicy() *bluemonday.Policy {
 	p := bluemonday.UGCPolicy()
 	// allow style tags (contents will be kept as-is)
 	p.AllowElements("style")
 	// allow the <samman-wasm> placeholder with src attr
 	p.AllowElements("samman-wasm")
 	p.AllowAttrs("src").OnElements("samman-wasm")
 	// keep class/id attributes on divs/spans for future use
 	p.AllowAttrs("class").Globally()
 	p.AllowAttrs("id").Globally()
 	return p
 }
 
 // ParseSML parses an SML document and returns sanitized HTML.
 // It expands directives via callbacks and renders Markdown via blackfriday.
 func ParseSML(input []byte, opts ParseOptions) (string, error) {
 	// default opts
 	if opts.FetchByCID == nil {
 		opts.FetchByCID = func(cid string) ([]byte, error) {
 			return nil, fmt.Errorf("fetch handler not configured")
 		}
 	}
 	if opts.IncludeResolver == nil {
 		opts.IncludeResolver = func(domainPath string) ([]byte, error) {
 			return nil, fmt.Errorf("include handler not configured")
 		}
 	}
 
 	// Step 1: Preprocess: extract style blocks and preserve them
 	styles := []string{}
 	content := string(input)
 	content = reStyle.ReplaceAllStringFunc(content, func(s string) string {
 		styles = append(styles, s)
 		// placeholder inserted and styles will be appended after render
 		return fmt.Sprintf("\n\n<!--__SML_STYLE_PLACEHOLDER_%d__-->\n\n", len(styles)-1)
 	})
 
 	// Step 2: Process wasm <script lang="wasm" src="wasm_cid:..."> tags:
 	// replace them with a safe placeholder element <samman-wasm src="wasm_cid:..."></samman-wasm>
 	content = reWasmScript.ReplaceAllStringFunc(content, func(s string) string {
 		match := reWasmScript.FindStringSubmatch(s)
 		if len(match) >= 2 {
 			src := html.EscapeString(match[1])
 			return fmt.Sprintf(`<samman-wasm src="%s"></samman-wasm>`, src)
 		}
 		return ""
 	})

	// Step 3: Process @include directives (may be many)
	content = reInclude.ReplaceAllStringFunc(content, func(m string) string {
		sub := reInclude.FindStringSubmatch(m)
		if len(sub) < 2 {
			return fmt.Sprintf("<!-- malformed include: %s -->", html.EscapeString(m))
		}
		dpath := sub[1]
		b, err := opts.IncludeResolver(dpath)
		if err != nil {
			return fmt.Sprintf("<!-- include unresolved: %s -->", html.EscapeString(dpath))
		}
		// included content may itself be SML; render included content as markdown fragment
		incHTML := string(blackfriday.Run(b))
		return incHTML
	})

	// Step 4: Process @fetch(cid) directives
	content = reFetch.ReplaceAllStringFunc(content, func(m string) string {
		sub := reFetch.FindStringSubmatch(m)
		if len(sub) < 2 {
			return fmt.Sprintf("<!-- malformed fetch: %s -->", html.EscapeString(m))
		}
		cid := sub[1]
		b, err := opts.FetchByCID(cid)
		if err != nil {
			return fmt.Sprintf("<!-- fetch unresolved: %s -->", html.EscapeString(cid))
		}
		// If the fetched bytes are wasm (magic) we leave a placeholder
		if len(b) >= 4 && bytes.Equal(b[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
			// create a saman-wasm placeholder
			return fmt.Sprintf(`<samman-wasm src="%s"></samman-wasm>`, html.EscapeString("wasm_cid:"+cid))
		}
		// Otherwise treat as markdown/html: render markdown then insert
		frag := string(blackfriday.Run(b))
		return frag
	})

	// Step 5: Render Markdown -> HTML (blackfriday)
	md := []byte(content)
	htmlBytes := blackfriday.Run(md, blackfriday.WithExtensions(blackfriday.CommonExtensions|blackfriday.AutoHeadingIDs))
	out := string(htmlBytes)

	// Step 6: Re-insert preserved styles in place of placeholders
	for i, s := range styles {
		ph := fmt.Sprintf("<!--__SML_STYLE_PLACEHOLDER_%d__-->", i)
		out = strings.ReplaceAll(out, ph, s)
	}

	// Step 7: Sanitize HTML with bluemonday
	policy := defaultPolicy()
	if !opts.AllowInlineHTML {
		// if inline HTML not allowed, use UGCPolicy but strip style and custom elements
		policy = bluemonday.UGCPolicy()
	}
	safe := policy.Sanitize(out)

	return safe, nil
}

 // ------------------ HTTP Handlers ------------------

 // POST /upload  (raw body) -> {"cid": "<cid">}
 func (n *Node) handleUpload(w http.ResponseWriter, r *http.Request) {
 	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // limit 10MB per upload (adjust)
 	if err != nil {
 		http.Error(w, "read error", 500)
 		return
 	}

 	// SML pre-checks: detect loops, missing includes, excessive depth
 	if err := checkSMLBytes(body); err != nil {
 		http.Error(w, "sml validation failed: "+err.Error(), 400)
 		return
 	}
 
 	cid, err := n.storeContent(body, r.Host)
 	if err != nil {
 		http.Error(w, "store error", 500)
 		return
 	}
	// Phase 1 IPFS: publish to IPFS and record CID in chain
	ipfsCid, ipfsErr := n.PublishContentCID(body)
	// if IPFS publish succeeded, append a small content_publish transaction to the chain
	if ipfsErr == nil && ipfsCid != "" {
		payload := []DomainTx{
			{
				Type:       "content_publish",
				ContentCID: ipfsCid,
				Timestamp:  time.Now().Unix(),
				Nonce:      time.Now().UnixNano(),
			},
		}
		_ = n.appendBlock(payload)
	}
	// Response includes local CID and may include IPFS CID when available
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{"cid": cid}
	if ipfsErr == nil && ipfsCid != "" {
		resp["ipfs_cid"] = ipfsCid
	}
	_ = json.NewEncoder(w).Encode(resp)
}
	
	func (n *Node) handlePublishProtocol(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, "read error: "+err.Error(), http.StatusBadRequest)
			return
		}
		var pm ProtocolMessage
		if err := json.Unmarshal(body, &pm); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		// enrich with identity
		pm.Pub = base64.StdEncoding.EncodeToString(n.pubKey)
		pm.Timestamp = time.Now().Unix()
		// sign
		sig, err := SignProtocol(n.privKey, pm)
		if err != nil {
			http.Error(w, "sign error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		pm.Sig = sig
		// persist locally
		n.storeProtocolMessage(pm)
		// broadcast to peers for propagation
		go func(p ProtocolMessage) {
			n.broadcastProtocol(p)
		}(pm)
		// respond with signed message
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pm)
	}

func (n *Node) PublishContentCID(b []byte) (string, error) {
	// ensure ipfs client exists
	if n.ipfs == nil {
		n.ipfs = ipfsapi.NewShell("http://127.0.0.1:5001")
	}
	return n.ipfs.Add(bytes.NewReader(b))
}

func (n *Node) FetchContentByCID(cid string) ([]byte, error) {
	if n.ipfs == nil {
		n.ipfs = ipfsapi.NewShell("http://127.0.0.1:5001")
	}
	rc, err := n.ipfs.Cat(cid)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return ioutil.ReadAll(rc)
}

func (n *Node) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Limit request body to 1MB for safety
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error: "+err.Error(), http.StatusBadRequest)
		return
	}
	// existing behavior unchanged (signature verification etc.)
	log.Println("[REGISTER] raw body:", string(body))

	// Parse incoming tx
	var tx DomainTx
	if err := json.Unmarshal(body, &tx); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Decode owner public key
	ownerPub, err := base64.StdEncoding.DecodeString(tx.OwnerPub)
	if err != nil || len(ownerPub) != ed25519.PublicKeySize {
		http.Error(w, "invalid owner_pub", http.StatusBadRequest)
		return
	}

	// Decode signature
	sig, err := base64.StdEncoding.DecodeString(tx.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		http.Error(w, "invalid sig", http.StatusBadRequest)
		return
	}

	// Build the exact same struct as signed (sig field = "")
	txForSig := DomainTx{
		Type:       tx.Type,
		Domain:     tx.Domain,
		OwnerPub:   tx.OwnerPub,
		ContentCID: tx.ContentCID,
		Timestamp:  tx.Timestamp,
		Nonce:      tx.Nonce,
		Sig:        "",
	}

	// Marshal using Go's default encoding/json (matches Python separators=(",", ":") + no sort)
	msg, err := json.Marshal(txForSig)
	if err != nil {
		http.Error(w, "marshal error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify signature
	if !ed25519.Verify(ownerPub, msg, sig) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// TODO: actually store domain registration in chain
	log.Printf("[REGISTER] domain=%s verified OK", tx.Domain)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
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
// If content looks like SML (includes/fetch or starts with markdown), ParseSML is used to render.
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

	// If wasm_cid present -> fetch and run referenced wasm, append logs to rendered HTML
	if wasmCID != "" {
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
		html := renderMarkdownToHTML(b)
		out := html + "\n<!-- wasm logs:\n" + logs + "\n-->"
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(out))
		return
	}

	// If content seems like SML/Markdown, attempt ParseSML with callbacks
	str := string(b)
	if strings.Contains(str, "@include(") || strings.Contains(str, "@fetch(") || strings.HasPrefix(strings.TrimSpace(str), "#") {
		opts := ParseOptions{
			AllowInlineHTML: true,
			FetchByCID: func(cid string) ([]byte, error) {
				return n.loadContent(cid)
			},
			IncludeResolver: func(domainPath string) ([]byte, error) {
				res := resolveTargetLocal(domainPath)
				if res != "" {
					bs, err := os.ReadFile(res)
					return bs, err
				}
				return nil, fmt.Errorf("include not found: %s", domainPath)
			},
		}
		html, err := ParseSML(b, opts)
		if err != nil {
			// fallback to raw markdown
			out := renderMarkdownToHTML(b)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(out))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}

	// default: render markdown to HTML (best-effort)
	html := renderMarkdownToHTML(b)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
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
 		data := mem.UnsafeData(store)
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
 	if err := linker.DefineFunc(store, "env", "log", logFunc); err != nil {
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
 		data := mem.UnsafeData(store)
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
 	if err := linker.DefineFunc(store, "env", "storage_get", storageGet); err != nil {
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
 	if err := linker.DefineFunc(store, "env", "storage_put", storagePut); err != nil {
 		return "", err
 	}

 	// export: env.fetch_samman(cidPtr,cidLen,outPtr) -> i32
 	fetchSamman := func(caller *wasmtime.Caller, cidPtr int32, cidLen int32, outPtr int32) int32 {
 		cidS, err := readStr(cidPtr, cidLen)
 		if err != nil {
 			return 0
 		}
 		// fetch via localhost (simple, robust)
 		url := fmt.Sprintf("http://127.0.0.1:7742/fetch?cid=%s", cidS)
 		client := &http.Client{Timeout: 3 * time.Second}
 		res, err := client.Get(url)
 		if err != nil || res.StatusCode != 200 {
 			return 0
 		}
 		defer res.Body.Close()
 		body, _ := io.ReadAll(res.Body)
 		s := string(body)
 		data := mem.UnsafeData(store)
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
 	if err := linker.DefineFunc(store, "env", "fetch_samman", fetchSamman); err != nil {
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
 	http.HandleFunc("/protocol/publish", node.handlePublishProtocol)

 	// peer syncer
 	go node.peerSyncLoop()

// Phase 2: Start Tor Hidden Service
onionAddr, torErr := StartTorHiddenService(cfg.ListenAddr)
if torErr != nil {
	log.Printf("Tor hidden service failed to start: %v", torErr)
} else {
	log.Printf("Tor hidden service available at %s", onionAddr)
}
 	log.Printf("Sammanode listening on %s (tor socks=%s)\n", cfg.ListenAddr, cfg.TorSocks)
 	if err := http.ListenAndServe(cfg.ListenAddr, nil); err != nil {
 		log.Fatalf("http server: %v", err)
 	}
 }

// Broadcast protocol messages to all peers for real peer propagation.
// This forwards the signed ProtocolMessage to each peer's /protocol/publish endpoint.
// The peer will re-sign the message locally, allowing a chain of signatures for provenance.
func (n *Node) broadcastProtocol(pm ProtocolMessage) {
	// Quick guard
	if pm.Type == "" && pm.CID == "" && pm.Data == "" {
		return
	}
	// Snapshot peers to avoid race conditions
	n.peersMu.Lock()
	peers := make([]PeerInfo, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p)
	}
	n.peersMu.Unlock()

	// Marshal once
	body, err := json.Marshal(pm)
	if err != nil {
		return
	}

	for _, p := range peers {
		peerAddr := strings.TrimRight(p.Addr, "/")
		// Forward to the peer's protocol publish endpoint
		url := peerAddr + "/protocol/publish"
		go func(u string, payload []byte) {
			req, err := http.NewRequest("POST", u, bytes.NewBuffer(payload))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err == nil {
				// Drain and close
				_, _ = io.Copy(ioutil.Discard, resp.Body)
				resp.Body.Close()
			}
		}(url, body)
	}
}

// In-memory protocol storage for Phase 3
var protocolMessages []ProtocolMessage
var protocolMu sync.Mutex

func storeProtocolMessage(pm ProtocolMessage) {
    protocolMu.Lock()
    protocolMessages = append(protocolMessages, pm)
    protocolMu.Unlock()
}

func handleProtocolMessages(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    protocolMu.Lock()
    out := make([]ProtocolMessage, len(protocolMessages))
    copy(out, protocolMessages)
    protocolMu.Unlock()
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

// Register route in init so it's available before main starts
func init() {
    http.HandleFunc("/protocol/messages", handleProtocolMessages)
}
