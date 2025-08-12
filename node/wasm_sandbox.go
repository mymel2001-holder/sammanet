// node/wasm_sandbox.go
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/bytecodealliance/wasmtime-go"
)

// HostContext provides controlled capabilities the wasm can use.
type HostContext struct {
	DomainCID string            // origin/content id
	DataDir   string            // node data dir (for host storage)
	Storage   map[string]string // in-memory store for prototype; persist to disk in real node
	NodeURL   string            // local node URL for fetch_samman
	Timeout   time.Duration     // execution timeout
}

// RunWasm loads wasmBytes and runs exported function "run" or "main".
// Returns the string result (if any) and logs captured from host log().
func RunWasm(wasmBytes []byte, ctx *HostContext) (string, error) {
	engine := wasmtime.NewEngine()
	store := wasmtime.NewStore(engine)
	// set a context deadline so we can cancel long running executions
	cctx, cancel := context.WithTimeout(context.Background(), ctx.Timeout)
	defer cancel()
	store.SetContext(cctx)

	module, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		return "", fmt.Errorf("module compile: %w", err)
	}
	linker := wasmtime.NewLinker(engine)

	// memory will be provided by the wasm module; we get it at instantiation time
	var mem *wasmtime.Memory

	// helper: read string from wasm memory at ptr/len
	readStr := func(ptr int32, length int32) (string, error) {
		if mem == nil {
			return "", fmt.Errorf("memory not available")
		}
		data, ok := mem.UnsafeData(store)
		if !ok {
			return "", fmt.Errorf("cannot read memory")
		}
		start := int(ptr)
		end := start + int(length)
		if start < 0 || end > len(data) {
			return "", fmt.Errorf("invalid memory range")
		}
		return string(data[start:end]), nil
	}

	// helper: allocate memory for returning strings - we expect wasm to export alloc/free or similar.
	// For prototype, we will write responses back into an out buffer that wasm consulted with out_ptr pointer.
	// Because WASM memory layout is module-defined, we use a callback protocol:
	// host functions write utf8 bytes into memory at a pointer which wasm has reserved (out_ptr).
	// The wasm side must allocate a result buffer and pass its pointer address to host functions.

	// Host function: log(ptr,len)
	logs := bytes.Buffer{}
	logFunc := func(caller *wasmtime.Caller, ptr int32, len int32) {
		s, err := readStr(ptr, len)
		if err == nil {
			logs.WriteString(s)
			logs.WriteByte('\n')
		}
	}
	if err := linker.DefineFunc("env", "log", logFunc); err != nil {
		return "", err
	}

	// Host function: storage_get(key_ptr, key_len, out_ptr)
	storageGet := func(caller *wasmtime.Caller, keyPtr int32, keyLen int32, outPtr int32) int32 {
		k, err := readStr(keyPtr, keyLen)
		if err != nil {
			return 0
		}
		// read from ctx.Storage (prototype); production persist by domain
		val := ctx.Storage[k]
		// write back into memory at outPtr as: [u32 len][bytes...]
		if mem == nil {
			return 0
		}
		data, _ := mem.UnsafeData(store)
		// first 4 bytes at outPtr = length (little endian)
		offset := int(outPtr)
		if offset+4 > len(data) {
			return 0
		}
		binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(len(val)))
		// then copy bytes
		if offset+4+len(val) > len(data) {
			return 0
		}
		copy(data[offset+4:offset+4+len(val)], []byte(val))
		return 1
	}
	if err := linker.DefineFunc("env", "storage_get", storageGet); err != nil {
		return "", err
	}

	// Host function: storage_put(key_ptr, key_len, val_ptr, val_len) -> i32
	storagePut := func(caller *wasmtime.Caller, keyPtr int32, keyLen int32, valPtr int32, valLen int32) int32 {
		k, err := readStr(keyPtr, keyLen)
		if err != nil {
			return 0
		}
		v, err := readStr(valPtr, valLen)
		if err != nil {
			return 0
		}
		ctx.Storage[k] = v
		// In a real node persist to disk by domain
		return 1
	}
	if err := linker.DefineFunc("env", "storage_put", storagePut); err != nil {
		return "", err
	}

	// Host function: fetch_samman(cid_ptr, cid_len, out_ptr) -> i32
	fetchSamman := func(caller *wasmtime.Caller, cidPtr int32, cidLen int32, outPtr int32) int32 {
		cid, err := readStr(cidPtr, cidLen)
		if err != nil {
			return 0
		}
		// Restricted: only fetch from local node
		url := fmt.Sprintf("%s/fetch?cid=%s", ctx.NodeURL, cid)
		// simple HTTP GET with a short timeout
		client := &http.Client{Timeout: 3 * time.Second}
		r, err := client.Get(url)
		if err != nil || r.StatusCode != 200 {
			return 0
		}
		defer r.Body.Close()
		b, _ := ioutil.ReadAll(r.Body)
		body := string(b)
		// write at outPtr as [u32 len][bytes...]
		if mem == nil {
			return 0
		}
		data, _ := mem.UnsafeData(store)
		offset := int(outPtr)
		if offset+4 > len(data) {
			return 0
		}
		binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(len(body)))
		if offset+4+len(body) > len(data) {
			return 0
		}
		copy(data[offset+4:offset+4+len(body)], []byte(body))
		return 1
	}
	if err := linker.DefineFunc("env", "fetch_samman", fetchSamman); err != nil {
		return "", err
	}

	// Instantiate
	inst, err := linker.Instantiate(store, module)
	if err != nil {
		return "", fmt.Errorf("instantiate: %w", err)
	}

	// grab memory
	memVal := inst.GetExport(store, "memory")
	if memVal == nil {
		return "", fmt.Errorf("module has no memory export")
	}
	mem = memVal.Memory()

	// choose entrypoint: run or main
	var fn *wasmtime.Func
	if f := inst.GetExport(store, "run"); f != nil {
		fn = f.Func()
	} else if f := inst.GetExport(store, "main"); f != nil {
		fn = f.Func()
	} else {
		// no exported function: module may be a library; we return logs
		return logs.String(), nil
	}

	// call entrypoint with no args (for simplicity)
	_, err = fn.Call(store)
	if err != nil {
		return logs.String(), fmt.Errorf("runtime error: %w", err)
	}
	return logs.String(), nil
}