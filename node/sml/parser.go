// **OUTDATED, REPLACED WITH MAIN NODE**
// sml/parser.go
//
// Simple Sammanet Markdown Language (SML) parser.
// Usage:
//   html, err := ParseSML(smlBytes, ParseOptions{
//       FetchByCID: func(cid string) ([]byte, error) { ... },
//       IncludeResolver: func(domainPath string) ([]byte, error) { ... },
//   })
//
// Dependencies:
//   go get github.com/russross/blackfriday/v2
//   go get github.com/microcosm-cc/bluemonday

package sml

import (
	"bytes"
	"fmt"
	"html"
	"regexp"
	"strings"

	bf "github.com/russross/blackfriday/v2"
	"github.com/microcosm-cc/bluemonday"
)

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

// directive regexes
var (
	reInclude = regexp.MustCompile(`@include\(\s*([a-zA-Z0-9._\-\/]+)\s*\)`)
	reFetch   = regexp.MustCompile(`@fetch\(\s*([A-Za-z0-9:+\-_.]+)\s*\)`)
	// script wasm tag: <script lang="wasm" src="wasm_cid:..."></script>
	reWasmScript = regexp.MustCompile(`(?is)<script\s+[^>]*lang\s*=\s*"(?:wasm|WASM)"[^>]*src\s*=\s*"(wasm_cid:[^"]+)"[^>]*>.*?</script>`)
	// allow inline style tags capture
	reStyle = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
)

// ParseSML parses an SML document and returns sanitized HTML.
// It expands directives via callbacks and renders Markdown via blackfriday.
func ParseSML(input []byte, opts ParseOptions) (string, error) {
	// default opts
	if opts.FetchByCID == nil {
		// set no-op fetcher that returns error
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
		// included content may itself be SML; call ParseSML recursively but avoid infinite recursion by passing nil resolvers? We will inline raw markdown here.
		// For simplicity, render included content as markdown fragment (no further includes)
		incHTML := string(b)
		// If included appears to be SML, run markdown on it
		incHTML = string(bf.Run([]byte(incHTML)))
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
		frag := string(bf.Run(b))
		return frag
	})

	// Step 5: Render Markdown -> HTML (blackfriday)
	md := []byte(content)
	htmlBytes := bf.Run(md, bf.WithExtensions(bf.CommonExtensions|bf.AutoHeadingIDs))
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

	// Step 8: Post-process: Ensure <samman-wasm> placeholders remain (bluemonday allowed it above)
	// (Nothing else required here.)

	return safe, nil
}
