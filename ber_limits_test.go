package pkcs7

import (
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"
)

// This file turns the BER->DER boundary rules into executable tests:
//
//   - constructed nesting and the explicit depth cap (no unbounded recursion),
//   - definite vs indefinite length encodings and canonical DER output,
//   - trailing bytes, truncated encodings and child/parent content overrun,
//   - output state after failure (no half-written DER, no state carried over
//     between calls to the same converter).
//
// Helpers build nested BER from the inside out so that every declared length
// in a definite-length fixture is exact.

// appendBERLength wraps b in a constructed tag with a minimal definite-length
// header for the given content length.
func appendBERLength(b []byte, tag byte, contentLen int) []byte {
	head := []byte{tag}
	switch {
	case contentLen < 128:
		head = append(head, byte(contentLen))
	case contentLen < 256:
		head = append(head, 0x81, byte(contentLen))
	default:
		head = append(head, 0x82, byte(contentLen>>8), byte(contentLen))
	}
	return append(head, b...)
}

// buildNestedDefinite returns `wrappers` definite-length constructed tags
// around an INTEGER 1 primitive. Every length is already minimal, so the BER
// is itself canonical DER and ber2der must return it unchanged.
func buildNestedDefinite(wrappers int) []byte {
	b := []byte{0x02, 0x01, 0x01}
	for i := 0; i < wrappers; i++ {
		b = appendBERLength(append([]byte{}, b...), 0x30, len(b))
	}
	return b
}

// buildNestedIndefinite returns `wrappers` indefinite-length constructed tags
// around an INTEGER 1 primitive, each closed by a 0x0000 EOC.
func buildNestedIndefinite(wrappers int) []byte {
	b := []byte{0x02, 0x01, 0x01}
	for i := 0; i < wrappers; i++ {
		b = append(append([]byte{0x30, 0x80}, b...), 0x00, 0x00)
	}
	return b
}

// buildNestedMixed alternates indefinite and definite constructed wrappers,
// exercising both length forms along the same recursion chain.
func buildNestedMixed(wrappers int) []byte {
	b := []byte{0x02, 0x01, 0x01}
	for i := 0; i < wrappers; i++ {
		if i%2 == 0 {
			b = append(append([]byte{0x30, 0x80}, b...), 0x00, 0x00)
		} else {
			b = appendBERLength(append([]byte{}, b...), 0x30, len(b))
		}
	}
	return b
}

// mustConvert fails the test if ber2der errors or panics, and returns the DER.
func mustConvert(t *testing.T, in []byte) []byte {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ber2der(% X) panicked: %v", in, r)
		}
	}()
	der, err := ber2der(in)
	if err != nil {
		t.Fatalf("ber2der(% X) unexpected error: %v", in, err)
	}
	return der
}

// assertFails runs ber2der, requires an error containing want, requires a nil
// output buffer and turns any panic into a test failure.
func assertFails(t *testing.T, in []byte, want string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ber2der(% X) panicked instead of returning error: %v", in, r)
		}
	}()
	der, err := ber2der(in)
	if err == nil {
		t.Errorf("ber2der(% X): expected error containing %q, got nil and output % X", in, want, der)
		return
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("ber2der(% X): error = %q, want substring %q", in, err.Error(), want)
	}
	if der != nil {
		t.Errorf("ber2der(% X): failed conversion left output bytes % X", in, der)
	}
}

// assertCanonicalDER transcodes in and checks that the result is a single
// complete ASN.1 object with no trailing bytes and is idempotent under a
// second conversion.
func assertCanonicalDER(t *testing.T, in, want []byte) {
	t.Helper()
	der := mustConvert(t, in)
	if !bytes.Equal(der, want) {
		t.Errorf("ber2der(% X) = % X, want % X", in, der, want)
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		t.Errorf("result % X is not valid DER: %v", der, err)
	}
	if len(rest) != 0 {
		t.Errorf("result % X has trailing bytes: % X", der, rest)
	}
	if again := mustConvert(t, der); !bytes.Equal(again, der) {
		t.Errorf("ber2der not idempotent: first % X, second % X", der, again)
	}
}

func TestBer2Der_NestedDefiniteIsCanonical(t *testing.T) {
	t.Parallel()
	// Two definite wrappers around INTEGER 1; lengths are already minimal.
	want := []byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01}
	assertCanonicalDER(t, buildNestedDefinite(2), want)
}

func TestBer2Der_IndefiniteNormalizesToDefinite(t *testing.T) {
	t.Parallel()
	// One and two indefinite wrappers must become definite-length DER, and the
	// result must be byte-identical to the all-definite construction.
	assertCanonicalDER(t,
		[]byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00},
		[]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	assertCanonicalDER(t, buildNestedIndefinite(2), buildNestedDefinite(2))
}

func TestBer2Der_MixedDefiniteAndIndefinite(t *testing.T) {
	t.Parallel()
	// Both length forms on one recursion chain collapse to one definite DER.
	assertCanonicalDER(t, buildNestedMixed(4), buildNestedDefinite(4))
}

func TestBer2Der_LongFormLengthIsMinimized(t *testing.T) {
	t.Parallel()
	// A non-minimal long-form length (81 03 for a 3-byte content) is BER-legal
	// but not DER: the output must use the short-form length octet 03.
	short := []byte{0x04, 0x81, 0x03, 0xAA, 0xBB, 0xCC}
	assertCanonicalDER(t, short, []byte{0x04, 0x03, 0xAA, 0xBB, 0xCC})

	// A genuinely long content keeps its minimal multi-octet length unchanged.
	content := make([]byte, 500)
	long := append([]byte{0x04, 0x82, 0x01, 0xF4}, content...)
	assertCanonicalDER(t, long, long)
}

func TestBer2Der_DepthLimitBoundary(t *testing.T) {
	t.Parallel()
	// The primitive below `wrappers` constructed tags is parsed at depth
	// wrappers+1, so wrappers == maxBerDepth-1 is the deepest legal input and
	// wrappers == maxBerDepth is the first rejected one, for both length forms.
	deepestLegal := maxBerDepth - 1
	assertCanonicalDER(t, buildNestedIndefinite(deepestLegal), buildNestedDefinite(deepestLegal))
	assertCanonicalDER(t, buildNestedDefinite(deepestLegal), buildNestedDefinite(deepestLegal))

	assertFails(t, buildNestedIndefinite(maxBerDepth), "nesting depth exceeded")
	assertFails(t, buildNestedDefinite(maxBerDepth), "nesting depth exceeded")
}

func TestBer2Der_ExtremeNestingFailsFast(t *testing.T) {
	t.Parallel()
	// Before the depth cap these inputs recursed until the goroutine stack was
	// exhausted (an unrecoverable runtime fatal). They must now return the
	// depth error after a bounded number of frames, for every length form.
	for _, in := range [][]byte{
		buildNestedIndefinite(10000), // ten times the cap
		buildNestedDefinite(1500),    // crosses the cap; definite size grows per level
		buildNestedMixed(3000),
	} {
		assertFails(t, in, "nesting depth exceeded")
	}
}

func TestBer2Der_TrailingDataRejected(t *testing.T) {
	t.Parallel()
	// Bytes outside the single parsed object must never be absorbed into the
	// DER result, regardless of whether the object is primitive, definite
	// constructed or indefinite constructed.
	fixtures := [][]byte{
		{0x02, 0x01, 0x01, 0x00},                         // primitive + 1 byte
		{0x30, 0x03, 0x02, 0x01, 0x01, 0xFF},             // definite wrapper + 1 byte
		{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0xFF}, // indefinite wrapper + 1 byte
		{0x02, 0x01, 0x01, 0x02, 0x01, 0x02},             // two complete TLVs
	}
	for _, in := range fixtures {
		assertFails(t, in, "trailing data after BER object")
	}

	// Sanity check: the same object without the trailing suffix converts and
	// contains none of the trailing bytes.
	clean := []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}
	der := mustConvert(t, clean)
	if bytes.Contains(der, []byte{0xFF}) {
		t.Errorf("converted DER unexpectedly contains trailing marker: % X", der)
	}
}

func TestBer2Der_TruncationAndBoundaryErrors(t *testing.T) {
	t.Parallel()
	fixtures := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "tag octet only",
			input: []byte{0x30},
			want:  "end of ber data reached",
		},
		{
			name:  "long-form length octets missing",
			input: []byte{0x30, 0x81},
			want:  "more than available data",
		},
		{
			name:  "primitive content truncated",
			input: []byte{0x02, 0x05, 0x01, 0x02},
			want:  "more than available data",
		},
		{
			name:  "constructed content truncated",
			input: []byte{0x30, 0x05, 0x02, 0x01, 0x01},
			want:  "more than available data",
		},
		{
			name:  "top-level child overruns parent content",
			input: []byte{0x30, 0x02, 0x02, 0x03, 0x01, 0x02, 0x03},
			want:  "child object exceeds the enclosing object's declared content length",
		},
		{
			name:  "nested child overruns its parent content",
			input: []byte{0x30, 0x07, 0x30, 0x02, 0x02, 0x03, 0x01, 0x02, 0x03},
			want:  "child object exceeds the enclosing object's declared content length",
		},
		{
			name:  "indefinite object missing EOC",
			input: []byte{0x30, 0x80, 0x02, 0x01, 0x01},
			want:  "Invalid BER format",
		},
		{
			name:  "indefinite object truncated inside child",
			input: []byte{0x30, 0x80, 0x02},
			want:  "end of ber data reached",
		},
		{
			name:  "indefinite length on primitive encoding",
			input: []byte{0x02, 0x80, 0x00, 0x00},
			want:  "Indefinite form tag must have constructed encoding",
		},
		{
			name:  "trailing bytes after complete object",
			input: []byte{0x02, 0x01, 0x01, 0x00},
			want:  "trailing data after BER object",
		},
		{
			name:  "nesting beyond depth cap",
			input: buildNestedIndefinite(maxBerDepth),
			want:  "nesting depth exceeded",
		},
	}

	// Each fixture must fail with its declared error class. Distinct failure
	// classes (truncation, content overrun, invalid indefinite encoding, depth
	// and trailing data) are checked separately in
	// TestBer2Der_ErrorClassesAreDistinguishable.
	for _, f := range fixtures {
		f := f
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			assertFails(t, f.input, f.want)
		})
	}
}

func TestBer2Der_ErrorClassesAreDistinguishable(t *testing.T) {
	t.Parallel()
	// One representative input per failure reason. Every reason must map to a
	// distinct error string so callers can tell them apart; none may be masked
	// by a generic failure.
	representatives := []struct {
		reason string
		input  []byte
		want   string
	}{
		{"empty input", nil, "input ber is empty"},
		{"truncated encoding", []byte{0x30}, "end of ber data reached"},
		{"declared length past data", []byte{0x02, 0x05, 0x01}, "more than available data"},
		{"child overruns parent content", []byte{0x30, 0x02, 0x02, 0x03, 0x01, 0x02, 0x03}, "child object exceeds the enclosing object's declared content length"},
		{"invalid indefinite encoding", []byte{0x30, 0x80, 0x02, 0x01, 0x01}, "Invalid BER format"},
		{"indefinite length on primitive", []byte{0x02, 0x80, 0x00, 0x00}, "Indefinite form tag must have constructed encoding"},
		{"trailing data", []byte{0x02, 0x01, 0x01, 0xFF}, "trailing data after BER object"},
		{"depth cap", buildNestedIndefinite(maxBerDepth), "nesting depth exceeded"},
	}
	seen := make(map[string]string)
	for _, r := range representatives {
		r := r
		t.Run(r.reason, func(t *testing.T) {
			t.Parallel()
			assertFails(t, r.input, r.want)
		})
		if prev, dup := seen[r.want]; dup {
			t.Errorf("error class %q used by both %q and %q", r.want, prev, r.reason)
		}
		seen[r.want] = r.reason
	}
}

func TestBer2Der_FailedConversionLeavesNoOutput(t *testing.T) {
	t.Parallel()
	// Every malformed input must return a nil result, never a partially written
	// DER buffer.
	bad := [][]byte{
		{},
		{0x30},
		{0x30, 0x81},
		{0x02, 0x05, 0x01},
		{0x30, 0x80, 0x02, 0x01, 0x01},
		{0x30, 0x02, 0x02, 0x03, 0x01, 0x02, 0x03},
		{0x02, 0x01, 0x01, 0xFF},
		buildNestedIndefinite(maxBerDepth),
	}
	for _, in := range bad {
		der, err := ber2der(in)
		if err == nil {
			t.Errorf("ber2der(% X): expected error, got output % X", in, der)
			continue
		}
		if der != nil {
			t.Errorf("ber2der(% X): error %q but non-nil output % X", in, err, der)
		}
	}
}

func TestBer2Der_NoStateCarriedBetweenCalls(t *testing.T) {
	t.Parallel()
	// ber2der holds no converter state: a rejected input must not change the
	// result of converting a legal input afterwards. Interleave every class of
	// failure with a known-good conversion and compare against the standalone
	// result.
	goodBER := []byte{0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}
	wantDER := []byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01}
	baseline := mustConvert(t, goodBER)
	if !bytes.Equal(baseline, wantDER) {
		t.Fatalf("baseline conversion = % X, want % X", baseline, wantDER)
	}

	failures := [][]byte{
		buildNestedIndefinite(maxBerDepth),         // depth cap
		{0x02, 0x05, 0x01},                         // truncated length/content
		{0x30, 0x02, 0x02, 0x03, 0x01, 0x02, 0x03}, // boundary overrun
		{0x02, 0x01, 0x01, 0xFF},                   // trailing data
		{0x30, 0x80, 0x02, 0x01, 0x01},             // missing EOC
	}
	for _, bad := range failures {
		if _, err := ber2der(bad); err == nil {
			t.Fatalf("malformed input % X unexpectedly converted", bad)
		}
		der := mustConvert(t, goodBER)
		if !bytes.Equal(der, baseline) {
			t.Errorf("after failure on % X, good input converted to % X, want baseline % X", bad, der, baseline)
		}
	}

	// The returned slice is independently owned: mutating one result must not
	// affect the next conversion of the same input.
	first := mustConvert(t, goodBER)
	second := mustConvert(t, goodBER)
	first[0] ^= 0xFF
	if bytes.Equal(first, second) {
		t.Error("mutating one ber2der result altered another result: output aliasing")
	}
}

func TestParse_RejectsTrailingBER(t *testing.T) {
	t.Parallel()
	// Parse must reject trailing bytes at the BER boundary rather than relying
	// on the downstream ASN.1 unmarshaler to notice them.
	in := append(append([]byte{}, buildNestedDefinite(1)...), 0xAA)
	_, err := Parse(in)
	if err == nil {
		t.Fatalf("Parse(% X): expected trailing-data error, got nil", in)
	}
	if !strings.Contains(err.Error(), "trailing data after BER object") {
		t.Errorf("Parse error = %q, want substring %q", err.Error(), "trailing data after BER object")
	}
}
