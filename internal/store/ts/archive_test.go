package ts

import (
	"bytes"
	"errors"
	"testing"
)

// COPY's text format (the PostgreSQL manual, "COPY, File Formats, Text
// Format"): every escape decodes, NULL is refused, a lone backslash is
// refused. The integration test round-trips the same values through the
// database, so these expectations are not only read from the manual.
func TestUnescapeCopyText(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:                "plain",
		`a\\b`:                 `a\b`,
		`tab\there`:            "tab\there",
		`nl\ncr\rbs\bff\fvt\v`: "nl\ncr\rbs\bff\fvt\v",
		`oct\101\7x`:           "octA\ax",
		`hex\x41\x4`:           "hexA\x04",
		`other\q`:              "otherq",
		`{"payload": "\\x0a"}`: `{"payload": "\x0a"}`,
		`json \\" quote`:       `json \" quote`,
		`\\N is not NULL here`: `\N is not NULL here`,
		`end\\`:                `end\`,
		`\x`:                   "x",
		`\xg`:                  "xg",
		`\0`:                   "\x00",
		`\777`:                 "\xff",
		`\1234`:                "S4",
		``:                     "",
	} {
		got, err := UnescapeCopyText([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	if _, err := UnescapeCopyText([]byte(`\N`)); !errors.Is(err, ErrCopyNull) {
		t.Errorf("NULL: %v", err)
	}
	if _, err := UnescapeCopyText([]byte(`lone\`)); err == nil {
		t.Error("a lone backslash was accepted")
	}
}

func FuzzUnescapeCopyText(f *testing.F) {
	for _, s := range []string{`a\\b`, `\t\n`, `\x4`, `\101`, `\`, `\N`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := UnescapeCopyText(b)
		if err == nil && bytes.IndexByte(b, '\\') < 0 && !bytes.Equal(out, b) {
			t.Fatalf("a value without escapes changed: %q -> %q", b, out)
		}
	})
}

func TestLineWriterSplitsRowsAcrossWrites(t *testing.T) {
	var rows []string
	w := &lineWriter{each: func(b []byte) error { rows = append(rows, string(b)); return nil }}
	for _, p := range []string{"a\tb\nc", "d\n", "e\nf"} {
		if _, err := w.Write([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	if len(rows) != 3 || rows[0] != "a\tb" || rows[1] != "cd" || rows[2] != "e" || string(w.buf) != "f" || w.rows != 3 {
		t.Fatalf("%q rows %d rest %q", rows, w.rows, w.buf)
	}
	w.each = func([]byte) error { return errors.New("stop") }
	if _, err := w.Write([]byte("\n")); err == nil {
		t.Fatal("an error of each was swallowed")
	}
}
