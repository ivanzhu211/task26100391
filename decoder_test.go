package syslogevidence

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func frame(body string) string {
	return fmt.Sprintf("%d %s", len([]byte(body)), body)
}

// collect feeds chunks to a Decoder and returns all emitted results.
func collect(t *testing.T, chunks ...[]byte) []Result {
	t.Helper()
	var results []Result
	d := NewDecoder(func(r Result) { results = append(results, r) })
	for _, c := range chunks {
		if err := d.Write(c); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	return results
}

// splitEvery returns one two-chunk split of b per possible cut point.
func splitEvery(b []byte) [][][]byte {
	var out [][][]byte
	for i := 1; i < len(b); i++ {
		out = append(out, [][]byte{b[:i:i], b[i:]})
	}
	return out
}

const complexBody = `<13>1 2024-01-02T03:04:05Z host app 42 ID7 ` +
	`[meta tag="汉字🙂" tag="again" esc="a\"b\\c\]d" weird="x\ny\tz"]` +
	`[empty]` +
	" \xEF\xBB\xBFMSG 内容\n换行 \x00 零字节"

// wantMsg is the explicitly listed expectation for complexBody.
var wantMsg = &Message{
	Priority: "13", Version: "1",
	Timestamp: "2024-01-02T03:04:05Z",
	Hostname:  "host", AppName: "app", ProcID: "42", MsgID: "ID7",
	Elements: []Element{
		{ID: "meta", Params: []Param{
			{Name: "tag", Value: "汉字🙂"},
			{Name: "tag", Value: "again"},
			{Name: "esc", Value: `a"b\c]d`},
			{Name: "weird", Value: `x\ny\tz`}, // unknown escapes kept verbatim
		}},
		{ID: "empty"},
	},
	HasMsg: true,
	Msg:    []byte("\xEF\xBB\xBFMSG 内容\n换行 \x00 零字节"),
}

func TestChunkIndependence(t *testing.T) {
	input := []byte(frame(complexBody))
	for _, chunks := range splitEvery(input) {
		results := collect(t, chunks...)
		if len(results) != 1 {
			t.Fatalf("got %d results, want 1", len(results))
		}
		if results[0].Err != nil {
			t.Fatalf("unexpected error: %v", results[0].Err)
		}
		if !reflect.DeepEqual(results[0].Message, wantMsg) {
			t.Fatalf("got %+v, want %+v", results[0].Message, wantMsg)
		}
	}
	oneByte := make([][]byte, 0, len(input))
	for i := range input {
		oneByte = append(oneByte, input[i:i+1])
	}
	for _, chunks := range [][][]byte{oneByte, {input}} {
		results := collect(t, chunks...)
		if len(results) != 1 || results[0].Err != nil {
			t.Fatalf("bad results: %+v", results)
		}
		if !reflect.DeepEqual(results[0].Message, wantMsg) {
			t.Fatalf("got %+v, want %+v", results[0].Message, wantMsg)
		}
	}
}

func TestBadMessageBetweenGoodOnes(t *testing.T) {
	good1 := `<13>1 - - - - - [a k="v"] first`
	bad := `<13>1 - - - - - [a k="unterminated] oops`
	good2 := `<13>1 - - - - - [b x="y"] second 消息`
	input := []byte(frame(good1) + frame(bad) + frame(good2))

	// Feed in awkward chunks that split the bad frame's header and body.
	var chunks [][]byte
	for i := 0; i < len(input); i += 7 {
		end := i + 7
		if end > len(input) {
			end = len(input)
		}
		chunks = append(chunks, input[i:end])
	}
	results := collect(t, chunks...)

	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Err != nil || results[0].Message.Msg == nil ||
		string(results[0].Message.Msg) != "first" {
		t.Fatalf("first result wrong: %+v", results[0])
	}
	if results[1].Err == nil || results[1].Message != nil {
		t.Fatalf("middle result should be exactly one error, got %+v", results[1])
	}
	if !strings.Contains(results[1].Err.Error(), "invalid message body") {
		t.Fatalf("unexpected error text: %v", results[1].Err)
	}
	if results[2].Err != nil {
		t.Fatalf("third result should be a message: %+v", results[2])
	}
	if string(results[2].Message.Msg) != "second 消息" {
		t.Fatalf("third message corrupted: %q", results[2].Message.Msg)
	}
	if results[2].Message.Elements[0].Params[0].Value != "y" {
		t.Fatalf("third message SD corrupted: %+v", results[2].Message.Elements)
	}
}

func TestIncompleteFrameAtEOF(t *testing.T) {
	good := frame(`<13>1 - - - - - - done`)
	input := []byte(good + "12 <13>1 - -")
	results := collect(t, input)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Err != nil || string(results[0].Message.Msg) != "done" {
		t.Fatalf("first result wrong: %+v", results[0])
	}
	if results[1].Err == nil || !strings.Contains(results[1].Err.Error(), "incomplete frame") {
		t.Fatalf("expected terminal incomplete-frame error, got %+v", results[1])
	}
}

func TestCleanEndAtFrameBoundary(t *testing.T) {
	results := collect(t, []byte(frame(`<13>1 - - - - - - a`)+frame(`<13>1 - - - - - - b`)))
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("result %d unexpected error: %v", i, r.Err)
		}
	}
}

func TestMultipleFramesOneChunk(t *testing.T) {
	bodies := []string{
		`<13>1 - - - - - - one`,
		`<13>1 - - - - - [id p="1" p="2"]`,
		`<13>1 - - - - - - `,
	}
	var input string
	for _, b := range bodies {
		input += frame(b)
	}
	results := collect(t, []byte(input))
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if string(results[0].Message.Msg) != "one" {
		t.Fatalf("bad msg: %q", results[0].Message.Msg)
	}
	if len(results[1].Message.Elements[0].Params) != 2 {
		t.Fatalf("duplicate params lost: %+v", results[1].Message.Elements)
	}
	if !results[2].Message.HasMsg || len(results[2].Message.Msg) != 0 {
		t.Fatalf("empty MSG not distinguished from omitted: %+v", results[2].Message)
	}
}

func TestNewlineInBodyIsNotFrameBoundary(t *testing.T) {
	body := "<13>1 - - - - - - line1\nline2\nline3"
	results := collect(t, []byte(frame(body)))
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("bad results: %+v", results)
	}
	if string(results[0].Message.Msg) != "line1\nline2\nline3" {
		t.Fatalf("msg corrupted: %q", results[0].Message.Msg)
	}
}

func TestInvalidFrameHeader(t *testing.T) {
	var results []Result
	d := NewDecoder(func(r Result) { results = append(results, r) })
	if err := d.Write([]byte("x3 bad")); err == nil {
		t.Fatal("expected framing error")
	}
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("expected one error result, got %+v", results)
	}
}
