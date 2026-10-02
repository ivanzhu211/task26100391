package syslog

import (
	"reflect"
	"strconv"
	"testing"
)

// frame 把消息体包装成“长度+空格+消息体”的帧。
func frame(body string) []byte {
	return append([]byte(strconv.Itoa(len(body))+" "), body...)
}

// collect 依次喂入分片并汇总全部结果（含 Close 的结果）。
func collect(chunks ...[]byte) []Result {
	d := NewDecoder()
	var out []Result
	for _, c := range chunks {
		out = append(out, d.Write(c)...)
	}
	out = append(out, d.Close()...)
	return out
}

func TestBadMessageBetweenGoodOnes(t *testing.T) {
	good1 := `<13>1 T H A P M [a k="v"] first`
	bad := `<13>1 T H A P M [a k="unterminated]`
	good2 := `<14>1 T H A P M [b x="汉"] second`
	stream := append(append(frame(good1), frame(bad)...), frame(good2)...)

	results := collect(stream)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if results[0].Message == nil || string(results[0].Message.Msg) != "first" {
		t.Errorf("result[0] = %+v, want first good message", results[0])
	}
	if results[1].Error == nil || results[1].Error.Kind != ErrBadMessage {
		t.Fatalf("result[1] = %+v, want one ErrBadMessage", results[1])
	}
	if string(results[1].Error.Raw) != bad {
		t.Errorf("error raw = %q, want the bad body", results[1].Error.Raw)
	}
	last := results[2].Message
	if last == nil {
		t.Fatalf("result[2] = %+v, want second good message intact", results[2])
	}
	if last.Header.PRI != "14" || string(last.Msg) != "second" ||
		len(last.Elements) != 1 || last.Elements[0].Params[0].Value != "汉" {
		t.Errorf("second good message corrupted: %+v", last)
	}
}

func TestFragmentationIndependence(t *testing.T) {
	// 含多字节字符、BOM、转义序列的帧，转义与 BOM 会被分片切断。
	bodies := []string{
		`<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su 12345 ID47 [esc@1 k="q\"w\\e\]r\nx\t末" dup="1" dup="2"] ` + "\xEF\xBB\xBF正文\n第二行",
		`<13>1 T H A P M -`,
		`<13>1 T H A P M - `,
		`<13>1 T H A P M [x@1 a="b"] raw \x00\xff bytes`,
	}
	var stream []byte
	for _, b := range bodies {
		stream = append(stream, frame(b)...)
	}

	want := collect(stream)
	if len(want) != len(bodies) {
		t.Fatalf("whole-feed got %d results, want %d", len(want), len(bodies))
	}

	// 逐字节喂入。
	var chunks [][]byte
	for _, b := range stream {
		chunks = append(chunks, []byte{b})
	}
	if got := collect(chunks...); !reflect.DeepEqual(got, want) {
		t.Errorf("byte-by-byte results differ from whole-feed results")
	}

	// 在每个可能的位置切成两段。
	for i := 0; i <= len(stream); i++ {
		if got := collect(stream[:i], stream[i:]); !reflect.DeepEqual(got, want) {
			t.Fatalf("split at byte %d differs from whole-feed results", i)
		}
	}
}

func TestExpectedValuesAcrossFragments(t *testing.T) {
	// 明确列出期望值：多字节、BOM、已知/未知转义、重复参数。
	body := `<13>1 T H A P M [e@1 k="q\"w\\e\]r\nx\t末" k="二"] ` + "\xEF\xBB\xBF"
	d := NewDecoder()
	wire := frame(body)
	var results []Result
	for _, b := range wire {
		results = append(results, d.Write([]byte{b})...)
	}
	results = append(results, d.Close()...)
	if len(results) != 1 || results[0].Message == nil {
		t.Fatalf("got %+v, want one message", results)
	}
	msg := results[0].Message
	wantParams := []Param{
		{Name: "k", Value: "q\"w\\e]r\\nx\\t末"},
		{Name: "k", Value: "二"},
	}
	if !reflect.DeepEqual(msg.Elements[0].Params, wantParams) {
		t.Errorf("params = %+v, want %+v", msg.Elements[0].Params, wantParams)
	}
	if string(msg.Msg) != "\xEF\xBB\xBF" {
		t.Errorf("Msg = %q, want bare BOM preserved", msg.Msg)
	}
}

func TestTruncatedInputAtClose(t *testing.T) {
	good := frame(`<13>1 T H A P M - ok`)
	partial := []byte("27 <13>1 T H A")
	results := collect(good, partial)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Message == nil || string(results[0].Message.Msg) != "ok" {
		t.Errorf("result[0] = %+v, want completed good message", results[0])
	}
	if results[1].Error == nil || results[1].Error.Kind != ErrTruncated {
		t.Errorf("result[1] = %+v, want ErrTruncated", results[1])
	}
}

func TestTruncatedLengthOnlyAtClose(t *testing.T) {
	results := collect([]byte("123"))
	if len(results) != 1 || results[0].Error == nil || results[0].Error.Kind != ErrTruncated {
		t.Errorf("got %+v, want one ErrTruncated", results)
	}
}

func TestCleanCloseAtFrameBoundary(t *testing.T) {
	results := collect(frame(`<13>1 T H A P M - ok`))
	if len(results) != 1 || results[0].Message == nil {
		t.Fatalf("got %+v, want one message and no error", results)
	}
}

func TestZeroLengthFrameIsBadMessage(t *testing.T) {
	results := collect(frame(""), frame(`<13>1 T H A P M - ok`))
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Error == nil || results[0].Error.Kind != ErrBadMessage {
		t.Errorf("result[0] = %+v, want ErrBadMessage for empty body", results[0])
	}
	if results[1].Message == nil {
		t.Errorf("result[1] = %+v, want following good message intact", results[1])
	}
}
