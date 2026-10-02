package syslog

import (
	"reflect"
	"testing"
)

func mustParse(t *testing.T, body string) *Message {
	t.Helper()
	msg, perr := parseMessage([]byte(body))
	if perr != nil {
		t.Fatalf("parseMessage(%q) unexpected error: %s", body, perr.Err)
	}
	return msg
}

func mustFail(t *testing.T, body string) *Error {
	t.Helper()
	msg, perr := parseMessage([]byte(body))
	if perr == nil {
		t.Fatalf("parseMessage(%q) expected error, got message %+v", body, msg)
	}
	if perr.Kind != ErrBadMessage {
		t.Fatalf("parseMessage(%q) error kind = %v, want ErrBadMessage", body, perr.Kind)
	}
	return perr
}

func TestParseHeaderOnlyNoMsg(t *testing.T) {
	msg := mustParse(t, "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su 12345 ID47 -")
	want := Header{PRI: "34", Version: "1", Timestamp: "2003-10-11T22:14:15.003Z",
		Hostname: "mymachine.example.com", AppName: "su", ProcID: "12345", MsgID: "ID47"}
	if msg.Header != want {
		t.Errorf("header = %+v, want %+v", msg.Header, want)
	}
	if msg.Elements != nil {
		t.Errorf("elements = %+v, want nil for '-' SD", msg.Elements)
	}
	if msg.HasMsg {
		t.Errorf("HasMsg = true, want false when MSG omitted")
	}
}

func TestParseEmptyMsgVsOmitted(t *testing.T) {
	withSpace := mustParse(t, "<34>1 T H A P M - ")
	if !withSpace.HasMsg {
		t.Errorf("HasMsg = false, want true when separator space present")
	}
	if len(withSpace.Msg) != 0 {
		t.Errorf("Msg = %q, want empty", withSpace.Msg)
	}
	without := mustParse(t, "<34>1 T H A P M -")
	if without.HasMsg {
		t.Errorf("HasMsg = true, want false when MSG omitted")
	}
}

func TestParseElementsRepeatedParamsAndEscapes(t *testing.T) {
	// 重复参数名、未知转义 \n \t 原样保留、已知转义 \" \\ \] 还原、多字节值。
	msg := mustParse(t, `<13>1 T H A P M [exampleSDID@32473 iut="3" eventID="1011" eventID="1011"][esc@1 k="q\"w\\e\]r\nx\t末"][empty@2] `+"\xEF\xBB\xBF"+`正文`)
	if len(msg.Elements) != 3 {
		t.Fatalf("elements count = %d, want 3", len(msg.Elements))
	}
	first := msg.Elements[0]
	if first.ID != "exampleSDID@32473" {
		t.Errorf("element[0].ID = %q", first.ID)
	}
	wantParams := []Param{
		{Name: "iut", Value: "3"},
		{Name: "eventID", Value: "1011"},
		{Name: "eventID", Value: "1011"},
	}
	if !reflect.DeepEqual(first.Params, wantParams) {
		t.Errorf("element[0].Params = %+v, want %+v", first.Params, wantParams)
	}
	esc := msg.Elements[1]
	wantValue := "q\"w\\e]r\\nx\\t末"
	if len(esc.Params) != 1 || esc.Params[0].Name != "k" || esc.Params[0].Value != wantValue {
		t.Errorf("element[1].Params = %+v, want single k=%q", esc.Params, wantValue)
	}
	if len(msg.Elements[2].Params) != 0 {
		t.Errorf("element[2].Params = %+v, want none", msg.Elements[2].Params)
	}
	if !msg.HasMsg {
		t.Fatalf("HasMsg = false, want true")
	}
	wantMsg := "\xEF\xBB\xBF正文"
	if string(msg.Msg) != wantMsg {
		t.Errorf("Msg = %q, want %q (BOM must be preserved)", msg.Msg, wantMsg)
	}
}

func TestParseMsgPreservesBytes(t *testing.T) {
	body := "<13>1 T H A P M - raw \x00bytes\xff and\nnewlines "
	msg := mustParse(t, body)
	want := "raw \x00bytes\xff and\nnewlines "
	if string(msg.Msg) != want {
		t.Errorf("Msg = %q, want %q", msg.Msg, want)
	}
}

func TestParseBOMRequiresUTF8(t *testing.T) {
	bad := "<13>1 T H A P M - \xEF\xBB\xBFvalid\xffinvalid"
	perr := mustFail(t, bad)
	if perr.Err == "" {
		t.Errorf("expected reason for BOM+invalid UTF-8")
	}
	good := "<13>1 T H A P M - \xEF\xBB\xBF汉字"
	if _, perr := parseMessage([]byte(good)); perr != nil {
		t.Errorf("BOM + valid UTF-8 should parse, got %s", perr.Err)
	}
}

func TestParseInvalidBodies(t *testing.T) {
	cases := map[string]string{
		"unterminated quote":   `<13>1 T H A P M [a k="v]`,
		"unterminated element": `<13>1 T H A P M [a k="v"`,
		"bare right bracket":   `<13>1 T H A P M [a k="v]w"]`,
		"invalid utf-8 value":  "<13>1 T H A P M [a k=\"\xff\"]",
		"duplicate element id": `<13>1 T H A P M [a x="1"][a y="2"]`,
		"name too long":        `<13>1 T H A P M [abcdefghijklmnopqrstuvwxyzabcdefg x="1"]`,
		"empty element id":     `<13>1 T H A P M []`,
		"junk after SD":        `<13>1 T H A P M -x`,
		"missing header":       `hello`,
		"empty body":           ``,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) { mustFail(t, body) })
	}
}
