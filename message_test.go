package syslogevidence

import (
	"reflect"
	"testing"
)

func TestParseHeaderAndNilSD(t *testing.T) {
	m, err := ParseMessage([]byte("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 -"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := &Message{
		Priority: "34", Version: "1",
		Timestamp: "2003-10-11T22:14:15.003Z",
		Hostname:  "mymachine.example.com",
		AppName:   "su", ProcID: "-", MsgID: "ID47",
	}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("got %+v, want %+v", m, want)
	}
	if m.HasMsg {
		t.Fatal("HasMsg should be false when MSG is omitted")
	}
}

func TestParseEmptyMsgVsOmitted(t *testing.T) {
	m, err := ParseMessage([]byte("<13>1 - - - - - - "))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.HasMsg {
		t.Fatal("HasMsg should be true when separator space is present")
	}
	if len(m.Msg) != 0 {
		t.Fatalf("Msg should be empty, got %q", m.Msg)
	}
}

func TestParseElementsDuplicateParamsAndEscapes(t *testing.T) {
	body := `<13>1 - host app 1 ID1 [exampleSDID@32473 eventSource="Application" eventID="1011" eventID="2022"][x k="a\"b\\c\]d" weird="p\nq" empty=""]`
	m, err := ParseMessage([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []Element{
		{ID: "exampleSDID@32473", Params: []Param{
			{Name: "eventSource", Value: "Application"},
			{Name: "eventID", Value: "1011"},
			{Name: "eventID", Value: "2022"},
		}},
		{ID: "x", Params: []Param{
			{Name: "k", Value: `a"b\c]d`},
			{Name: "weird", Value: `p\nq`}, // unknown escape kept as two chars
			{Name: "empty", Value: ""},
		}},
	}
	if !reflect.DeepEqual(m.Elements, want) {
		t.Fatalf("got %+v, want %+v", m.Elements, want)
	}
}

func TestParseElementWithoutParams(t *testing.T) {
	m, err := ParseMessage([]byte(`<13>1 - - - - - [noparams]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Elements) != 1 || m.Elements[0].ID != "noparams" || len(m.Elements[0].Params) != 0 {
		t.Fatalf("bad elements: %+v", m.Elements)
	}
}

func TestParseMsgRawBytesAndBOM(t *testing.T) {
	// MSG with spaces, zero bytes, newline; not valid UTF-8, no BOM: allowed.
	raw := []byte("<13>1 - - - - - - hi \x00 there\n\xff\xfe")
	m, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte("hi \x00 there\n\xff\xfe")
	if !reflect.DeepEqual(m.Msg, want) {
		t.Fatalf("got %q, want %q", m.Msg, want)
	}

	// BOM + valid UTF-8: kept, BOM preserved.
	bom := []byte("<13>1 - - - - - - \xEF\xBB\xBF你好")
	m, err = ParseMessage(bom)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(m.Msg) != "\xEF\xBB\xBF你好" {
		t.Fatalf("BOM or content lost: %q", m.Msg)
	}

	// BOM + invalid UTF-8 after it: rejected.
	bad := []byte("<13>1 - - - - - - \xEF\xBB\xBFok\xff")
	if _, err = ParseMessage(bad); err == nil {
		t.Fatal("expected error for invalid UTF-8 after BOM")
	}
}

func TestParseMultibyteSDValue(t *testing.T) {
	m, err := ParseMessage([]byte(`<13>1 - - - - - [a b="汉字🙂"]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Elements[0].Params[0].Value != "汉字🙂" {
		t.Fatalf("got %q", m.Elements[0].Params[0].Value)
	}
}

func TestParseInvalidBodies(t *testing.T) {
	cases := map[string]string{
		"unterminated quote":   `<13>1 - - - - - [a b="abc]`,
		"unterminated element": `<13>1 - - - - - [a b="c"`,
		"bare right bracket":   `<13>1 - - - - - [a b="x]y"]`,
		"invalid utf-8 value":  "<13>1 - - - - - [a b=\"\xff\"]",
		"duplicate SD-ID":      `<13>1 - - - - - [a x="1"][a y="2"]`,
		"empty SD-ID":          `<13>1 - - - - - []`,
		"empty param name":     `<13>1 - - - - - [a ="v"]`,
		"missing equals":       `<13>1 - - - - - [a b"v"]`,
		"missing SD":           `<13>1 - - - - -`,
		"garbage after SD":     `<13>1 - - - - - -x`,
		"trailing backslash":   `<13>1 - - - - - [a b="x\`,
	}
	for name, body := range cases {
		if _, err := ParseMessage([]byte(body)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestParseNameCaseSensitive(t *testing.T) {
	m, err := ParseMessage([]byte(`<13>1 - - - - - [a Key="1" key="2"]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Elements[0].Params[0].Name != "Key" || m.Elements[0].Params[1].Name != "key" {
		t.Fatalf("case not preserved: %+v", m.Elements[0].Params)
	}
}
