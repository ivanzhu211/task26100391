// Package syslogevidence decodes length-counted frames of RFC5424 syslog
// messages into in-memory evidence records.
package syslogevidence

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// Param is a single name="value" pair inside a structured-data element.
// Duplicate names are preserved in order.
type Param struct {
	Name  string
	Value string
}

// Element is one RFC5424 structured-data element, e.g. [id k="v"].
type Element struct {
	ID     string
	Params []Param
}

// Message is a decoded RFC5424 message body.
type Message struct {
	Priority  string
	Version   string
	Timestamp string
	Hostname  string
	AppName   string
	ProcID    string
	MsgID     string
	Elements  []Element // nil when SD is "-"
	HasMsg    bool      // false when MSG is omitted entirely
	Msg       []byte    // raw MSG bytes, BOM included
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ParseMessage parses one complete RFC5424 message body.
func ParseMessage(body []byte) (*Message, error) {
	p := &msgParser{buf: body}
	return p.parse()
}

type msgParser struct {
	buf []byte
	pos int
}

func (p *msgParser) parse() (*Message, error) {
	m := &Message{}

	// <PRI>
	if p.pos >= len(p.buf) || p.buf[p.pos] != '<' {
		return nil, errors.New("missing '<' at PRI start")
	}
	end := indexByteFrom(p.buf, '>', p.pos+1)
	if end < 0 {
		return nil, errors.New("unterminated PRI")
	}
	m.Priority = string(p.buf[p.pos+1 : end])
	p.pos = end + 1

	// SP-separated header fields, each guaranteed non-empty and space-free.
	// VERSION directly follows '>'; the rest are preceded by SP.
	fields := []*string{&m.Version, &m.Timestamp, &m.Hostname, &m.AppName, &m.ProcID, &m.MsgID}
	for i, f := range fields {
		if i > 0 {
			if p.pos >= len(p.buf) || p.buf[p.pos] != ' ' {
				return nil, errors.New("truncated header")
			}
			p.pos++
		}
		sp := indexByteFrom(p.buf, ' ', p.pos)
		if sp < 0 {
			return nil, errors.New("truncated header")
		}
		*f = string(p.buf[p.pos:sp])
		p.pos = sp
	}
	// p.pos is at the SP before SD.
	p.pos++

	if err := p.parseSD(m); err != nil {
		return nil, err
	}

	// Optional SP MSG.
	if p.pos < len(p.buf) {
		if p.buf[p.pos] != ' ' {
			return nil, fmt.Errorf("unexpected byte 0x%02x after structured data", p.buf[p.pos])
		}
		p.pos++
		m.HasMsg = true
		m.Msg = append([]byte(nil), p.buf[p.pos:]...)
		if len(m.Msg) >= 3 && string(m.Msg[:3]) == string(utf8BOM) {
			if !utf8.Valid(m.Msg[3:]) {
				return nil, errors.New("MSG after BOM is not valid UTF-8")
			}
		}
	}
	return m, nil
}

func (p *msgParser) parseSD(m *Message) error {
	if p.pos >= len(p.buf) {
		return errors.New("missing structured data")
	}
	if p.buf[p.pos] == '-' {
		p.pos++
		return nil
	}
	seen := make(map[string]bool)
	for p.pos < len(p.buf) && p.buf[p.pos] == '[' {
		el, err := p.parseElement()
		if err != nil {
			return err
		}
		if seen[el.ID] {
			return fmt.Errorf("duplicate SD-ID %q", el.ID)
		}
		seen[el.ID] = true
		m.Elements = append(m.Elements, *el)
	}
	if len(m.Elements) == 0 {
		return errors.New("invalid structured data")
	}
	return nil
}

func (p *msgParser) parseElement() (*Element, error) {
	p.pos++ // consume '['
	id, err := p.parseName("SD-ID")
	if err != nil {
		return nil, err
	}
	el := &Element{ID: id}
	for {
		if p.pos >= len(p.buf) {
			return nil, errors.New("unterminated element")
		}
		switch p.buf[p.pos] {
		case ']':
			p.pos++
			return el, nil
		case ' ':
			p.pos++
			name, err := p.parseName("param name")
			if err != nil {
				return nil, err
			}
			if p.pos >= len(p.buf) || p.buf[p.pos] != '=' {
				return nil, fmt.Errorf("missing '=' after param name %q", name)
			}
			p.pos++
			value, err := p.parseValue()
			if err != nil {
				return nil, err
			}
			el.Params = append(el.Params, Param{Name: name, Value: value})
		default:
			return nil, fmt.Errorf("unexpected byte 0x%02x in element", p.buf[p.pos])
		}
	}
}

// parseName reads a 1-32 byte printable-ASCII name (no SP, '=', ']', '"').
func (p *msgParser) parseName(what string) (string, error) {
	start := p.pos
	for p.pos < len(p.buf) && isNameByte(p.buf[p.pos]) {
		p.pos++
	}
	n := p.pos - start
	if n == 0 {
		return "", fmt.Errorf("empty %s", what)
	}
	if n > 32 {
		return "", fmt.Errorf("%s exceeds 32 bytes", what)
	}
	return string(p.buf[start:p.pos]), nil
}

func isNameByte(b byte) bool {
	if b < 0x21 || b > 0x7E {
		return false
	}
	return b != '=' && b != ']' && b != '"'
}

// parseValue reads a quoted param value and returns it unescaped.
func (p *msgParser) parseValue() (string, error) {
	if p.pos >= len(p.buf) || p.buf[p.pos] != '"' {
		return "", errors.New("missing opening quote of param value")
	}
	p.pos++
	rawStart := p.pos
	var out []byte
	for {
		if p.pos >= len(p.buf) {
			return "", errors.New("unterminated param value")
		}
		b := p.buf[p.pos]
		switch b {
		case '"':
			raw := p.buf[rawStart:p.pos]
			if !utf8.Valid(raw) {
				return "", errors.New("param value is not valid UTF-8")
			}
			p.pos++
			if out == nil {
				return string(raw), nil
			}
			return string(out), nil
		case ']':
			return "", errors.New("bare ']' in param value")
		case '\\':
			if p.pos+1 >= len(p.buf) {
				return "", errors.New("unterminated escape in param value")
			}
			next := p.buf[p.pos+1]
			if out == nil {
				out = append([]byte(nil), p.buf[rawStart:p.pos]...)
			}
			if next == '"' || next == '\\' || next == ']' {
				out = append(out, next)
			} else {
				out = append(out, b, next)
			}
			p.pos += 2
		default:
			if out != nil {
				out = append(out, b)
			}
			p.pos++
		}
	}
}

func indexByteFrom(b []byte, c byte, from int) int {
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}
