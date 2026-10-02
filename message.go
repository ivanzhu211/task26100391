package syslog

import (
	"fmt"
	"unicode/utf8"
)

var bom = []byte{0xEF, 0xBB, 0xBF}

// parser 是消息体解析游标。
type parser struct {
	buf []byte
	pos int
}

// parseMessage 解析一个完整帧的消息体。
// 成功返回 *Message，失败返回 *Error（ErrBadMessage），不输出半条证据。
func parseMessage(body []byte) (*Message, *Error) {
	p := &parser{buf: body}
	msg, err := p.parse()
	if err != nil {
		return nil, &Error{Kind: ErrBadMessage, Raw: body, Err: err.Error()}
	}
	return msg, nil
}

func (p *parser) parse() (*Message, error) {
	msg := &Message{}
	if err := p.parseHeader(&msg.Header); err != nil {
		return nil, err
	}
	elements, err := p.parseSD()
	if err != nil {
		return nil, err
	}
	msg.Elements = elements
	if p.pos == len(p.buf) {
		return msg, nil
	}
	if p.buf[p.pos] != ' ' {
		return nil, fmt.Errorf("unexpected byte 0x%02x after structured data", p.buf[p.pos])
	}
	p.pos++
	msg.HasMsg = true
	msg.Msg = append([]byte(nil), p.buf[p.pos:]...)
	if hasBOM(msg.Msg) && !utf8.Valid(msg.Msg) {
		return nil, fmt.Errorf("MSG with UTF-8 BOM must be valid UTF-8")
	}
	return msg, nil
}

// parseHeader 解析 “<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ”。
// 各字段保证合法且不含空格，只提取并保留原值。
func (p *parser) parseHeader(h *Header) error {
	if p.pos >= len(p.buf) || p.buf[p.pos] != '<' {
		return fmt.Errorf("header must start with '<'")
	}
	end := indexByteFrom(p.buf, '>', p.pos+1)
	if end < 0 {
		return fmt.Errorf("unterminated PRI in header")
	}
	h.PRI = string(p.buf[p.pos+1 : end])
	p.pos = end + 1
	fields := []*string{&h.Version, &h.Timestamp, &h.Hostname, &h.AppName, &h.ProcID, &h.MsgID}
	for _, f := range fields {
		tok, err := p.token()
		if err != nil {
			return err
		}
		*f = tok
	}
	return nil
}

// token 读取一个以空格结尾的头部字段。
func (p *parser) token() (string, error) {
	end := indexByteFrom(p.buf, ' ', p.pos)
	if end < 0 {
		return "", fmt.Errorf("truncated header field")
	}
	tok := string(p.buf[p.pos:end])
	p.pos = end + 1
	return tok, nil
}

// parseSD 解析结构化数据：单个减号，或连续拼接的一个以上元素。
func (p *parser) parseSD() ([]Element, error) {
	if p.pos >= len(p.buf) {
		return nil, fmt.Errorf("missing structured data")
	}
	if p.buf[p.pos] == '-' {
		p.pos++
		return nil, nil
	}
	var elements []Element
	seen := map[string]bool{}
	for p.pos < len(p.buf) && p.buf[p.pos] == '[' {
		el, err := p.parseElement()
		if err != nil {
			return nil, err
		}
		if seen[el.ID] {
			return nil, fmt.Errorf("duplicate SD element id %q", el.ID)
		}
		seen[el.ID] = true
		elements = append(elements, el)
	}
	if len(elements) == 0 {
		return nil, fmt.Errorf("invalid structured data")
	}
	return elements, nil
}

// parseElement 解析一个元素 “[id key="value" ...]”。
func (p *parser) parseElement() (Element, error) {
	p.pos++ // 消费 '['
	id, err := p.parseName()
	if err != nil {
		return Element{}, err
	}
	el := Element{ID: id}
	for p.pos < len(p.buf) && p.buf[p.pos] == ' ' {
		p.pos++
		param, err := p.parseParam()
		if err != nil {
			return Element{}, err
		}
		el.Params = append(el.Params, param)
	}
	if p.pos >= len(p.buf) {
		return Element{}, fmt.Errorf("unterminated SD element %q", el.ID)
	}
	if p.buf[p.pos] != ']' {
		return Element{}, fmt.Errorf("unexpected byte 0x%02x in SD element %q", p.buf[p.pos], el.ID)
	}
	p.pos++ // 消费 ']'
	return el, nil
}

// parseParam 解析一个参数 key="value"。
func (p *parser) parseParam() (Param, error) {
	name, err := p.parseName()
	if err != nil {
		return Param{}, err
	}
	if p.pos >= len(p.buf) || p.buf[p.pos] != '=' {
		return Param{}, fmt.Errorf("expected '=' after param name %q", name)
	}
	p.pos++
	if p.pos >= len(p.buf) || p.buf[p.pos] != '"' {
		return Param{}, fmt.Errorf("expected '\"' after '=' for param %q", name)
	}
	p.pos++
	value, err := p.parseValue()
	if err != nil {
		return Param{}, err
	}
	return Param{Name: name, Value: value}, nil
}

// parseValue 解析带引号的参数值，完成转义还原并校验 UTF-8。
func (p *parser) parseValue() (string, error) {
	var out []byte
	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		switch c {
		case '"':
			p.pos++
			if !utf8.Valid(out) {
				return "", fmt.Errorf("param value is not valid UTF-8")
			}
			return string(out), nil
		case ']':
			return "", fmt.Errorf("bare ']' in param value must be escaped")
		case '\\':
			p.pos++
			if p.pos >= len(p.buf) {
				return "", fmt.Errorf("unterminated escape at end of param value")
			}
			next := p.buf[p.pos]
			switch next {
			case '"', '\\', ']':
				out = append(out, next)
			default:
				// 未知转义：两个字符都按原样保留。
				out = append(out, '\\', next)
			}
			p.pos++
		default:
			out = append(out, c)
			p.pos++
		}
	}
	return "", fmt.Errorf("unterminated quoted param value")
}

// parseName 解析 id 或参数名：1 至 32 字节可打印 ASCII，
// 不含空格、等号、右方括号或双引号。
func (p *parser) parseName() (string, error) {
	start := p.pos
	for p.pos < len(p.buf) && isNameByte(p.buf[p.pos]) {
		p.pos++
	}
	n := p.pos - start
	if n == 0 {
		return "", fmt.Errorf("expected SD identifier or param name")
	}
	if n > 32 {
		return "", fmt.Errorf("SD identifier or param name exceeds 32 bytes")
	}
	return string(p.buf[start:p.pos]), nil
}

// isNameByte 报告字节是否为合法的名称字符。
func isNameByte(c byte) bool {
	if c < 0x21 || c > 0x7E {
		return false
	}
	switch c {
	case '=', ']', '"':
		return false
	}
	return true
}

// hasBOM 报告数据是否以 UTF-8 BOM 开头。
func hasBOM(b []byte) bool {
	return len(b) >= 3 && b[0] == bom[0] && b[1] == bom[1] && b[2] == bom[2]
}

// indexByteFrom 从 from 开始查找字节 c，未找到返回 -1。
func indexByteFrom(b []byte, c byte, from int) int {
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}
