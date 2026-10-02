package syslog

import "fmt"

// maxFrameLen 是单帧消息体的最大字节数，用于防御损坏的长度前缀
// 导致的无界内存增长。
const maxFrameLen = 64 << 20

// decodeState 是帧解码状态机的状态。
type decodeState int

const (
	stateLength decodeState = iota // 正在读取十进制长度
	stateBody                      // 正在读取消息体
	stateFailed                    // 帧头损坏，无法重新同步
)

// Decoder 是流式帧解码器，通过 Write 持续接收分片，
// 通过 Close 通知输入结束。结果随每次调用逐条返回。
// 解码结果与分片方式无关。
type Decoder struct {
	state   decodeState
	length  int  // 当前帧声明的长度
	gotLen  bool // 是否已读到至少一个长度数字
	body    []byte
	results []Result
}

// NewDecoder 创建一个新的解码器。
func NewDecoder() *Decoder {
	return &Decoder{state: stateLength}
}

// Write 接收一个分片（可在任意字节处断开，可含多个完整帧），
// 返回本次调用产生的全部结果。
func (d *Decoder) Write(p []byte) []Result {
	d.results = d.results[:0]
	for i := 0; i < len(p); {
		switch d.state {
		case stateFailed:
			// 帧头损坏后无法可靠定位后续帧边界，丢弃剩余输入。
			return d.drain()
		case stateLength:
			i = d.consumeLength(p, i)
		case stateBody:
			i = d.consumeBody(p, i)
		}
	}
	return d.drain()
}

// Close 通知输入结束。若仍有未完成帧，返回一条 ErrTruncated 结果；
// 正常结束于帧边界则不产生结果。
func (d *Decoder) Close() []Result {
	d.results = d.results[:0]
	switch d.state {
	case stateLength:
		if d.gotLen {
			d.results = append(d.results, Result{Error: &Error{
				Kind: ErrTruncated,
				Err:  fmt.Sprintf("input ended after frame length %d, before body", d.length),
			}})
		}
	case stateBody:
		d.results = append(d.results, Result{Error: &Error{
			Kind: ErrTruncated,
			Raw:  append([]byte(nil), d.body...),
			Err:  fmt.Sprintf("input ended mid-frame: got %d of %d body bytes", len(d.body), d.length),
		}})
	}
	d.state = stateFailed
	return d.drain()
}

// consumeLength 处理长度前缀字节，返回新的消费位置。
func (d *Decoder) consumeLength(p []byte, i int) int {
	c := p[i]
	switch {
	case c >= '0' && c <= '9':
		d.length = d.length*10 + int(c-'0')
		if d.length > maxFrameLen {
			d.failFrame(fmt.Sprintf("frame length exceeds %d bytes", maxFrameLen))
			return len(p)
		}
		d.gotLen = true
		return i + 1
	case c == ' ' && d.gotLen:
		d.state = stateBody
		d.body = d.body[:0]
		if d.length == 0 {
			d.finishBody()
		}
		return i + 1
	default:
		d.failFrame(fmt.Sprintf("invalid byte 0x%02x in frame length", c))
		return len(p)
	}
}

// consumeBody 处理消息体字节，返回新的消费位置。
func (d *Decoder) consumeBody(p []byte, i int) int {
	need := d.length - len(d.body)
	take := len(p) - i
	if take > need {
		take = need
	}
	d.body = append(d.body, p[i:i+take]...)
	if len(d.body) == d.length {
		d.finishBody()
	}
	return i + take
}

// finishBody 在收齐一个完整帧后解析消息体并复位状态。
func (d *Decoder) finishBody() {
	body := d.body
	d.body = nil
	d.state = stateLength
	d.length = 0
	d.gotLen = false
	msg, perr := parseMessage(body)
	if perr != nil {
		d.results = append(d.results, Result{Error: perr})
		return
	}
	d.results = append(d.results, Result{Message: msg})
}

// failFrame 记录帧头损坏错误并进入失败状态。
func (d *Decoder) failFrame(why string) {
	d.results = append(d.results, Result{Error: &Error{Kind: ErrBadFrame, Err: why}})
	d.state = stateFailed
}

// drain 返回本次调用累积的结果。
func (d *Decoder) drain() []Result {
	if len(d.results) == 0 {
		return nil
	}
	out := make([]Result, len(d.results))
	copy(out, d.results)
	return out
}
