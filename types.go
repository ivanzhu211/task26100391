// Package syslog 提供离线 Syslog(RFC5424 子集) 证据解码能力。
// 输入为长度计数帧的连续字节流，输出为逐条解码结果。
// 全部状态仅保存在内存中，由调用方决定如何持久化结果。
package syslog

// Header 是 RFC5424 消息头部，各字段保留原值，不做解释。
type Header struct {
	PRI       string
	Version   string
	Timestamp string
	Hostname  string
	AppName   string
	ProcID    string
	MsgID     string
}

// Param 是结构化数据中的一个参数，保持出现顺序与重复项。
type Param struct {
	Name  string
	Value string // 已完成转义还原
}

// Element 是一个结构化数据元素 [id key="value" ...]。
type Element struct {
	ID     string
	Params []Param
}

// Message 是一条成功解码的消息体。
type Message struct {
	Header   Header
	Elements []Element // SD 为 "-" 时为 nil
	HasMsg   bool      // 区分“省略 MSG”与“分隔空格存在但 MSG 为空”
	Msg      []byte    // 逐字节保留，含 BOM、零字节与换行
}

// ErrorKind 区分错误类别。
type ErrorKind int

const (
	// ErrBadMessage 表示一个完整帧内的消息体无效。
	ErrBadMessage ErrorKind = iota
	// ErrTruncated 表示输入结束时仍有未完成的帧。
	ErrTruncated
	// ErrBadFrame 表示帧头（长度前缀）本身损坏，无法继续同步。
	ErrBadFrame
)

// Error 是一条解码错误结果。
type Error struct {
	Kind ErrorKind
	Raw  []byte // 出错帧的原始消息体（截断错误时为已收到的部分），可能为 nil
	Err  string // 人类可读的原因
}

// Result 是逐条交付的解码结果：Message 与 Error 恰有一个非空。
type Result struct {
	Message *Message
	Error   *Error
}
