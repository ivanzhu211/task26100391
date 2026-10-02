# syslogevidence

离线 Syslog（RFC5424 子集）证据解码库，供日志导入程序直接以包形式调用，无接口层、无网络、无外部服务。输入、解码结果与临时状态全部只在内存中，由调用方决定如何持久化。

## 功能

- 解析连续的长度计数帧：`十进制长度 + ASCII空格 + 恰好该长度的消息体`，长度按字节计。
- 分片可在任意字节处断开、可含多个完整帧；解码结果与分片方式无关。
- 消息体为 RFC5424 子集：`<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD[ MSG]`，头部字段保留原值，不做时间解释。
- 结构化数据支持 `-` 或连续拼接的 `[id key="value"]` 元素；id 不可重复，参数名可重复，顺序与重复项均保留，名称区分大小写。
- 参数值转义还原：`\"` `→`"`、`\\`→`\`、`\]`→`]`；反斜杠后接其他字符时两字符原样保留。值必须是合法 UTF-8。
- MSG 逐字节保留（含空格、零字节、换行）；仅以 `EF BB BF` 开头时要求其余内容为合法 UTF-8，BOM 本身保留。`HasMsg` 区分“省略 MSG”与“MSG 为空”。
- 完整帧内消息体无效时只输出该帧的一条 `ErrBadMessage`，不影响后续帧；输入结束时仍有未完成帧则输出 `ErrTruncated`；正常结束于帧边界不报错。

## 使用

```go
d := syslog.NewDecoder()
for _, chunk := range chunks {      // 任意方式切分的分片
    for _, r := range d.Write(chunk) {
        handle(r)                   // r.Message 或 r.Error 恰有一个非空
    }
}
for _, r := range d.Close() {       // 通知输入结束
    handle(r)                       // 可能产生一条 ErrTruncated
}
```

结果类型见 `types.go`：`Result{Message *Message, Error *Error}`；
错误类别：`ErrBadMessage`（帧内消息体无效）、`ErrTruncated`（输入结束时帧未完成）、`ErrBadFrame`（长度前缀损坏，无法重新同步）。

## 运行测试

```sh
go test ./...        # 全部测试
go test ./... -v     # 查看各场景明细
go vet ./...         # 静态检查
```

测试覆盖：多字节字符、BOM 与转义序列跨分片（逐字节及每个切分点两段切分均与整体喂入结果一致）、重复参数与未知转义的明确期望值、坏消息体夹在两条合法消息之间仅报一条错误且后条完整可读、截断终止、空 MSG 与省略 MSG 的区分等。

## 环境要求

仅需 Go 1.21+，无第三方依赖，不监听端口，不使用数据库/缓存/消息队列。
