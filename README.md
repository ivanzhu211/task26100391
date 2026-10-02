# syslogevidence

离线 Syslog（RFC5424 子集）证据解码库，供日志导入程序直接以 Go 包形式调用。
输入、解码结果与临时状态全部只在内存中，结果的持久化由调用方决定。

## 功能

- 连续长度计数帧解码：`<十进制字节长度><空格><消息体>`，分片可在任意字节处断开，
  一个分片也可含多个完整帧；消息体内的换行不构成帧边界。
- RFC5424 头部提取：`<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID`，原值保留，不解释时间。
- 结构化数据（SD）：`-` 或一个以上 `[id key="value"]` 元素；id 不可重复，
  同一元素内参数名可重复，顺序与重复项均保留，名称区分大小写。
- 参数值：必须合法 UTF-8；`\"`、`\\`、`\]` 完成转义还原；反斜杠后接其他字符时
  两个字符原样保留；未闭合引号/元素、裸露 `]`、非法 UTF-8 均判为无效消息体。
- MSG 逐字节保留（含空格、零字节、换行）；仅以 `EF BB BF`（UTF-8 BOM）开头时
  要求其余内容为合法 UTF-8，BOM 本身保留；区分"省略 MSG"与"MSG 为空"。
- 单条坏消息体只产生一条错误结果，不影响后续帧；输入结束时有未完成帧则产生
  一条终止错误，此前结果仍然有效；正常结束于帧边界不报错。
- 解码结果与分片方式无关。

## API

```go
d := syslogevidence.NewDecoder(func(r syslogevidence.Result) {
    // 每条完整帧回调一次：r.Message 与 r.Err 恰有一个非空
})
d.Write(chunk) // 可多次调用，chunk 为任意分片
d.Close()      // 通知输入结束
```

`ParseMessage(body []byte)` 也可单独用于解析一个完整消息体。

## 运行测试

```sh
go test ./...
```

（沙箱环境中如默认构建缓存不可写，可指定 `GOCACHE=/private/tmp/gocache go test ./...`。）

## 文件

- `message.go` — RFC5424 消息体解析（头部、SD、MSG）
- `decoder.go` — 长度计数帧的流式分帧与逐条交付
- `message_test.go` / `decoder_test.go` / `example_test.go` — 自动化测试与调用示例
