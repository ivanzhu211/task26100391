package syslogevidence_test

import (
	"fmt"

	"syslogevidence"
)

// Example shows how a log importer feeds arbitrary chunks and collects
// per-frame results. Storage of results is entirely up to the caller.
func Example() {
	var results []syslogevidence.Result
	d := syslogevidence.NewDecoder(func(r syslogevidence.Result) {
		results = append(results, r)
	})

	body := `<13>1 - host app 1 ID1 [meta tag="汉字"] ` + "\xEF\xBB\xBF你好"
	frame := fmt.Sprintf("%d %s", len([]byte(body)), body)

	// Chunks may split anywhere, even inside a multibyte character.
	d.Write([]byte(frame[:10]))
	d.Write([]byte(frame[10:25]))
	d.Write([]byte(frame[25:]))
	d.Close()

	for _, r := range results {
		if r.Err != nil {
			fmt.Println("error:", r.Err)
			continue
		}
		hasBOM := len(r.Message.Msg) >= 3 && string(r.Message.Msg[:3]) == "\xEF\xBB\xBF"
		fmt.Printf("pri=%s sd=%v bom=%v msg=%q\n",
			r.Message.Priority, r.Message.Elements[0].Params[0].Value,
			hasBOM, r.Message.Msg[3:])
	}
	// Output: pri=13 sd=汉字 bom=true msg="你好"
}
