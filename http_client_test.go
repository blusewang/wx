// Copyright 2021 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
)

func TestMt_RoundTrip(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	RegisterHook(func(req *http.Request, reqBody []byte, res *http.Response, err error) {
		var data struct {
			Method  string `json:"method"`
			Url     string `json:"url"`
			Body    string `json:"body"`
			ResBody string `json:"res_body"`
		}
		data.Method = req.Method
		data.Url = req.URL.String()
		data.Body = string(reqBody)

		if res.Body != nil {
			raw, _ := ioutil.ReadAll(res.Body)
			data.ResBody = string(raw)
			res.Body = ioutil.NopCloser(bytes.NewReader(raw))
		}

		raw, err := json.Marshal(data)
		log.Println(string(raw), err)
	})

	var buf = new(bytes.Buffer)
	var coder = json.NewEncoder(buf)
	coder.SetEscapeHTML(false)
	if err := coder.Encode(map[string]string{"a": "b"}); err != nil {
		return
	}
	log.Println(client().Post("https://www.baidu.com", "text/json", buf))
}
