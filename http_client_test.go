// Copyright 2021 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"bytes"
	"encoding/json"
	"github.com/blusewang/wx/mch_api"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"
)

func TestMt_RoundTrip(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	RegisterHook(func(req *http.Request, reqBody []byte, res *http.Response, startAt time.Time, stopAt time.Time, err error) {
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

	var mch = MchAccount{
		MchId:    "",
		MchKeyV2: "",
		MchKeyV3: "",
	}
	mch.NewMchReq(mch_api.PayOrderQuery)
}

func TestRegisterHook(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Println(client().Get("https://httpbin.org/delay/6"))
}
