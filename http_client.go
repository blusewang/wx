// Copyright 2021 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"bytes"
	"io/ioutil"
	"net/http"
)

var _cli *http.Client
var _hook func(req *http.Request, reqBody []byte, res *http.Response, err error)

type mt struct {
	t http.Transport
}

func (m *mt) RoundTrip(req *http.Request) (res *http.Response, err error) {
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewReader(reqBody))
	}
	res, err = m.t.RoundTrip(req)
	if _hook != nil {
		_hook(req, reqBody, res, err)
	}
	return
}

func client() *http.Client {
	if _cli == nil {
		_cli = &http.Client{Transport: &mt{http.Transport{}}}
	}
	return _cli
}

func RegisterHook(hook func(req *http.Request, reqBody []byte, res *http.Response, err error)) {
	_hook = hook
}
