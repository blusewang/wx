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
	"time"
)

var _hook func(req *http.Request, reqBody []byte, res *http.Response, startAt time.Time, stopAt time.Time, err error)

type mt struct {
	t http.Transport
}

func (m *mt) RoundTrip(req *http.Request) (res *http.Response, err error) {
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewReader(reqBody))
	}
	t := time.Now()
	res, err = m.t.RoundTrip(req)
	if _hook != nil {
		_hook(req, reqBody, res, t, time.Now(), err)
	}
	return
}

var c *http.Client

func client() *http.Client {
	if c == nil {
		c = &http.Client{Transport: &mt{}}
	}
	return c
}

func RegisterHook(hook func(req *http.Request, reqBody []byte, res *http.Response, startAt time.Time, stopAt time.Time, err error)) {
	_hook = hook
}
