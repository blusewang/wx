// Copyright 2021 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"
)

var _hook func(req *http.Request, ctx context.Context, reqBody []byte, res *http.Response, startAt time.Time, stopAt time.Time, err error)

type mt struct {
	t   http.Transport
	ctx context.Context
}

func (m *mt) RoundTrip(req *http.Request) (res *http.Response, err error) {
	t := time.Now()
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	res, err = m.t.RoundTrip(req)
	if _hook != nil {
		_hook(req, m.ctx, reqBody, res, t, time.Now(), err)
	}
	return
}

var c *http.Client

func client(ctx context.Context) *http.Client {
	if c == nil {
		c = &http.Client{Transport: &mt{ctx: ctx}}
	} else {
		c.Transport = &mt{ctx: ctx}
	}
	return c
}

func RegisterHook(hook func(req *http.Request, ctx context.Context, reqBody []byte, res *http.Response, startAt time.Time, stopAt time.Time, err error)) {
	_hook = hook
}
