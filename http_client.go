// Copyright 2021 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"net/http"
)

var _cli *http.Client
var _middleware func(req *http.Request, res *http.Response, err error)

type mt struct {
	t http.Transport
}

func (m *mt) RoundTrip(req *http.Request) (res *http.Response, err error) {
	res, err = m.t.RoundTrip(req)
	if _middleware != nil {
		_middleware(req, res, err)
	}
	return
}

func client() *http.Client {
	if _cli == nil {
		_cli = &http.Client{Transport: &mt{http.Transport{}}}
	}
	return _cli
}

func SetClientMiddleware(middleware func(req *http.Request, res *http.Response, err error)) {
	_middleware = middleware
}
