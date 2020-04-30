// Copyright 2020 MQ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wxApi

import (
	"log"
	"testing"
)

func TestBankPayReq_String(t *testing.T) {
	var m Mch
	m.MchName = ""
	m.MchId = ""
	m.MchKey = ""
	rs, err := m.OrderQuery("", "H5_217903_1vEKQHqd0m")
	if err != nil {
		t.Fatal(err)
	}
	log.Println(m.PayNotify(rs))
	log.Println(rs.String())
}
