// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"bytes"
	"github.com/blusewang/wx/mch_api"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"testing"
)

func TestMchAccount_NewMchReq(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	SetClientMiddleware(func(req *http.Request, reqBody []byte, res *http.Response, err error) {
		log.Println(req, res, err)
		raw, _ := ioutil.ReadAll(res.Body)
		log.Println(string(raw))
		res.Body = ioutil.NopCloser(bytes.NewReader(raw))
	})
	mch := MchAccount{
		MchId:           "",
		MchKey:          "",
		MchSSLCert:      []byte(""),
		MchSSLKey:       []byte(""),
		MchRSAPublicKey: []byte(""),
	}
	var data mch_api.PayProfitSharingRes
	var body = mch_api.PayProfitSharingData{
		TransactionId: "4200000531202004307536721907",
		OutOrderNo:    "TSF_216144_1065_ye7DvHdSed",
	}
	_ = body.SerReceivers([]mch_api.PayProfitSharingReceiver{
		{
			Type:        "",
			Account:     "",
			Amount:      10,
			Description: "",
		},
	})
	err := mch.NewMchReqWithApp(mch_api.PayProfitSharing, "wxbb4d55eb95f282f4").
		Send(&body).
		UseHMacSign().
		UsePrivateCert().
		Bind(&data).Do()
	log.Println(err)
	log.Println(data)
}

func TestMchAccount_OrderSign(t *testing.T) {
	//var mch MchAccount
	var data interface{} = &mch_api.PayUnifiedOrderRes{
		MchBaseResponse: mch_api.MchBaseResponse{
			ReturnCode: "ReturnCode",
			ReturnMsg:  "ReturnMsg",
		},
		MchBase: mch_api.MchBase{
			MchId: "MchId",
			AppId: "AppId",
		},
		PrepayId: "24wer",
	}
	vs := reflect.ValueOf(data).Elem()
	log.Println(vs.Field(0))
	vs.FieldByName("MchBase").FieldByName("MchId").Set(reflect.ValueOf("asdf"))
	log.Println(vs.FieldByName("MchBase").FieldByName("MchId"))
}
