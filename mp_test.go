package wxApi

import (
	"github.com/blusewang/wxApi-go/mp_api"
	"github.com/youkale/go-querystruct/params"
	"log"
	"net/http"
	"net/url"
	"testing"
)

func TestLimitString(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	var a = MpAccount{
		AppId:          "wx20a7b1888ed3de1b",
		AccessToken:    "38_XtyPcVUODHd8q3TNYPVGAZ2WNRx_nW4gnclObbv78tsEa1Y_bwdkLALDMEb4372wYqcC_CanjU9O0Zw4MqHiqxrIukk_G4ElAUxyv_ASOb0V2y8647cbxbYU-G8CbtnPdLNub8NrqtUVrSTnWAPaAGALPE",
		AppSecret:      "ceea4169a257e0dcca5eb9486aa3e2d9",
		PrivateToken:   "cashier",
		EncodingAESKey: "5Vbl6BYbV5glfq4QmOpzkkaLYjH4xLaaxNmpkxsYPI3",
		JsSdkTicket:    "HoagFKDcsGMVCIY2vOjf9s0GXJnei4VNEyMRGfnxFUVx0yG1pAUA8B1hsRllP4kp8v2wAIbXzQPiwlmmkJp1xg",
		ServerHost:     mp_api.ServerHostShangHai,
	}

	var list mp_api.MessageCustomServiceKfListRes
	if err := a.NewMpReq(mp_api.MessageCustomServiceKfList).Bind(&list).Do(); err != nil {
		t.Error(err)
	}
	log.Println(list)

	resp, err := http.Get("https://b.s.mywsy.cn/logo.512.png")
	if err != nil {
		t.Error(err)
	}

	err = a.NewMpReq(mp_api.MessageCustomServiceKfAccountUploadHeadImg).Query(mp_api.MessageCustomServiceKfAccountUploadHeadImgQuery{
		KfAccount: "1@1",
	}).Upload(resp.Body, "png")
	if err != nil {
		t.Error(err)
	}
}
func TestMp(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	var mp = Mp{
		AppId:       "wx20a7b1888ed3de1b",
		AccessToken: "38_XtyPcVUODHd8q3TNYPVGAZ2WNRx_nW4gnclObbv78tsEa1Y_bwdkLALDMEb4372wYqcC_CanjU9O0Zw4MqHiqxrIukk_G4ElAUxyv_ASOb0V2y8647cbxbYU-G8CbtnPdLNub8NrqtUVrSTnWAPaAGALPE",
	}
	resp, err := http.Get("https://b.s.mywsy.cn/logo.512.png")
	if err != nil {
		t.Error(err)
	}
	err = mp.KfUploadHeadImg(resp.Body, "1@1")
	if err != nil {
		t.Error(err)
	}
	log.Println(err)
}

func TestMpAccount_NewMpReq(t *testing.T) {
	var s mp_api.MessageQuery
	var v = url.Values{
		"signature": []string{"G0gkxwXEutoJOd6zXGHXPHd7M56SgWEQcjxnuRWuEud98Mh0iaeibcMWG4SaVF0OPYbh0G0qdYlALGbmrp5G36fw"},
		"timestamp": []string{"234234234"},
	}
	log.Println(params.Unmarshal(v, &s))
	log.Println(s)
}

func TestMp_Upload(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	var a = MpAccount{
		AppId:          "wx20a7b1888ed3de1b",
		AccessToken:    "38_DXXrtUF80DxFW9ngM49GZypgVQ632G1GDEsK641bMMSafF0dXx9WLipivcAMHCkP7WwmIHmPum4RqXlN4ueDr49Q-OuDE2pUpV8tdGs6st-U50aUjRCI9X0bM-ErCRGruevqaXX8-SIDwlEkKUGdACAWGS",
		AppSecret:      "ceea4169a257e0dcca5eb9486aa3e2d9",
		PrivateToken:   "cashier",
		EncodingAESKey: "5Vbl6BYbV5glfq4QmOpzkkaLYjH4xLaaxNmpkxsYPI3",
		JsSdkTicket:    "HoagFKDcsGMVCIY2vOjf9s0GXJnei4VNEyMRGfnxFUVx0yG1pAUA8B1hsRllP4kp8v2wAIbXzQPiwlmmkJp1xg",
		ServerHost:     mp_api.ServerHostShangHai,
	}

	resp, err := http.Get("https://b.s.mywsy.cn/logo.512.png")
	if err != nil {
		t.Error(err)
	}

	var rs mp_api.MediaUploadRes
	err = a.NewMpReq(mp_api.MediaUpload).Query(mp_api.MediaUploadQuery{Type: mp_api.MediaTypeImage}).Bind(&rs).Upload(resp.Body, "png")
	if err != nil {
		t.Error(err)
	}
	log.Println(rs)
}
