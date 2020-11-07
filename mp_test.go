package wx

import (
	"github.com/blusewang/wx/mp_api"
	"github.com/youkale/go-querystruct/params"
	"log"
	"net/url"
	"testing"
)

func TestLimitString(t *testing.T) {
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

func TestMp_ShortUrl(t *testing.T) {
	log.SetFlags(log.Ltime | log.Lshortfile)
	var a = MpAccount{
		AppId:       "wx20a7b1888ed3de1b",
		AccessToken: "38_DXXrtUF80DxFW9ngM49GZypgVQ632G1GDEsK641bMMSafF0dXx9WLipivcAMHCkP7WwmIHmPum4RqXlN4ueDr49Q-OuDE2pUpV8tdGs6st-U50aUjRCI9X0bM-ErCRGruevqaXX8-SIDwlEkKUGdACAWGS",
		ServerHost:  mp_api.ServerHostShangHai,
	}

	var rs mp_api.AccountShortUrlRes
	err := a.NewMpReq(mp_api.AccountShortUrl).SendData(&mp_api.AccountShortUrlData{
		Action:  mp_api.ShortUrlAction,
		LongUrl: "https://developers.weixin.qq.com/doc/offiaccount/Account_Management/URL_Shortener.html",
	}).Bind(&rs).Do()
	if err != nil {
		t.Error(err)
	}
	log.Println(rs)
}
