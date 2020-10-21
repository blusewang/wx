// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mp_api

type GuideAccountAddData struct {
	GuideAccount    string `json:"guide_account,omitempty"`
	GuideOpenId     string `json:"guide_openid,omitempty"`
	GuideHeadImgUrl string `json:"guide_headimgurl,omitempty"`
	GuideNickname   string `json:"guide_nickname,omitempty"`
}

type GuideBuyer struct {
	OpenId        string `json:"openid,omitempty"`
	BuyerNickname string `json:"buyer_nickname,omitempty"`
}

type GuideAddBuyerData struct {
	GuideAccount string `json:"guide_account,omitempty"`
	GuideOpenid  string `json:"guide_openid,omitempty"`
	GuideBuyer
	BuyerList []GuideBuyer `json:"buyer_list,omitempty"`
}
