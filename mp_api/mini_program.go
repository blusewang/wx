// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mp_api

type SnsJsCode2SessionQuery struct {
	AppId     string `url:"appid"`
	Secret    string `url:"secret"`
	JsCode    string `url:"js_code"`
	GrantType string `url:"grant_type"`
}

type SnsJsCode2SessionRes struct {
	MpBaseResp
	OpenId     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionId    string `json:"unionid"`
}

type WXACodeReqColor struct {
	R int64 `json:"r"`
	G int64 `json:"g"`
	B int64 `json:"b"`
}

type WXACodeReq struct {
	Path      string           `json:"path"`
	Width     int64            `json:"width,omitempty"`
	AutoColor bool             `json:"auto_color,omitempty"`
	LineColor *WXACodeReqColor `json:"line_color,omitempty"`
	IsHyaline bool             `json:"is_hyaline"`
}

type WXACodeUnLimitReq struct {
	Scene      string           `json:"scene"`
	Page       string           `json:"page,omitempty"`
	CheckPath  bool             `json:"check_path"`
	EnvVersion string           `json:"env_version,omitempty"`
	Width      int64            `json:"width,omitempty"`
	AutoColor  bool             `json:"auto_color,omitempty"`
	LineColor  *WXACodeReqColor `json:"line_color,omitempty"`
	IsHyaline  bool             `json:"is_hyaline,omitempty"`
}
