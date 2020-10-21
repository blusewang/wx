// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mp_api

type AccountQrCreateData struct {
	ExpireSeconds int64        `json:"expire_seconds,omitempty"`
	ActionName    QrActionType `json:"action_name"`
	ActionInfo    struct {
		Scene struct {
			SceneId  int64  `json:"scene_id,omitempty"`
			SceneStr string `json:"scene_str,omitempty"`
		} `json:"scene"`
	} `json:"action_info"`
}

type AccountQrCreateRes struct {
	Ticket        string `json:"ticket"`
	ExpireSeconds int64  `json:"expire_seconds"`
	Url           string `json:"url"`
}

type AccountShortUrlData struct {
	Action  string `json:"action"`
	LongUrl string `json:"long_url"`
}

type AccountShortUrlRes struct {
	MpBaseResp
	ShortUrl string `json:"short_url"`
}
