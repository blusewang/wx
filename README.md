# wechat

wechat weixin sdk，支持微信应用和商户。

## 设计目标
在概念清晰的基础上追求更少的编码、更开放、灵活的结构。

本库不是在微信官方API基础上进一步封装，造出一个新的框架级的重体量SDK。而是努力成为微信官方文档的Golang版快速工具箱。

努力让开发者在学习微信官方文档后，不再有新的学习曲线（另学一套）！

所以本库目标是：极致、简单！不创另行发明新理念、不另行创造新架构！

## 概述
根据微信的文档，微信的业务有两个不同的领域：
- 应用类账号下的Api
- 商户类账号下的Api

## 安装
	go get github.com/blusewang/wechat

# 应用账号API
`订阅号`、`服务号`、`小程序`、`App`
- [x] 支持连接不同的地区的微信服务器
- [x] 支持一行代码从被动消息的 http.Request 中安全取出消息成`MessageData`。内部实现了识别并解密消息、校验请求的`Query`数据。
- [x] 支持自动填充`Query`中的`access_token`数据。
- [x] 链式调用，让不同需求的业务能一气和成！

## 时效性凭证安置方式约定
`access_token`、`js_sdk_ticket` 这类需要每7200秒刷新一次的，放到`crontab`中。

对此不满的，完全可以在使用本库的基础上，采用自己熟悉的方式、甚至自己设计方案来替代`crontab`。

## 核心设计
### 算法
一个基础账号对象`MpAccount`，它有三个行为：
- 为微信H5的网址签名 `UrlSign(url string)`
- 读取被动消息通知 `ReadMessage(req *http.Request)`
- 主动发出请求 `NewMpReq(path mp_api.MpApi) *mpReq`

### 数据结构
- 常量：[constant.go](https://github.com/blusewang/wechat/blob/master/mp_api/constant.go)
- 基础信息：[basic_information.go](https://github.com/blusewang/wechat/blob/master/mp_api/basic_information.go)
- 自定义菜单：[custom_menus.go](https://github.com/blusewang/wechat/blob/master/mp_api/custom_menus.go)
- 消息：[message.go](https://github.com/blusewang/wechat/blob/master/mp_api/message.go)
- 媒体文件上传：[media.go](https://github.com/blusewang/wechat/blob/master/mp_api/media.go)
- 微信网页开发：[oa_web_apps.go](https://github.com/blusewang/wechat/blob/master/mp_api/oa_web_apps.go)
- 用户管理：[user.go](https://github.com/blusewang/wechat/blob/master/mp_api/user.go)
- 账号管理：[account.go](https://github.com/blusewang/wechat/blob/master/mp_api/account.go)
- 对话能力：[guide.go](https://github.com/blusewang/wechat/blob/master/mp_api/guide.go)
- 小程序：[mini_program.go](https://github.com/blusewang/wechat/blob/master/mp_api/mini_program.go)

只实现了很有限的数据。若需要使用本库自带的数据结构之外的API。完全可以参考本库的数据结构写法，自行另起书写(注意不同业务的tag名称不同)。
并能得到一样的兼容体验！

## 举例
```go
	a := MpAccount{
		AppId:       "your_app_id",
		AccessToken: "38_XtyPcVUODHd8q3TNYPVGAZ2WNRx_nW4gnclObbv78tsEa1Y_bwdkLALDMEb4372wYqcC_CanjU9O0Zw4MqHiqxrIukk_G4ElAUxyv_ASOb0V2y8647cbxbYU-G8CbtnPdLNub8NrqtUVrSTnWAPaAGALPE",
        // ...
		ServerHost:  mp_api.ServerHostShangHai, // 选择离自己最近的服务主机
	}

    // 一个简单的只带access_token的GET API
	var list mp_api.MessageCustomServiceKfListRes
	if err := a.NewMpReq(mp_api.MessageCustomServiceKfList).Bind(&list).Do(); err != nil {
		t.Error(err)
	}
	log.Println(list)

    // 一个POST API
	var rs mp_api.AccountShortUrlRes
	err = a.NewMpReq(mp_api.AccountShortUrl).SendData(mp_api.AccountShortUrlData{
		Action:  mp_api.ShortUrlAction,
		LongUrl: "https://developers.weixin.qq.com/doc/offiaccount/Account_Management/URL_Shortener.html",
	}).Bind(&rs).Do()
	if err != nil {
		t.Error(err)
	}
	log.Println(rs)

    // 一个上传媒体文件的API
	err = a.NewMpReq(mp_api.MessageCustomServiceKfAccountUploadHeadImg).Query(mp_api.MessageCustomServiceKfAccountUploadHeadImgQuery{
		KfAccount: "1@1",
	}).Upload(resp.Body, "png")
	if err != nil {
		t.Error(err)
	}
```

# 商户账号API（V2版）
`App、JSAPI、小程序下单` `分账` `付款至微信零钱` `付款至个人银行卡` `发红包`
- [x] 自动填充基础信息
- [x] 自动签名
- [x] 私有证书HTTP客户端自动缓存
- [x] 支持`MD5`、`HMAC-SHA256`加密
- [x] 支持付款至银行卡时，隐私信息加密

## 核心设计
### 算法
一个基础账号对象`MchAccount`，它有以下行为：
- 创建请求 `NewMchReq(url string)`
- 将订单签名给App `OrderSign4App(or mch_api.PayUnifiedOrderRes)`
- 将订单签名给于H5、小程序 `OrderSign(or mch_api.PayUnifiedOrderRes)`
- 验证支付成功通知 `PayNotify(pn mch_api.PayNotify)`
- 付款至银行卡时，隐私信息项加密 `RsaEncrypt(plain string)`

### 数据结构
- 常量：[constant.go](https://github.com/blusewang/wechat/blob/master/mch_api/constant.go)
- 数据结构：[structs.go](https://github.com/blusewang/wechat/blob/master/mch_api/structs.go)

只实现了很有限的数据。若需要使用本库自带的数据结构之外的API。完全可以参考本库的数据结构写法，自行另起书写(建议参考structs.go中的方式书写)。
能得到一样的兼容体验！

## 举例
```go
    mch := MchAccount{}
    
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

	err := mch.NewMchReq(mch_api.PayProfitSharing).
		Send(&body). // 注意：发送的数据需传指针，以便自动填充基础信息和签名
		UseHMacSign(). // 指定使用HMAC-SHA256
		UsePrivateCert(). // 指定使用私有证书通信
		Bind(&data).Do() // 传指针
	log.Println(err)
	log.Println(data)
```

# 为微信业务数据提供的额外工具方法 
- `NewRandStr` 生成符合微信要求随机字符
- `LimitString` 限制长度，并将微信不支持的字符替换成'x'，能满足公众号App的字符要求
- `SafeString` 安全地限制长度，并将微信不支持的字符替换成'x'，能满足商户平台的字符要求
