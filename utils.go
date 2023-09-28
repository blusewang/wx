package wx

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
)

type H map[string]interface{}

const letterBytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// SafeString 安全地限制长度，并将微信不支持的字符替换成'x'，能满足商户平台的字符要求
func SafeString(str string, length int) string {
	if length <= 3 {
		return ""
	}
	runs := []rune(str)
	// 单字符长度高于3的，不是一般的utf8字符，剔除掉
	for k, v := range runs {
		switch len([]byte(string(v))) {
		case 1:
			// 全部放行
		case 3:
			if v < 19968 || v > 40869 {
				// 只支持中文
				runs[k] = 'x'
			}
		default:
			runs[k] = 'x'
		}
	}
	str = string(runs)
	if len(str) > length {
		var r2 []rune
		for k := range runs {

			if len(string(runs[:k])) <= length-3 {
				r2 = runs[:k]
			}
		}
		r2 = append(r2, '…')
		str = string(r2)
	}
	return str
}

// LimitString 限制长度，并将微信不支持的字符替换成'x'，能满足公众号App的字符要求
func LimitString(str string, length int) string {
	runs := []rune(str)
	// 单字符长度高于3的，不是一般的utf8字符，剔除掉
	for k, v := range runs {
		switch len([]byte(string(v))) {
		case 1:
			// 全部放行
		case 3:
			// 全部放行
		default:
			runs[k] = 'x'
		}
	}
	str = string(runs)
	if len(runs) > length {
		var r2 = runs[:length-1]
		r2 = append(r2, '…')
		str = string(r2)
	}
	return str
}

// NewRandStr 生成符合微信要求随机字符
func NewRandStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

func obj2map(obj interface{}) (p map[string]interface{}) {
	vs := reflect.ValueOf(obj)
	if vs.Kind() == reflect.Ptr {
		vs = vs.Elem()
	}
	p = make(map[string]interface{})
	obj2mapOnce(vs, &p)
	return
}

func obj2mapOnce(vs reflect.Value, data *map[string]interface{}) {
	for i := 0; i < vs.NumField(); i++ {
		if vs.Type().Field(i).Anonymous {
			obj2mapOnce(vs.Field(i), data)
		} else {
			k := vs.Type().Field(i).Tag.Get("json")
			if k == "" {
				k = vs.Type().Field(i).Tag.Get("xml")
				if k == "xml" {
					continue
				}
			}
			if k == "sign" || k == "-" {
				continue
			}
			k = strings.Split(k, ",")[0]
			// 跳过空值
			if reflect.Zero(vs.Field(i).Type()).Interface() == vs.Field(i).Interface() {
				continue
			}
			(*data)[k] = vs.Field(i).Interface()
		}
	}
}

func mapSortByKey(data map[string]interface{}) string {
	var keys []string
	nData := ""
	for k := range data {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	for _, k := range keys {
		nData = fmt.Sprintf("%v&%v=%v", nData, k, data[k])
	}
	return nData[1:]
}
