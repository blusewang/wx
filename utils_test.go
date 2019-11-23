package wxApi

import (
	"log"
	"testing"
	"unicode/utf8"
)

func TestSafeString(t *testing.T) {
	str := "均】A 爱尚美  亮哥(^ω^)人心的丑陋＾⒈个乆旳天荒地老🚖👮🏾绝对没问题👌🏼唯τā命゛L金剪子￿LK花🌺侑你僦好💝无忧🌹V沙龙杨斌 AA·Enya-ZZJG"
	for k, v := range []rune(str) {
		log.Println(k, string(v), utf8.ValidRune(v), len([]byte(string(v))), v)
	}
	log.Println(SafeString(str, 320))
}
