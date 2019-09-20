package wxApi

import (
	"log"
	"testing"
	"unicode/utf8"
)

func TestSafeString(t *testing.T) {
	str := "来自[君君-Jμиe ®🎀]的推荐奖励"
	for k, v := range []rune(str) {
		log.Println(k, string(v), utf8.ValidRune(v), len([]byte(string(v))))
	}
	log.Println(SafeString(str, 32))
}
