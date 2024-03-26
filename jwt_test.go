package zjwt

import (
	"testing"
	"time"
)

const secret = "your_secret"
const rawData = "data"

func TestJwt(t *testing.T) {
	token, err := MakeToken(rawData, secret)
	if err != nil {
		t.Error("MakeToken err:", err)
	}
	t.Logf("token = %s", token)

	var result string
	err = ParserAndValid(token, secret, &result)
	if err != nil {
		t.Error("MakeToken err:", err)
	}
	t.Logf("result = %s", result)

	if result != rawData {
		t.Errorf("result: %s not match rawData: %s", result, rawData)
	}
}

func TestJwtNbf(t *testing.T) {
	j := New()
	j.SetAfter(time.Hour)
	token, err := j.MakeToken(rawData, secret)
	if err != nil {
		t.Error("MakeToken err:", err)
	}
	t.Logf("token = %s", token)

	j2 := New()
	var result string
	err = j2.Parser(token, secret, &result)
	if err != nil {
		t.Error("MakeToken err:", err)
	}
	t.Logf("result = %s", result)

	if result != rawData {
		t.Errorf("result: %s not match rawData: %s", result, rawData)
	}

	err = j2.Valid()
	if err == nil {
		t.Error("Valid no err. fail")
	}
}
