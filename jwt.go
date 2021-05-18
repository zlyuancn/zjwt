/*
-------------------------------------------------
   Author :       Zhang Fan
   date：         2020/1/20
   Description :
-------------------------------------------------
*/

package zjwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	DefaultAlgorithm = HS256
)

type Algorithm string

const (
	HS256 Algorithm = "HS256"
	HS384           = "HS384"
	HS512           = "HS512"
	ES256           = "ES256"
	ES384           = "ES384"
	ES512           = "ES512"
	PS256           = "PS256"
	PS384           = "PS384"
	PS512           = "PS512"
	RS256           = "RS256"
	RS384           = "RS384"
	RS512           = "RS512"
)

var algorithmMap = map[Algorithm]jwt.SigningMethod{
	HS256: jwt.SigningMethodHS256,
	HS384: jwt.SigningMethodHS384,
	HS512: jwt.SigningMethodHS512,
	ES256: jwt.SigningMethodES256,
	ES384: jwt.SigningMethodES384,
	ES512: jwt.SigningMethodES512,
	PS256: jwt.SigningMethodPS256,
	PS384: jwt.SigningMethodPS384,
	PS512: jwt.SigningMethodPS512,
	RS256: jwt.SigningMethodRS256,
	RS384: jwt.SigningMethodRS384,
	RS512: jwt.SigningMethodRS512,
}

type jwtData struct {
	jwt.StandardClaims
	Payload interface{} `json:"a"`
}

type JWT struct {
	data *jwtData
}

// 创建一个jwt
func New() *JWT {
	return &JWT{data: new(jwtData)}
}

// 设置令牌签发时间为当前时间
func (m *JWT) SetIssuedAt() *JWT {
	m.data.IssuedAt = time.Now().Unix()
	return m
}

// 设置令牌签发时间为指定时间
func (m *JWT) SetIssuedAtTime(t time.Time) *JWT {
	m.data.IssuedAt = t.Unix()
	return m
}

// 设置令牌一段时间后生效
func (m *JWT) SetAfter(t time.Duration) *JWT {
	m.data.NotBefore = time.Now().Add(t).Unix()
	return m
}

// 设置令牌指定生效时间
func (m *JWT) SetAfterTime(t time.Time) *JWT {
	m.data.NotBefore = t.Unix()
	return m
}

// 设置令牌一段时间后失效
func (m *JWT) SetExpires(t time.Duration) *JWT {
	m.data.ExpiresAt = time.Now().Add(t).Unix()
	return m
}

// 设置令牌指定失效时间
func (m *JWT) SetExpiresTime(t time.Time) *JWT {
	m.data.ExpiresAt = t.Unix()
	return m
}

// 根据秘钥将对象制作为token
func (m *JWT) MakeToken(payload interface{}, secret string, algorithm ...Algorithm) (string, error) {
	var alg jwt.SigningMethod
	if len(algorithm) > 0 {
		alg = algorithmMap[algorithm[0]]
	} else {
		alg = algorithmMap[DefaultAlgorithm]
	}

	if alg == nil {
		panic(fmt.Sprintf("没有 <%s> 这种算法", algorithm))
	}

	m.data.Payload = payload
	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "zjwt",
			"alg": alg.Alg(),
		},
		Claims: m.data,
		Method: alg,
	}
	return token.SignedString([]byte(secret))
}

func (m *JWT) parser(token, secret string, outPtr interface{}, validAlgorithms ...Algorithm) error {
	m.data.Payload = outPtr

	if len(validAlgorithms) == 0 {
		validAlgorithms = []Algorithm{DefaultAlgorithm}
	}
	algorithms := make([]string, len(validAlgorithms))
	for i, a := range validAlgorithms {
		algorithms[i] = string(a)
	}

	parser := &jwt.Parser{ValidMethods: algorithms, SkipClaimsValidation: true}
	_, err := parser.ParseWithClaims(token, m.data, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	return err
}

// 解析jwt数据
func (m *JWT) Parser(token, secret string, outPtr interface{}, validAlgorithms ...Algorithm) error {
	return m.parser(token, secret, outPtr, validAlgorithms...)
}

// 解析jwt数据并验证使用时间
func (m *JWT) ParserAndValid(token, secret string, outPtr interface{}, validAlgorithms ...Algorithm) error {
	err := m.parser(token, secret, outPtr, validAlgorithms...)
	if err != nil {
		return err
	}
	return m.Valid()
}

// 验证令牌的签发时间, 生效时间, 到期时间
func (m *JWT) Valid() error {
	return m.data.Valid()
}

// 注册自定义算法
func RegistryAlgorithm(algorithm jwt.SigningMethod) {
	name := Algorithm(algorithm.Alg())
	algorithmMap[name] = algorithm
}

// 根据秘钥将对象制作为token
func MakeToken(payload interface{}, secret string, algorithm ...Algorithm) (string, error) {
	return New().MakeToken(payload, secret, algorithm...)
}

// 解析并验证token
func ParserAndValid(token, secret string, outPtr interface{}, validAlgorithms ...Algorithm) error {
	return New().ParserAndValid(token, secret, outPtr, validAlgorithms...)
}
