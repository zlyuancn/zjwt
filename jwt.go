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

	"github.com/golang-jwt/jwt/v5"
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

type Claims struct {
	Exp     int64
	Nbf     int64
	Iat     int64
	Payload interface{}
}

func (m *Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	if m.Exp == 0 {
		return nil, nil
	}
	return &jwt.NumericDate{time.Unix(m.Exp, 0)}, nil
}
func (m *Claims) GetNotBefore() (*jwt.NumericDate, error) {
	if m.Nbf == 0 {
		return nil, nil
	}
	return &jwt.NumericDate{time.Unix(m.Nbf, 0)}, nil
}
func (m *Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	if m.Iat == 0 {
		return nil, nil
	}
	return &jwt.NumericDate{time.Unix(m.Iat, 0)}, nil
}

func (m *Claims) GetAudience() (jwt.ClaimStrings, error) { return []string{}, nil }
func (m *Claims) GetIssuer() (string, error)             { return "", nil }
func (m *Claims) GetSubject() (string, error)            { return "", nil }

type JWT struct {
	Claims *Claims
}

// 创建一个jwt
func New() *JWT {
	return &JWT{
		Claims: &Claims{},
	}
}

// 设置令牌签发时间为当前时间
func (m *JWT) SetIssuedAt() *JWT {
	m.Claims.Iat = time.Now().Unix()
	return m
}

// 设置令牌签发时间为指定时间
func (m *JWT) SetIssuedAtTime(t time.Time) *JWT {
	m.Claims.Iat = t.Unix()
	return m
}

// 设置令牌一段时间后生效
func (m *JWT) SetAfter(t time.Duration) *JWT {
	m.Claims.Nbf = time.Now().Add(t).Unix()
	return m
}

// 设置令牌指定生效时间
func (m *JWT) SetAfterTime(t time.Time) *JWT {
	m.Claims.Nbf = t.Unix()
	return m
}

// 设置令牌一段时间后失效
func (m *JWT) SetExpires(t time.Duration) *JWT {
	m.Claims.Exp = time.Now().Add(t).Unix()
	return m
}

// 设置令牌指定失效时间
func (m *JWT) SetExpiresTime(t time.Time) *JWT {
	m.Claims.Exp = t.Unix()
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

	//m.Claims["a"] = payload
	m.Claims.Payload = payload
	token := jwt.NewWithClaims(alg, m.Claims)
	return token.SignedString([]byte(secret))
}

func (m *JWT) parser(token, secret string, outPtr interface{}, validAlgorithms ...Algorithm) error {
	//m.Claims["a"] = outPtr
	m.Claims.Payload = outPtr

	if len(validAlgorithms) == 0 {
		validAlgorithms = []Algorithm{DefaultAlgorithm}
	}
	algorithms := make([]string, len(validAlgorithms))
	for i, a := range validAlgorithms {
		algorithms[i] = string(a)
	}

	parser := jwt.NewParser(jwt.WithValidMethods(algorithms), jwt.WithoutClaimsValidation())
	_, err := parser.ParseWithClaims(token, m.Claims, func(token *jwt.Token) (interface{}, error) {
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
	validator := jwt.NewValidator()
	return validator.Validate(m.Claims)
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

// 解析
func Parser(token, secret string, outPtr interface{}, validAlgorithms ...Algorithm) error {
	return New().Parser(token, secret, outPtr, validAlgorithms...)
}

// 解析并验证token
func ParserAndValid(token, secret string, outPtr interface{}, validAlgorithms ...Algorithm) error {
	return New().ParserAndValid(token, secret, outPtr, validAlgorithms...)
}
