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
    "strings"
    "time"

    "github.com/dgrijalva/jwt-go"
)

const (
    DefaultSecret    = "123456"
    DefaultAlgorithm = "HS256"
)

var algorithmMapp = map[string]jwt.SigningMethod{
    "HS256": jwt.SigningMethodHS256,
    "HS384": jwt.SigningMethodHS384,
    "HS512": jwt.SigningMethodHS512,
    "ES256": jwt.SigningMethodES256,
    "ES384": jwt.SigningMethodES384,
    "ES512": jwt.SigningMethodES512,
    "PS256": jwt.SigningMethodPS256,
    "PS384": jwt.SigningMethodPS384,
    "PS512": jwt.SigningMethodPS512,
    "RS256": jwt.SigningMethodRS256,
    "RS384": jwt.SigningMethodRS384,
    "RS512": jwt.SigningMethodRS512,
}

type JWT struct {
    jwt.StandardClaims
    A         interface{}       `json:"a"`
    secret    []byte            `json:"-"`
    algorithm jwt.SigningMethod `json:"-"`
}

// 创建一个jwt
func New() *JWT {
    return new(JWT).SetSecret(DefaultSecret).SetAlgorithm(DefaultAlgorithm)
}

// 设置秘钥
func (m *JWT) SetSecret(secret string) *JWT {
    if len(secret) == 0 {
        panic("秘钥不能为空")
    }
    m.secret = []byte(secret)
    return m
}

// 设置算法
func (m *JWT) SetAlgorithm(algorithm string) *JWT {
    a := algorithmMapp[strings.ToUpper(algorithm)]
    if a == nil {
        panic(fmt.Sprintf("没有 <%s> 这种算法", algorithm))
    }
    m.algorithm = a
    return m
}

// 设置令牌签发时间为当前时间
func (m *JWT) SetIssuedAt() *JWT {
    m.IssuedAt = time.Now().Unix()
    return m
}

// 设置令牌签发时间
func (m *JWT) SetIssuedAtTime(t time.Duration) *JWT {
    m.IssuedAt = int64(t) / 1e9
    return m
}

// 设置令牌一段时间后生效(纳秒
func (m *JWT) SetAfter(t int64) *JWT {
    m.NotBefore = time.Now().Add(time.Duration(t)).Unix()
    return m
}

// 设置令牌指定生效时间
func (m *JWT) SetAfterTime(t time.Duration) *JWT {
    m.NotBefore = int64(t) / 1e9
    return m
}

// 设置令牌一段时间后失效(纳秒
func (m *JWT) SetExpires(t int64) *JWT {
    m.ExpiresAt = time.Now().Add(time.Duration(t)).Unix()
    return m
}

// 设置令牌指定失效时间
func (m *JWT) SetExpiresTime(t time.Duration) *JWT {
    m.ExpiresAt = int64(t) / 1e9
    return m
}

// 获取jwt签名后的数据
func (m *JWT) GetToken(a interface{}) (string, error) {
    m.A = a
    token := jwt.NewWithClaims(m.algorithm, m)
    return token.SignedString(m.secret)
}

func (m *JWT) parser(token string, a interface{}, valid bool) error {
    m.A = a
    parser := &jwt.Parser{ValidMethods: []string{m.algorithm.Alg()}, SkipClaimsValidation: !valid}
    _, err := parser.ParseWithClaims(token, m, func(token *jwt.Token) (interface{}, error) {
        return m.secret, nil
    })
    return err
}

// 解析jwt数据
func (m *JWT) Parser(token string, a interface{}) error {
    return m.parser(token, a, false)
}

// 解析jwt数据并验证使用时间
func (m *JWT) ParserAndValid(token string, a interface{}) error {
    return m.parser(token, a, true)
}

// 验证令牌有效时间
func (m *JWT) Valid() error {
    return m.StandardClaims.Valid()
}
