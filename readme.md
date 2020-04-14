# 二次封装的的jwt, 使用非常简单

---

# 获得

`go get -u github.com/zlyuancn/zjwt`

# 文档
[godoc](https://godoc.org/github.com/zlyuancn/zjwt)

# 快速使用

```go
    token, _ := zjwt.MakeToken("123", "your_secret")
    fmt.Println(token)

    var result string
    _ = zjwt.ParserAndValid(token, "your_secret", &result)
    fmt.Println(result)
```
