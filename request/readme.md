# Request

Этот пакет является обёрткой поверх http.Request, которая позволяет шифровать отправляемый запрос.

# Функции пакета

```golang
func NewRequest(method, url string, body io.Reader, c *cipher.Cipher) (req *http.Request, err error)
```

Функция создаёт http.Request с зашифрованным телом запроса.

```golang
func NewRequestWithContext(ctx context.Context, method, url string,
    body io.Reader, mtls *mtls.MTLS,
) (req *http.Request, err error)
```

Функция создаёт http.Request, зависимый от контекста, с зашифрованным телом запроса.

# Пример использования

```golang
func main() {
    const body = `{"value": "key"}`

    req, err := request.NewRequest(http.MethodPost, "http://somehost:8888/v1/hello", body, cipher)
    if err != nil {
        panic(err)	
    }

    _, err := http.DefaultClient.Do(req)
    if err != nil {
        panic(err)
    }
}
```