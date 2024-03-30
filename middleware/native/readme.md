# Native HTTP middleware

Пакет предоставляет промежуточный слой для стандартного HTTP пакета, который обеспечивает шифрование/дешифрование тела
HTTP запроса/ответ налету.

# Функции пакета, структуры и их методы

## Функции пакета

```golang
NewMTLS(mux http.Handler, log *slog.Logger, mtls *mtls.MTLS) (middleware *MTLS)
```

Функция создаёт новый HTTP промежуточный слой.

## Структуры и их методы

```golang
type MTLS struct {
    mux  http.Handler
    log  *slog.Logger
    mtls *mtls.MTLS
    
    config
}
```

Структура содержит мультиплексор HTTP запросов, лог, [MTLS](../../mtls/readme.md) и конфигурация этого промежуточного слоя.

```golang
func (m *MTLS) SetBodySizeLimit(size uint64)
```

Метод устанавливает ограничение размера шифрованного запроса, полученного в запросе.

```golang
func (m *MTLS) ServeHTTP(res http.ResponseWriter, req *http.Request)
```

Метод реализует интерфейс http.Handler, выполняя основную логику дешифрования входящего запроса и шифрования исходящего.

# Пример использования

```golang
func main() {
    addr := os.Getenv("ADDR")
    
    mux := http.NewServeMux()
    mux.HandleFunc("/v1/hello", HelloHandler)
    mux.HandleFunc("/v1/time", CurrentTimeHandler)
    
    mtlsMiddleware := NewMTLS(mux, log, mtls)
    
    log.Printf("server is listening at %s", addr)
    
    log.Fatal(http.ListenAndServe(addr, mtlsMiddleware))
}
```