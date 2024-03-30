# Reader

Пакет предоставляет io.Reader интерфейс для шифрованных данных.

# Функции пакета

```golang
func NewReader(origin io.Reader, cipher *cipher.Cipher) (reader *Reader)
```

Функция создаёт читателя, соответствующего интерфейсу io.Reader.

## Структуры и их методы

```golang
type Reader struct {
    origin io.Reader
    cipher *cipher.Cipher
}
```

Структура содержит оригинального читателя, которого текущий будет оборачивать, и шифровальщик сообщений.

```golang
func (r *Reader) Read(p []byte) (num int, err error)
```

Метод читает и шифрует данные из оригинального читателя.

# Пример использования

```golang
func main() {
    r := reader.NewReader(bytes.NewReader(strings.NewReader("original text")), cipher)

    var encoded []byte

    encoded, err = io.ReadAll(r)
    if err != nil {
        panic(err)
    }
	
    fmt.Println(encoded)
}
```