# MTLS

mTLS (Mutual Transport Layer Security) - это способ обеспечения одновременной аутентифицирующим двух сторон.

Способ предназначен для решения задачи взаимной аутентификации (Mutual authentication или Two-way authentication),
позволяющий работу в сети с нулевым доверием.

Пакет предоставляет методы обратимых преобразований, зависящая от пар public и private ключей двух участников
коммуникации, при помощи которых генерируются секретные ключи, используемые в симметричном шифровании.

# Функции пакета, структуры и их методы

## Функции пакета

```golang
func NewMTLS(pubPEMBs, privPEMBs []byte) (mtls *MTLS, err error)
```

Функция создаёт новый шифровальщик, преобразования которого будут зависеть от public и private ключей.

## Структуры и их методы

```golang
type MTLS struct {
    cipher *cipher.Cipher
    sign   string
}
```

Структура содержит [шифровальщик](../pkg/cipher/readme.md)
и [6 символьный признак секретного ключа](../pkg/ed25519/readme.md).

```golang
func (m MTLS) Encode(src []byte) (dst []byte, err error)
```

Метод шифрует входной набор данных.

```golang
func (m MTLS) Decode(src []byte) (dst []byte, err error)
```

Метод дешифрует входной набор данных.

```golang
func (m MTLS) Sign() (sign string)
```

Метод возвращает 6 символьный признак секретного ключа.

```golang
func (m MTLS) Cipher() (cipher *cipher.Cipher)
```

Метод возвращает используемый в MTLS шифровальщик.

# Пример использования

```golang
func main() {
    mtls, err := NewMTLS(pubPEMBs, privPEMBs)
    if err != nil {
        panic(err)
    }

    const origin = "some text"
    
    var encoded []byte
    
    encoded, err = mtls.Encode([]byte(origin))
    if err != nil {
        panic(err)
    }
    
    var decoded []byte
    
    decoded, err = mtls.Decode([]byte(encoded))
    if err != nil {
        panic(err)
    }
    
    fmt.Println(string(decoded))
}
```