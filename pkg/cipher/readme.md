# Cipher

Пакет предоставляет методы обратимых преобразований, зависящая от секретного параметра - ключа, и предназначен для
обеспечения секретности передаваемой информации.

# Функции пакета, структуры и их методы

## Функции пакета

```golang
func NewCipher(key []byte) (c *Cipher, err error)
```

Функция создаёт новый шифровальщик, преобразования которого будут зависеть от ключа.

## Структуры и их методы

```golang
type Cipher struct {
    gcm cipher.AEAD
}
```

Структура содержит AEAD (Authenticated Encryption with Associated Data): класс блочных режимов шифрования, при котором
часть сообщения шифруется, часть остается открытой, и всё сообщение целиком аутентифицировано.

В конкретном случае для аутентификации используется GCM (Galois/Counter Mode): счётчик с аутентификацией Галуа.

GCM - широко применяющийся режим работы симметричных блочных шифров, имеющий высокую эффективность и производительность.

```golang
func (c Cipher) Encode(src []byte) (dst []byte, err error)
```

Метод шифрует входной набор данных.

```golang
func (c Cipher) Decode(src []byte) (dst []byte, err error)
```

Метод дешифрует входной набор данных.

# Пример использования

```golang
func main() {
	c, err = NewCipher([]byte("secret"))
	if err != nil {
	    panic(err)	
    }
	
    const origin = "some text"
    
    var encoded []byte
    
    encoded, err = c.Encode([]byte(origin))
    if err != nil {
        panic(err)
    }
    
    var decoded []byte
    
    decoded, err = c.Decode([]byte(encoded))
    if err != nil {
        panic(err)	
    }
    
    fmt.Println(string(decoded))
}
```