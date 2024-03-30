# Ed25519

**Edwards-curve Digital Signature Algorithm (EdDSA)** - это схема цифровой подписи, использующая вариант схемы Шнора,
основанной
на эллиптической кривой Эдвардса.

Она спроектирована так, чтобы быть быстрее по сравнению с существующей схемой цифровой подписи без ущерба для её
безопасности.
Она была разработана Дэниелом Бернштейном младшим, Нильсом Дуйфом, Таней Ланге, Питером Швабе и Бо-Инь Яном к 2011 году.

**Ed25519** - эта схема подписи EdDSA использующая SHA-512 и Curve25519.

**Curve25519** - это криптографическая эллиптическая кривая, обеспечивающая 128-битное шифрование при размере ключа 256
бит,
предназначена для использования со схемой согласования ключей Диффи — Хеллмана (ECDH).

Одна из самых быстрых кривых, при этом не защищена патентами. Эталонная программная реализация находится в общественном
достоянии.

**ECDH (Elliptic Curve Diffie-Hellman / Протокол Ди́ффи-Хе́ллмана на эллиптических кривых)** - криптографический
протокол,
позволяющий двум сторонам, имеющим пары public и private ключи на эллиптических кривых, получить общий секретный ключ,
используя незащищённый от прослушивания канал связи.

## Алгоритм работы

- Есть два пользователя _Alice_ и _Bob_
- Каждый на своей стороне генерирует пары _public_ и _private_ ключей
- _Alice_ отправляет _public_ ключ _Bob'у_, а _Bob_ отправляет свой _public_ ключ _Alice_
- Имея _public_ ключ от _Bob'а_ и свой _private_ ключ _Alice_ генерирует общий секретный ключ
- Имея _public_ ключ от _Alice_ и свой _private_ ключ _Bob_ генерирует общий секретный ключ
- В результате секретный ключ _Alice_ будет идентичным ключу _Bob'а_
- Далее, _Alice_ и _Bob_ могут шифровать и дешифровать сообщения используя полученный секретный ключ

# Функции пакета, структуры и их методы

## Функции пакета

```golang
func GenerateKeyPair() (pub domain.PublicKey, priv domain.PrivateKey, err error)
```

Функция генерирует пару public и private ключей **Ed25519**.

```golang
func GenerateSharedKey(pub domain.PublicKey, priv domain.PrivateKey) (shared domain.SharedKey, err error)
```

Функция генерирует секретный ключ на базе public и private ключей.

## Структуры и их методы

```golang
type PublicKey ed25519.PublicKey
```

Структура содержит в себе **Ed25519** public ключ.

```golang
func (pub PublicKey) ToBytes() (bs []byte, err error)
```

Метод конвертирует ключ в PKIX ASN.1 DER форму.

**PKIX** - это сертификатная компания инфраструктуры, выдающая сертификаты на основе новейших стандартов Internet X.509.

**ASN.1 (Abstract Syntax Notation One)** - в области телекоммуникаций и компьютерных сетей язык для описания
абстрактного
синтаксиса данных.

**DER (Distinguished Encoding Rules)** - однозначное кодирование данных используя особые правила:

- для кодирования данных с известной длиной количество октетов (восемь двоичных разрядов) длины должно быть наименьшим
- кодирование простых типов данных (STRING, OCTET STRING и BIT ARRAY) всегда примитивное

```golang
func (pub PublicKey) ToPEMBlock() (pem PEMBlock, err error)
```

Метод конвертирует ключ в **PEM block**.

**PEM (Privacy-Enhanced Mail / Почта с повышенной секретностью)** является стандартом Интернета для гарантирования
безопасности электронной почты в Интернете. Этот стандарт одобрен советом по архитектуре Интернета (Internet
Architecture Board, IAB). Впервые был разработан под руководством Группы приватности и безопасности Internet Resources
Task Force (IRTF) в 1993 году, далее разработка была передана в PEM Working Group (IETF). Фактически, протоколы PEM
созданы для шифрования, проверки подлинности, проверки целостности и администрирования ключей. В конечном итоге
протоколы описываются в RFC 7468.

```golang
func (pub PublicKey) ToPublicCurve() (pubCurve PublicCurve, err error)
```

Метод конвертирует ключ к криптографической эллиптической кривой **Curve25519**.

---

```golang
type PrivateKey ed25519.PrivateKey
```

Структура содержит в себе Ed25519 private ключ.

```golang
func (priv PrivateKey) ToBytes() (bs []byte, err error)
```

Метод конвертирует ключ в PKCS, ASN.1 DER форму.

**PKCS (Public Key Cryptography Standards)** - это спецификации для ускорения разработки криптографии с открытым ключом.

**ASN.1 (Abstract Syntax Notation One)** - в области телекоммуникаций и компьютерных сетей язык для описания
абстрактного
синтаксиса данных.

**DER (Distinguished Encoding Rules)** - однозначное кодирование данных используя особые правила:

- для кодирования данных с известной длиной количество октетов (восемь двоичных разрядов) длины должно быть наименьшим
- кодирование простых типов данных (STRING, OCTET STRING и BIT ARRAY) всегда примитивное

```golang
func (priv PrivateKey) ToPEMBlock() (pem PEMBlock, err error)
```

Метод конвертирует ключ в **PEM block**.

**PEM (Privacy-Enhanced Mail / Почта с повышенной секретностью)** является стандартом Интернета для гарантирования
безопасности электронной почты в Интернете. Этот стандарт одобрен советом по архитектуре Интернета (Internet
Architecture Board, IAB). Впервые был разработан под руководством Группы приватности и безопасности Internet Resources
Task Force (IRTF) в 1993 году, далее разработка была передана в PEM Working Group (IETF). Фактически, протоколы PEM
созданы для шифрования, проверки подлинности, проверки целостности и администрирования ключей. В конечном итоге
протоколы описываются в RFC 7468.

```golang
func (priv PrivateKey) ToPrivateCurve() (privCurve PrivateCurve, err error)
```

Метод конвертирует ключ к криптографической эллиптической кривой **Curve25519**.

---

```golang
type PEMBlock pem.Block
```

Структура содержит в себе PEM блок.

**PEM (Privacy-Enhanced Mail / Почта с повышенной секретностью)** является стандартом Интернета для гарантирования
безопасности электронной почты в Интернете. Этот стандарт одобрен советом по архитектуре Интернета (Internet
Architecture Board, IAB). Впервые был разработан под руководством Группы приватности и безопасности Internet Resources
Task Force (IRTF) в 1993 году, далее разработка была передана в PEM Working Group (IETF). Фактически, протоколы PEM
созданы для шифрования, проверки подлинности, проверки целостности и администрирования ключей. В конечном итоге
протоколы описываются в RFC 7468.

```golang
func (pb *PEMBlock) ToPublicKey() (pub PublicKey, err error)
```

Метод конвертирует **PEM block** в public ключ.

```golang
func (pb *PEMBlock) ToPrivateKey() (priv PrivateKey, err error)
```

Метод конвертирует **PEM block** в private ключ.

```golang
func (pb *PEMBlock) ToBytes() (bs []byte)
```

Метод конвертирует **PEM block** байтовую последовательность.

```golang
func (pb *PEMBlock) Save(filePath string) (err error)
```

Метод сохраняет **PEM block** в файл.

```golang
func (pb *PEMBlock) FromBytes(bs []byte) (err error)
```

Метод загружает **PEM block** из байтовой последовательности.

---

```golang
type SharedKey []byte
```

Структура содержит секретный ключ

```golang
func (shared SharedKey) Sign() (sign string, err error)
```

Метод генерирует 6 символьный признак, который используется сторонами для идентификации используемого секретного ключа
без его потери.

# Пример использования

```golang
func main() {
    var (
        pub  domain.PublicKey
        priv domain.PrivateKey
    )
    
    pub, priv, err = ed25519.GenerateKeyPair()
    if err != nil {
        panic(err)
    }
    
    var shared domain.SharedKey
    
    shared, err = ed25519.GenerateSharedKey(pub, priv)
    if err != nil {
        panic(err)
    }
    
    fmt.Println(shared)
}
```