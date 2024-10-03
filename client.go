package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
)

// IKEv2Message — структура для сообщений IKEv2
type IKEv2Message struct {
	InitiatorSPI uint64 // Идентификатор инициатора
	ResponderSPI uint64 // Идентификатор ответчика
	NextPayload  uint8  // Следующий тип полезной нагрузки (IKE_SA_INIT, IKE_AUTH и т.д.)
	Version      uint8  // Версия IKEv2
	ExchangeType uint8  // Тип обмена (IKE_SA_INIT, IKE_AUTH)
	Flags        uint8  // Флаги (например, инициатор или ответчик)
	MessageID    uint32 // Идентификатор сообщения
	Length       uint32 // Длина всего сообщения
	Payload      []byte // Полезная нагрузка (полностью зависит от этапа IKEv2)
}

// Генерация случайного SPI (идентификатора безопасности)
func generateSPI() uint64 {
	spi := make([]byte, 8)
	rand.Read(spi)
	return binary.BigEndian.Uint64(spi)
}

// Генерация SA полезной нагрузки (Simple Security Association)
func generateSAPayload() []byte {
	// Определяем параметры шифрования и хэширования (упрощенная версия)
	// Пример полезной нагрузки SA, в которой указаны политики и алгоритмы шифрования
	// Здесь указываются идентификаторы криптографических алгоритмов, групп DH и т.д.
	saPayload := []byte{
		0x00, 0x00, 0x00, 0x30, // Пример заголовка SA полезной нагрузки (длина 48 байт)
		// Политики и алгоритмы: шифрование, хэширование, группы DH и т.д.
		// Это упрощенный формат. В реальности нужно добавить параметры, такие как Transform ID и Transform Length.
		0x00, 0x01, // Proposal Number
		0x02,       // Protocol ID
		0x00, 0x28, // Length of the proposal (включая весь раздел Transform)
		// Полезная нагрузка Transform: описывает конкретные параметры, такие как алгоритмы шифрования и аутентификации
		0x01,             // Transform Type (Encryption)
		0x00, 0x00, 0x0c, // Transform Length (длина раздела)
		// Остальные данные Transform Payload...
	}
	return saPayload
}

// Генерация открытого ключа Диффи-Хеллмана (KE Payload)
func generateKEPayload(groupNumber int) ([]byte, error) {
	// Здесь реализуется генерация открытого ключа для группы DH
	// Для упрощения, используется библиотека math/big

	// Пример группы (Group 14: 2048-bit MODP group)
	groupPrime, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"+
		"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0"+
		"BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	base := big.NewInt(2)

	// Секретное случайное значение (x)
	privateKey, err := rand.Int(rand.Reader, groupPrime)
	if err != nil {
		return nil, fmt.Errorf("Ошибка генерации секретного ключа: %v", err)
	}

	// Открытый ключ: g^x mod p
	publicKey := new(big.Int).Exp(base, privateKey, groupPrime)

	// Полезная нагрузка KE с открытым ключом
	kePayload := publicKey.Bytes()
	return kePayload, nil
}

// Создание IKE_SA_INIT сообщения с SA и KE полезной нагрузкой
func createIKESaInitMessage() (IKEv2Message, error) {
	// Генерация SPI для инициатора
	initiatorSPI := generateSPI()

	// Создание полезной нагрузки SA
	saPayload := generateSAPayload()

	// Создание KE полезной нагрузки и генерация ключа Диффи-Хеллмана
	kePayload, err := generateKEPayload(14) // Группа DH 14 (2048-bit MODP)
	if err != nil {
		return IKEv2Message{}, fmt.Errorf("Ошибка генерации KE полезной нагрузки: %v", err)
	}

	// Объединение SA и KE полезных нагрузок
	payload := append(saPayload, kePayload...)

	// Создание сообщения IKE_SA_INIT
	ikeSaInitMessage := IKEv2Message{
		InitiatorSPI: initiatorSPI,
		ResponderSPI: 0,    // Пока не известен
		NextPayload:  33,   // IKE_SA_INIT payload
		Version:      0x20, // IKEv2 Version 2.0
		ExchangeType: 34,   // IKE_SA_INIT
		Flags:        0x08, // Инициатор, без ACK
		MessageID:    0,    // Идентификатор сообщения
		Length:       uint32(28 + len(payload)),
		Payload:      payload,
	}

	return ikeSaInitMessage, nil
}

// Функция для отправки IKEv2 сообщений
func sendIKEMessage(conn *net.UDPConn, message IKEv2Message) error {
	// Сериализация IKEv2Message
	buffer := make([]byte, 28+len(message.Payload))
	binary.BigEndian.PutUint64(buffer[0:8], message.InitiatorSPI)
	binary.BigEndian.PutUint64(buffer[8:16], message.ResponderSPI)
	buffer[16] = message.NextPayload
	buffer[17] = message.Version
	buffer[18] = message.ExchangeType
	buffer[19] = message.Flags
	binary.BigEndian.PutUint32(buffer[20:24], message.MessageID)
	binary.BigEndian.PutUint32(buffer[24:28], uint32(len(buffer))) // Длина всего сообщения

	// Добавление полезной нагрузки, если она существует
	if len(message.Payload) > 0 {
		copy(buffer[28:], message.Payload)
	}

	// Отправка сообщения серверу
	_, err := conn.Write(buffer)
	return err
}

// Отправка IKE_SA_INIT сообщения серверу
func main() {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5000")
	if err != nil {
		fmt.Println("Ошибка разрешения адреса:", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		fmt.Println("Ошибка создания соединения:", err)
		return
	}
	defer conn.Close()
	fmt.Println("Соединение с сервером установлено...")

	// Создание и отправка IKE_SA_INIT сообщения
	ikeSaInitMessage, err := createIKESaInitMessage()
	if err != nil {
		fmt.Println("Ошибка создания IKE_SA_INIT сообщения:", err)
		return
	}

	err = sendIKEMessage(conn, ikeSaInitMessage)
	if err != nil {
		fmt.Println("Ошибка отправки IKE_SA_INIT сообщения:", err)
		return
	}
	fmt.Println("IKE_SA_INIT сообщение отправлено серверу.")

	// Чтение ответа от сервера
	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("Ошибка чтения данных:", err)
		return
	}

	if n < 28 {
		fmt.Println("Ошибка: сообщение слишком короткое.")
		return
	}

	// Разбор IKEv2 ответа
	serverMessage := IKEv2Message{
		InitiatorSPI: binary.BigEndian.Uint64(buffer[0:8]),
		ResponderSPI: binary.BigEndian.Uint64(buffer[8:16]),
		NextPayload:  buffer[16],
		Version:      buffer[17],
		ExchangeType: buffer[18],
		Flags:        buffer[19],
		MessageID:    binary.BigEndian.Uint32(buffer[20:24]),
		Length:       binary.BigEndian.Uint32(buffer[24:28]),
		Payload:      buffer[28:n],
	}

	fmt.Printf("Получен ответ от сервера: %+v\n", serverMessage)

	// В следующем шаге будем обрабатывать IKE_AUTH.
}
