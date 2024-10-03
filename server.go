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

// Генерация собственного открытого ключа DH и создание общего секретного ключа
func handleIKESAInit(ikeMessage IKEv2Message) ([]byte, *big.Int, error) {
	// Извлечение открытого ключа клиента из сообщения IKE_SA_INIT (предположим, он начинается с 28 байта)
	clientPublicKey := new(big.Int).SetBytes(ikeMessage.Payload[28:])

	// Группа 14: 2048-bit MODP (та же, что использует клиент)
	groupPrime, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"+
		"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0"+
		"BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	base := big.NewInt(2)

	// Генерация собственного закрытого и открытого ключа сервера
	privateKey, err := rand.Int(rand.Reader, groupPrime)
	if err != nil {
		return nil, nil, fmt.Errorf("Ошибка генерации секретного ключа: %v", err)
	}
	serverPublicKey := new(big.Int).Exp(base, privateKey, groupPrime) // g^y mod p

	// Генерация общего секретного ключа
	sharedSecret := new(big.Int).Exp(clientPublicKey, privateKey, groupPrime) // (g^x)^y mod p = g^(xy) mod p

	// Создание KE полезной нагрузки для ответа (отправляем серверный открытый ключ)
	kePayload := serverPublicKey.Bytes()
	return kePayload, sharedSecret, nil
}

// Создание IKE_SA_INIT ответа с KE полезной нагрузкой сервера
func createIKESaInitResponse(initiatorSPI, responderSPI uint64, kePayload []byte) IKEv2Message {
	// Объединение KE полезной нагрузки
	payload := kePayload

	// Создание сообщения IKE_SA_INIT ответа
	ikeSaInitResponse := IKEv2Message{
		InitiatorSPI: initiatorSPI,
		ResponderSPI: responderSPI,
		NextPayload:  33,   // IKE_SA_INIT payload
		Version:      0x20, // IKEv2 Version 2.0
		ExchangeType: 34,   // IKE_SA_INIT
		Flags:        0x20, // Ответчик
		MessageID:    0,    // Идентификатор сообщения
		Length:       uint32(28 + len(payload)),
		Payload:      payload,
	}

	return ikeSaInitResponse
}

// Обработка входящих IKE сообщений
func handleIncomingMessages(conn *net.UDPConn) {
	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Ошибка чтения данных:", err)
			continue
		}

		if n < 28 {
			fmt.Println("Ошибка: сообщение слишком короткое.")
			continue
		}

		// Разбор IKEv2 сообщения
		ikeMessage := IKEv2Message{
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

		fmt.Printf("Получено сообщение от клиента: %+v\n", ikeMessage)

		// Обработка IKE_SA_INIT (первое сообщение)
		if ikeMessage.ExchangeType == 34 { // IKE_SA_INIT
			fmt.Println("Обработка IKE_SA_INIT сообщения...")

			// Генерация KE ответа и общего секретного ключа
			kePayload, sharedSecret, err := handleIKESAInit(ikeMessage)
			if err != nil {
				fmt.Println("Ошибка обработки IKE_SA_INIT:", err)
				continue
			}

			fmt.Printf("Общий секретный ключ: %x\n", sharedSecret.Bytes())

			// Создание ответа на IKE_SA_INIT
			ikeSaInitResponse := createIKESaInitResponse(ikeMessage.InitiatorSPI, generateSPI(), kePayload)

			// Отправка ответа клиенту
			err = sendIKEMessage(conn, addr, ikeSaInitResponse)
			if err != nil {
				fmt.Println("Ошибка отправки IKE_SA_INIT ответа:", err)
				continue
			}
			fmt.Println("IKE_SA_INIT ответ отправлен клиенту.")
		}
	}
}

// Функция для отправки IKE сообщения сервером
func sendIKEMessage(conn *net.UDPConn, addr *net.UDPAddr, ikeMessage IKEv2Message) error {
	// Формирование заголовка IKEv2 сообщения
	header := make([]byte, 28)
	binary.BigEndian.PutUint64(header[0:8], ikeMessage.InitiatorSPI)
	binary.BigEndian.PutUint64(header[8:16], ikeMessage.ResponderSPI)
	header[16] = ikeMessage.NextPayload
	header[17] = ikeMessage.Version
	header[18] = ikeMessage.ExchangeType
	header[19] = ikeMessage.Flags
	binary.BigEndian.PutUint32(header[20:24], ikeMessage.MessageID)
	binary.BigEndian.PutUint32(header[24:28], ikeMessage.Length)

	// Объединение заголовка и полезной нагрузки
	message := append(header, ikeMessage.Payload...)

	// Отправка IKE сообщения клиенту
	_, err := conn.WriteToUDP(message, addr)
	return err
}

func main() {
	// Запуск UDP сервера
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5000")
	if err != nil {
		fmt.Println("Ошибка разрешения адреса:", err)
		return
	}

	conn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		fmt.Println("Ошибка создания UDP сервера:", err)
		return
	}
	defer conn.Close()
	fmt.Println("IKEv2 сервер запущен и ожидает входящих соединений...")

	// Обработка входящих сообщений
	handleIncomingMessages(conn)
}
