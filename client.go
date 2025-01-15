package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Структура EAP message
type EAPMessage struct {
	Code    uint8 // Request=1, Response=2, Success=3, Failure=4
	ID      uint8
	Type    uint8 // Identity=1, IKEv2=TBD
	Payload []byte
}

func encryptAES(key, plaintext []byte) ([]byte, error) {
	// Создаем новый блок шифрования AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Создаем новый GCM, который будет использовать блок шифрования
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Создаем случайный nonce (инициализационный вектор)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Шифруем plaintext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decryptAES(key, ciphertext []byte) ([]byte, error) {
	// Создаем новый блок шифрования AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Создаем новый GCM, который будет использовать блок шифрования
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Извлекаем nonce из начала ciphertext
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Расшифровываем ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func generateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}
	return nonce, nil
}

func generatePrivateKey() (*rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	return privKey, nil
}

func generateCertificate(privKey *rsa.PrivateKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Inc."},
			CommonName:   "EAP-IKEv2 Client",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return x509.ParseCertificate(certDER)
}

func extractAndConvert(input string, method int) ([]byte, error) {
	var re *regexp.Regexp
	switch method {
	case 1:
		re = regexp.MustCompile(`KEi: ([0-9a-fA-F]+)`)
	case 2:
		re = regexp.MustCompile(`IDi: ([0-9a-fA-F]+)`)
	case 3:
		re = regexp.MustCompile(`AUTH: ([0-9a-fA-F]+)`)
	}
	// Регулярное выражение для извлечения последовательности KEi
	//re := regexp.MustCompile(`KEi: ([0-9a-fA-F]+)`)
	matches := re.FindStringSubmatch(input)
	if len(matches) < 2 {
		return nil, fmt.Errorf("sequence not found")
	}

	// Извлеченная последовательность
	keiSequence := matches[1]

	// Проверка, что длина последовательности четная
	if len(keiSequence)%2 != 0 {
		return nil, fmt.Errorf("KEi sequence length is not even")
	}

	// Преобразование последовательности в байты
	byteArray := make([]byte, len(keiSequence)/2)
	for i := 0; i < len(keiSequence); i += 2 {
		hexPair := keiSequence[i : i+2]
		byteValue, err := strconv.ParseUint(hexPair, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("error converting hex pair to byte: %v", err)
		}
		byteArray[i/2] = byte(byteValue)
	}

	return byteArray, nil
}

func main() {
	conn, err := net.Dial("tcp", "localhost:5000")
	if err != nil {
		fmt.Printf("Failed to connect to server: %v\n", err)
		return
	}
	defer conn.Close()

	buffer := make([]byte, 4096)

	// Шаг 1: получить EAP-Request/Identity
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Printf("Ошибка получения Identity request: %v\n", err)
		return
	}
	fmt.Printf("Получено EAP-Request/Identity: %s\n", string(buffer[:n]))

	// Шаг 2: отправить EAP-Response/Identity
	identityResp := &EAPMessage{
		Code:    2, // Response
		ID:      1,
		Type:    1, // Identity
		Payload: []byte("client@example.com"),
	}
	if _, err := conn.Write([]byte(fmt.Sprintf("%+v", identityResp))); err != nil {
		fmt.Printf("Ошибка отправки Identity response: %v\n", err)
		return
	}

	// Шаг 3: получить EAP-Req (HDR, SAi, KEi, Ni)
	n, err = conn.Read(buffer)
	if err != nil {
		fmt.Printf("Ошибка получения IKE_SA_INIT запроса: %v\n", err)
		return
	}

	fmt.Printf("Получен IKE_SA_INIT запрос: %s\n", string(buffer[:n]))

	// Парсим KEi сервера (публичный ключ) из сообщения
	serverKEi, err := extractAndConvert(string(buffer[:n]), 1)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// Генерируем DH пару ключей
	clientPrivateKey := make([]byte, 32)
	if _, err := rand.Read(clientPrivateKey); err != nil {
		fmt.Printf("Ошибка генерации приватного ключа клиента: %v\n", err)
		return
	}

	clientPublicKey, err := curve25519.X25519(clientPrivateKey, curve25519.Basepoint)
	if err != nil {
		fmt.Printf("Ошибка генерации публичного ключа клиента: %v\n", err)
		return
	}

	// Считаем SK
	sharedSecret, err := curve25519.X25519(clientPrivateKey, serverKEi)
	if err != nil {
		fmt.Printf("Ошибка вычисления SK: %v\n", err)
		return
	}

	fmt.Printf("Shared Secret: %x\n", sharedSecret)

	// Шаг 4: отправлеяем EAP-Res (HDR, SAr, KEr, Nr, [CERTREQ], [SK{IDr}])
	Nr, err := generateNonce()
	if err != nil {
		fmt.Printf("Ошибка генерации нонса: %v\n", err)
		return
	}

	SAr := map[string]string{
		"encryption": "aes256-gcm",
		"prf":        "hmac-sha256",
		"dh":         "curve25519",
	}

	fmt.Println("--------------ПРОВЕРКА ПУБЛИЧНОГО КЛЮЧА КЛИЕНТА-----------------")
	fmt.Printf("KEr: %x\n", clientPublicKey)
	fmt.Println("-------------ПРОВЕРКА IDr И ЗАШИФРОВАННОГО IDr-----------------")

	IDr := []byte("client@example.com")

	ciphertext, err := encryptAES(sharedSecret, IDr)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("Ciphertext: %x\n", ciphertext)
	fmt.Printf("IDr: %s\n", IDr)

	fmt.Println("-------------КОНЕЦ ПРОВЕРКИ-----------------")

	ikeResponse := fmt.Sprintf("EAP-Response/IKEv2\nSAr: %v\nKEr: %x\nNr: %x\n[SK{IDr}]: %x", SAr, clientPublicKey, Nr, ciphertext)
	if _, err := conn.Write([]byte(ikeResponse)); err != nil {
		fmt.Printf("Ошибка отправки IKE_SA_INIT response: %v\n", err)
		return
	}

	// Шаг 5: получить EAP-Req (HDR, SK{IDi, [CERT], [CERTREQ], [NFID], AUTH})
	n, err = conn.Read(buffer)
	if err != nil {
		fmt.Printf("Ошибка получения IKE_AUTH request: %v\n", err)
		return
	}

	fmt.Printf("Получен IKE_AUTH request: %s\n", string(buffer[:n]))
	authEncrypted, _ := extractAndConvert(string(buffer[:n]), 3)
	auth, _ := decryptAES(sharedSecret, authEncrypted)
	fmt.Printf("AUTH decrypted: %x\n", auth)
	fmt.Println("-------------------------")

	// Шаг 6: отправить EAP-Res (HDR, SK{IDr, [CERT], AUTH})
	privKey, err := generatePrivateKey()
	if err != nil {
		fmt.Printf("Ошибка генерации приватного ключа RSA: %v\n", err)
		return
	}

	cert, err := generateCertificate(privKey)
	if err != nil {
		fmt.Printf("Ошибка генерации сертификата: %v\n", err)
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	encryptAuth, _ := encryptAES(sharedSecret, auth)

	authResponse := fmt.Sprintf("EAP-Response/IKEv2\nIDr: client@example.com\nCERT: %s\nAUTH: %x", certPEM, encryptAuth)
	if _, err := conn.Write([]byte(authResponse)); err != nil {
		fmt.Printf("Ошибка отправки IKE_AUTH response: %v\n", err)
		return
	}

	// Шаг 7: получение EAP-Success
	n, err = conn.Read(buffer)
	if err != nil {
		fmt.Printf("Ошибка получения EAP-Success: %v\n", err)
		return
	}
	fmt.Printf("Получено итоговое сообщение: %s\n", string(buffer[:n]))

	fmt.Println("EAP-IKEv2 процедура успешно завершена")
}
