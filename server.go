package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

// Генерация случайного nonce на 32 байта
func generateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	return nonce, err
}

// Генерация приватного ключа RSA
func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// Генерация самоподписанного сертификата
func generateCertificate(privKey *rsa.PrivateKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Inc."},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// Генерация параметров безопасности SAi и KEi
func generateSAiKEi() (string, []byte, []byte, error) {
	SAi := "{encryption=aes256, prf=hmac-sha256, dh=curve25519}"

	// Генерация ключевой пары Diffie-Hellman
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		return "", nil, nil, err
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", nil, nil, err
	}

	return SAi, privateKey, publicKey, nil
}

func sendData(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	return err
}

func extractAndConvert(input string, method int) ([]byte, error) {
	var re *regexp.Regexp
	switch method {
	case 1:
		re = regexp.MustCompile(`KEr: ([0-9a-fA-F]+)`)
	case 2:
		re = regexp.MustCompile(`\[SK\{IDr\}\]: ([0-9a-fA-F]+)`)
	case 3:
		re = regexp.MustCompile(`AUTH: ([0-9a-fA-F]+)`)
	}
	matches := re.FindStringSubmatch(input)
	if len(matches) < 2 {
		return nil, fmt.Errorf("последовательность не найдена")
	}

	// Извлеченная последовательность
	keiSequence := matches[1]

	// Проверка, что длина последовательности четная
	if len(keiSequence)%2 != 0 {
		return nil, fmt.Errorf("послед нечетная")
	}

	// Преобразование последовательности в байты
	byteArray := make([]byte, len(keiSequence)/2)
	for i := 0; i < len(keiSequence); i += 2 {
		hexPair := keiSequence[i : i+2]
		byteValue, err := strconv.ParseUint(hexPair, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("ошибка преобразования 16теричных пар в байты: %v", err)
		}
		byteArray[i/2] = byte(byteValue)
	}

	return byteArray, nil
}

// Чтение данных из соединения
func readData(conn net.Conn) ([]byte, error) {
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:n], nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Шаг 1: R<-I: EAP-Request/Identity
	err := sendData(conn, []byte("EAP-Request/Identity"))
	if err != nil {
		fmt.Println("Ошибка отправки запроса Identity:", err)
		return
	}

	// Шаг 2: R->I: EAP-Response/Identity(Id)
	idData, err := readData(conn)
	if err != nil {
		fmt.Println("Ошибка чтения ID:", err)
		return
	}
	fmt.Println("Получен Identity:", string(idData))

	// Шаг 3: R<-I: EAP-Req (HDR, SAi, KEi, Ni)
	nonce, _ := generateNonce()
	SAi, privateKey, publicKey, err := generateSAiKEi()
	if err != nil {
		fmt.Println("Ошибка генерации SAi и KEi:", err)
		return
	}

	fmt.Println("---------------------------------------")
	fmt.Printf("KEi: %x\n", publicKey)
	fmt.Println(publicKey)
	fmt.Println("---------------------------------------")

	message := fmt.Sprintf("EAP-Req (HDR, SAi, KEi, Ni)\nSAi: %s\nKEi: %x\nNi: %x", SAi, publicKey, nonce)
	err = sendData(conn, []byte(message))
	if err != nil {
		fmt.Println("Ошибка отправки IKE_SA_INIT запроса:", err)
		return
	}

	// Шаг 4: R->I: EAP-Res (HDR, SAr, KEr, Nr, [CERTREQ], [SK{IDr}])
	response, err := readData(conn)
	if err != nil {
		fmt.Println("Ошибка чтения EAP-Res:", err)
		return
	}
	fmt.Println("Получен EAP-Res:", string(response))

	// Парсим публичный ключ клиента KEr из сообщения
	clientKEr, err := extractAndConvert(string(response), 1)

	// Парсим IDr из сообщения
	clientIDr, err := extractAndConvert(string(response), 2)

	fmt.Printf("IDr: %x\n", clientIDr)
	fmt.Println("---------------------------------------")

	sharedSecret, err := curve25519.X25519(privateKey, clientKEr)
	if err != nil {
		fmt.Println("Ошибка вычисления общего секрета:", err)
		return
	}

	fmt.Println("---------------------------------------")
	fmt.Printf("Shared Secret: %x\n", sharedSecret)
	fmt.Println("---------------------------------------")

	IDr, _ := decryptAES(sharedSecret, clientIDr)
	fmt.Printf("IDr decr: %s\n", string(IDr))

	// Шаг 5: R<-I: EAP-Req (HDR, SK{IDi, [CERT], [CERTREQ], [NFID], AUTH})
	IDi := []byte("server")
	privKey, _ := generatePrivateKey()
	cert, _ := generateCertificate(privKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	// Генерация AUTH на основе общего секрета
	authPayload := hmac.New(sha256.New, sharedSecret)
	authPayload.Write([]byte("authentication data"))
	auth := authPayload.Sum(nil)

	encryptAuth, _ := encryptAES(sharedSecret, auth)

	message = fmt.Sprintf(
		"EAP-Req (HDR, SK{IDi, CERT, CERTREQ, NFID, AUTH})\nIDi: %s\nCERT: %s\nCERTREQ: %t\nNFID: %s\nAUTH: %x",
		IDi, certPEM, true, "Example NFID", encryptAuth,
	)

	fmt.Println("-----------FIRST AUTH FROM SERVER--------------")
	fmt.Printf("AUTH: %x\n", auth)
	fmt.Printf("Encrypt AUTH: %x\n", encryptAuth)
	fmt.Println("-----------END--------------")

	err = sendData(conn, []byte(message))
	if err != nil {
		fmt.Println("Ошибка отправки IKE_AUTH запроса:", err)
		return
	}

	// Шаг 6: R->I: EAP-Res (HDR, SK{IDr, [CERT], AUTH})
	response, err = readData(conn)
	if err != nil {
		fmt.Println("Ошибка чтения EAP-Res:", err)
		return
	}
	fmt.Println("Получен EAP-Res:", string(response))

	checkEncryptAuth, _ := extractAndConvert(string(response), 3)
	checkAuth, _ := decryptAES(sharedSecret, checkEncryptAuth)

	fmt.Println("-----------FINAL AUTH--------------")
	fmt.Printf("AUTH: %x\n", checkAuth)
	fmt.Println("-----------END--------------")

	// Шаг 7: R<-I: EAP-Success
	if bytes.Equal(auth, checkAuth) {
		err = sendData(conn, []byte("EAP-Success"))
		if err != nil {
			fmt.Println("Ошибка отправки EAP-Success:", err)
			return
		}
		fmt.Println("EAP-Success отправлено")
	}

}

func main() {
	listener, err := net.Listen("tcp", ":5000")
	if err != nil {
		fmt.Println("Ошибка запуска сервера:", err)
		return
	}
	defer listener.Close()
	fmt.Println("Сервер слушает порт 5000")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Ошибка подключения:", err)
			continue
		}
		go handleConnection(conn)
	}
}
