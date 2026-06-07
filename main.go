package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

var defaultDbPath = "EmailProvider.db"

func main() {
	list := flag.Bool("l", false, "列出所有邮箱（去重，显示 Id 和 Email）")
	decrypt := flag.String("d", "", "解密指定邮箱（邮箱地址或 Id）")
	all := flag.Bool("a", false, "解密所有邮箱")
	flag.Parse()

	dbPath := defaultDbPath
	if args := flag.Args(); len(args) > 0 {
		dbPath = args[0]
	}

	if *list {
		listEmails(dbPath)
		return
	}
	if *decrypt != "" {
		decryptEmail(dbPath, *decrypt)
		return
	}
	if *all {
		decryptAll(dbPath)
		return
	}
	flag.Usage()
}

// 获取 RSA 公钥（从 rsakey 表）
func getPublicKey(dbPath string) (*rsa.PublicKey, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var raw string
	err = db.QueryRow("SELECT value FROM rsakey WHERE type='public'").Scan(&raw)
	if err != nil {
		return nil, err
	}
	// 删除所有空白符（换行、空格等）
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' {
			return -1
		}
		return r
	}, raw)
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥不是 RSA 类型")
	}
	return rsaPub, nil
}

// RSA 公钥解密（模拟 openssl pkeyutl -verifyrecover）
func rsaPublicDecrypt(pub *rsa.PublicKey, ciphertext []byte) ([]byte, error) {
	keySize := pub.N.BitLen() / 8 // 模数长度，2048位 -> 256字节
	if len(ciphertext) > keySize {
		return nil, fmt.Errorf("密文长度 %d 大于模数长度 %d", len(ciphertext), keySize)
	}
	// 左侧补零至 keySize 字节
	padded := make([]byte, keySize)
	copy(padded[keySize-len(ciphertext):], ciphertext)

	c := new(big.Int).SetBytes(padded)
	m := new(big.Int).Exp(c, big.NewInt(int64(pub.E)), pub.N)
	em := m.Bytes()
	// 结果可能短于 keySize，左侧补零
	if len(em) < keySize {
		tmp := make([]byte, keySize)
		copy(tmp[keySize-len(em):], em)
		em = tmp
	}
	// PKCS#1 v1.5 类型 1 填充检查（用于签名验证恢复）
	if len(em) < 11 {
		return nil, fmt.Errorf("数据太短")
	}
	if em[0] != 0x00 || em[1] != 0x01 {
		return nil, fmt.Errorf("无效的 PKCS#1 填充")
	}
	i := 2
	for ; i < len(em); i++ {
		if em[i] == 0x00 {
			break
		}
	}
	if i == len(em) {
		return nil, fmt.Errorf("找不到分隔符")
	}
	return em[i+1:], nil
}

// 解密单个密码 Base64 字符串
func decryptPassword(encBase64 string, pub *rsa.PublicKey) (string, error) {
	encBase64 = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, encBase64)
	ciphertext, err := base64.StdEncoding.DecodeString(encBase64)
	if err != nil {
		return "", err
	}
	plain, err := rsaPublicDecrypt(pub, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// 检测是否在 Nushell 环境中运行
func isNushell() bool {
	return os.Getenv("NU_VERSION") != ""
}

// 列出所有邮箱（去重，显示最小的 _id）
func listEmails(dbPath string) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`
		SELECT MIN(_id) as id, login
		FROM HostAuth
		WHERE login != ''
		GROUP BY login
		ORDER BY id
	`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	type row struct {
		id    int
		email string
	}
	var data []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.email); err != nil {
			log.Fatal(err)
		}
		data = append(data, r)
	}

	if isNushell() {
		fmt.Println("Id\tEmail")
		for _, r := range data {
			fmt.Printf("%d\t%s\n", r.id, r.email)
		}
	} else {
		maxID := 2 // "id"
		for _, r := range data {
			if w := len(fmt.Sprintf("%d", r.id)); w > maxID {
				maxID = w
			}
		}
		fmt.Printf("%*s  %s\n", maxID, "Id", "Email")
		for _, r := range data {
			fmt.Printf("%*d  %s\n", maxID, r.id, r.email)
		}
	}
}

// 解密指定邮箱（支持 _id 或 login）
func decryptEmail(dbPath, identifier string) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	var login, password string
	// 先按 _id 查
	err = db.QueryRow("SELECT login, password FROM HostAuth WHERE _id = ?", identifier).Scan(&login, &password)
	if err != nil {
		// 再按 login 查（取第一条）
		err = db.QueryRow("SELECT login, password FROM HostAuth WHERE login = ? LIMIT 1", identifier).Scan(&login, &password)
		if err != nil {
			log.Fatalf("未找到数据库: %s", identifier)
		}
	}
	pub, err := getPublicKey(dbPath)
	if err != nil {
		log.Fatal("获取公钥失败:", err)
	}
	plain, err := decryptPassword(password, pub)
	if err != nil {
		log.Fatal("解密失败:", err)
	}
	fmt.Println(plain)
}

// 解密所有邮箱（每个邮箱只解密一次，取第一条密码记录）
func decryptAll(dbPath string) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// 对每个 login 取任意一条 password（通常 IMAP 和 SMTP 的密码相同）
	rows, err := db.Query(`
		SELECT login, password
		FROM HostAuth
		WHERE password IS NOT NULL
		GROUP BY login
	`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	pub, err := getPublicKey(dbPath)
	if err != nil {
		log.Fatal("获取公钥失败:", err)
	}
	type row struct {
		login    string
		password string
	}
	var data []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.login, &r.password); err != nil {
			log.Fatal(err)
		}
		plain, err := decryptPassword(r.password, pub)
		if err != nil {
			data = append(data, row{r.login, "解密失败: " + err.Error()})
		} else {
			data = append(data, row{r.login, plain})
		}
	}

	if isNushell() {
		fmt.Println("Email\tPassword")
		for _, r := range data {
			fmt.Printf("%s\t%s\n", r.login, r.password)
		}
	} else {
		maxEmail := 5   // "email"
		maxPass := 8    // "password"
		for _, r := range data {
			if w := len(r.login); w > maxEmail {
				maxEmail = w
			}
			if w := len(r.password); w > maxPass {
				maxPass = w
			}
		}
		fmt.Printf("%-*s  %-*s\n", maxEmail, "Email", maxPass, "Password")
		for _, r := range data {
			fmt.Printf("%-*s  %-*s\n", maxEmail, r.login, maxPass, r.password)
		}
	}
}
