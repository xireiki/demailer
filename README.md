# demailer — 小米邮件数据库授权码提取工具

`demailer` 是一个轻量级命令行工具，用于从小米手机电子邮件 App 的数据库 `EmailProvider.db` 中恢复第三方邮箱的授权码（专用密码）。它直接读取 `HostAuth` 表中的加密密码，使用 RSA 公钥解密得到明文，免去手动重置授权码的繁琐步骤。

## 功能

- `-l`：列出所有已配置的邮箱账号（去重，TSV 格式 `id<tab>email`）
- `-d <邮箱地址|id>`：解密指定账号的授权码（仅输出密码明文）
- `--all`：批量解密所有账号的授权码（TSV 格式 `email<tab>password`）
- 支持自定义数据库文件路径（作为最后一个参数）

## 编译

```bash
go build -ldflags "-s -w" -o demailer .
```

### 基本用法

```bash
# 使用当前目录下的 EmailProvider.db
./demailer -l
./demailer -d aisccount@qq.com
./demailer --all

# 指定数据库文件
./demailer -l /path/to/EmailProvider.db
./demailer -d 12 /path/to/EmailProvider.db
```

### Nushell 中使用

`-l` 和 `--all` 输出 TSV（Tab 分隔值）格式，可在 Nushell 中通过 `from tsv` 解析为结构化数据：

```nushell
./demailer -l | from tsv | get email
./demailer --all | from tsv | where email =~ "qq"
./demailer --all | from tsv | sort-by email
```

`-d` 仅输出密码明文，适合复制或嵌入脚本：

```nushell
let pw = (./demailer -d aisccount@qq.com | str trim)
```

### Bash / awk 中使用

```bash
./demailer -l | awk -F'\t' '{print $2}'
./demailer --all | awk -F'\t' '$1 ~ /qq/ {print $2}'
```

## 解密逻辑

小米邮件 App 对第三方邮箱授权码的存储过程如下：

1. 用户输入授权码（明文） → RSA 私钥加密（使用设备生成的 RSA 密钥对） → Base64 编码后存入 HostAuth.password 字段。
2. RSA 密钥对（公钥 + 私钥）存储在同数据库的 rsakey 表中（type='public' 和 type='private'）。
3. 解密时，从 rsakey 获取公钥，对 password 字段进行 RSA 公钥解密（数学运算 c^e mod n）并去除 PKCS#1 v1.5 填充，得到原始授权码。

此过程等价于 OpenSSL 命令：

```bash
openssl pkeyutl -verifyrecover -pubin -inkey public_key.pem -in ciphertext.bin
```

可行的 Shell 脚本

以下 Shell 脚本可以实现与 demailer 相同的功能：

```bash
#!/bin/bash
DB="${1:-EmailProvider.db}"   # 数据库文件路径，默认 EmailProvider.db

# 提取公钥并格式化为 PEM
pub=$(sqlite3 "$DB" "SELECT value FROM rsakey WHERE type='public';")
printf "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" "$pub" > /tmp/pub.pem

# 列出所有邮箱（去重）
list_emails() {
    sqlite3 "$DB" "SELECT MIN(_id), login FROM HostAuth WHERE login != '' GROUP BY login ORDER BY MIN(_id);" | awk -F'|' '{print $1"\t"$2}'
}

# 解密指定账号（参数：邮箱地址或 _id）
decrypt_one() {
    local id_or_mail="$1"
    local pass=$(sqlite3 "$DB" "SELECT password FROM HostAuth WHERE _id = '$id_or_mail' OR login = '$id_or_mail' LIMIT 1;")
    if [ -z "$pass" ]; then
        echo "未找到账号: $id_or_mail" >&2
        return 1
    fi
    echo "$pass" | base64 -d 2>/dev/null | openssl pkeyutl -verifyrecover -pubin -inkey /tmp/pub.pem 2>/dev/null
}

# 解密所有账号
decrypt_all() {
    sqlite3 "$DB" "SELECT login, password FROM HostAuth WHERE password IS NOT NULL GROUP BY login;" | while IFS='|' read login pass; do
        plain=$(echo "$pass" | base64 -d 2>/dev/null | openssl pkeyutl -verifyrecover -pubin -inkey /tmp/pub.pem 2>/dev/null)
        echo "$login: $plain"
    done
}

case "$1" in
    -l) list_emails ;;
    -d) decrypt_one "$2" ;;
    --all) decrypt_all ;;
    *) echo "用法: $0 [-l|-d <id|email>|--all] [database.db]" ;;
esac

rm -f /tmp/pub.pem
```

将此脚本保存为 demailer.sh，运行：

```bash
chmod +x demailer.sh
./demailer.sh -l                     # 列出邮箱
./demailer.sh -d aisccount@qq.com    # 解密指定账号
./demailer.sh --all                  # 解密所有账号
./demailer.sh --all /path/to/EmailProvider.db   # 指定数据库
```

## 注意事项

  - 需要 sqlite3, base64, openssl 命令。
  - 数据库文件需要从手机中提取（通常需要 root 权限）。
  - 仅适用于小米邮件 App 的默认加密方式，已测试多个账号验证。
