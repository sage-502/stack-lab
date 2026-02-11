#!/bin/bash
set -e

LAB_NAME="bof-rop-orw"
TMP_DIR="/tmp/$LAB_NAME"
SRC="vuln.c"
BIN="vuln"

echo "[*] build $LAB_NAME"

# ---------------------------
# 1. /tmp 디렉터리 준비
# ---------------------------
echo "[*] preparing $TMP_DIR"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"


# ---------------------------
# 2. 소스코드 복사
# ---------------------------
cp "$SRC" "$TMP_DIR/"
echo "[+] source copied"

# ---------------------------
# 3. 컴파일 (32bit, 보호기법 비활성화)
# ---------------------------
echo "[*] compiling binary"

gcc -m32 "$TMP_DIR/$SRC" -o "$TMP_DIR/$BIN" \
    -O0 \
    -fno-omit-frame-pointer \
    -fno-stack-protector \
    -no-pie \
    -z noexecstack \
    -Wl,-z,relro,-z,now \


echo "[+] build complete"

# ---------------------------
# 4. 권한 설정
# ---------------------------
chown root:root "$TMP_DIR/$BIN"
chmod 2755 "$TMP_DIR/$BIN"

# ---------------------------
# 5. flag 생성
# ---------------------------
echo "flag{cat_said_orw_ROP^._.^}" > "$TMP_DIR/flag"
chown root:root "$TMP_DIR/flag"
chmod 640 "$TMP_DIR/flag"

echo "[+] flag: $TMP_DIR/flag"
echo "[+] binary: $TMP_DIR/$BIN"

echo ""
file $TMP_DIR/$BIN
echo ""
checksec --file=$TMP_DIR/$BIN

echo ""
echo "[!] Run this manually if needed:"
echo "    echo 2 | sudo tee /proc/sys/kernel/randomize_va_space"
