#!/bin/bash
set -e

LAB_NAME="bof-fsb-canary-bypass"
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
    -fstack-protector-all \
    -fPIE -pie \
    -Wl,-z,relro,-z,now \
    -fno-omit-frame-pointer \
    -z noexecstack

echo "[+] build complete"

# ---------------------------
# 4. 권한 설정
# ---------------------------
chown root:root "$TMP_DIR/$BIN"
chmod 2755 "$TMP_DIR/$BIN"

echo "[+] binary: $TMP_DIR/$BIN"

echo ""
file $TMP_DIR/$BIN
echo ""
checksec --file=$TMP_DIR/$BIN

echo ""
echo "[!] Run this manually if needed:"
echo "    echo 2 | sudo tee /proc/sys/kernel/randomize_va_space"
