#!/bin/bash
set -e

LAB_NAME="fsb-1input-got-rce"
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
    -fno-stack-protector \
    -no-pie \
    -Wl,-z,relro \
    -Wl,-z,lazy \
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
echo "    ASLR off: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
echo "    ASLR on : echo 2 | sudo tee /proc/sys/kernel/randomize_va_space"
