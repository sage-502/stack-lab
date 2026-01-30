# pwnable-lab
포너블 공부 기록 모음집

- 취약점 포함 코드 작성&컴파일, 익스플로잇 시도, 취약점 제거 코드 작성 순서로 진행.
- ubuntu 24.04, 32bit 환경 기준.

※ 가상머신에서만 사용할 것을 추천.

---

## 구성

예시, 변동 있음.

```
pwnable-lab/
├── setup.sh            // 패키지, 툴, 32bit 환경 설정
├── stack-bof-basic/
│    ├── README.md      // 취약점 개념 정리, 바이너리 분석, 익스플로잇
│    ├── vuln.c         // 취약점 포함 C소스코드
│    ├── build.sh       // vuln.c 컴파일
│    ├── exploit.py     // 익스플로잇 파이썬 코드
│    └── fix.c          // 취약점 제거한 C소스코드
...
├── memo.md             // 메모장, 기록
└── images/             // .md 파일에 사용할 이미지 모음
```

### 개별 디렉터리 소개

| No | Directory | Vuln | Method | Environ |
|-------|-------|-------|-------|-------|
| 1 | [stack-bof-basic](https://github.com/sage-502/pwnable-lab/tree/main/stack-bof-basic) | bof | ret2win | ASLR / canary off |
| 2 | [format-string-vuln](https://github.com/sage-502/pwnable-lab/tree/main/format-string-vuln) | fsb | local overwrite | ASLR off |
| 3 | [format-string-vuln2](https://github.com/sage-502/pwnable-lab/tree/main/format-string-vuln2) | fsb | ret2win | ASLR off |
| 4 | [fsb-leak](https://github.com/sage-502/pwnable-lab/tree/main/fsb-leak) | fsb | libc leak | ASLR on |
| 5 (번외) | [bof-ret2libc-epilogue](https://github.com/sage-502/pwnable-lab/tree/main/bof-ret2libc-epilogue) | fsb | ret2libc | ASLR off |
| 6 | [bof-ret2libc-basic](https://github.com/sage-502/pwnable-lab/tree/main/bof-ret2libc-basic) | bof | ret2libc | ASLR off / canary off |
| 7 | [fsb-bof-ret2libc](https://github.com/sage-502/pwnable-lab/tree/main/fsb-bof-ret2libc) | fsb + bof | ret2libc | ASLR on / canary off |
| 8 | [fsb-local-overwrite](https://github.com/sage-502/pwnable-lab/tree/main/fsb-local-overwrite) | fsb | leak + local overwrite | ASLR on / PIE on |
| 9 | [fsb-got-overwrite](https://github.com/sage-502/pwnable-lab/tree/main/fsb-got-overwrite) | fsb | got overwrite | PIE off / Partial RELRO |
| 10 (번외) | [fsb-1input-got-rce](https://github.com/sage-502/pwnable-lab/tree/main/fsb-1input-got-rce) | fsb | got overwrite | PIE off / Partial RELRO |
| 11 | [fsb-canary-leak](https://github.com/sage-502/pwnable-lab/tree/main/fsb-canary-leak) | fsb | canary leak | ASLR on / canary on |

(업데이트 예정)

---

## 사용법

### 1. 환경 설정 (setup.sh)

- 실습에 필요한 패키지, 툴, 32bit 환경 설치
- 최소권한, 패스워드 없는 사용자 baby 생성 -> 권한 상승 실습 시 사용
- 사용 : `sudo bash setup.sh`

### 2. 실습 바이너리 빌드 (build.sh)

- 실습용 디렉터리 `/tmp/(취약점 디렉터리)` 생성
- 실습용 디렉터리에 vuln.c 복사, vuln.c 컴파일, 권한 설정
- 사용 : `sudo bash build.sh`
- 이후 해당 디렉터리로 이동, 필요 시 계정 변경 후 실습

### 3. 실행 예시
``` bash
git clone https://github.com/sage-502/pwnable-lab
cd pwnable-lab
sudo bash setup.sh    # 최초 1회만 실행

cd stack-bof-basic
sudo bash build.sh    # 컴파일
```

※ baby 계정 사용을 원할 시, `/tmp`에 `exploit.py` 복사 후 baby로 로그인.

---

## 실습 순서 (권장)
1. `vuln.c`에서 취약점 확인
2. `build.sh` 로 컴파일
3. 분석, `exploit.py` 또는 `payload.py` → 익스플로잇
4. 취약점 제거한 `fix.c` 확인

※ `exploit.py` 와 `payload.py`에서 주소나 오프셋 등은 직접 수정하여 사용해야 함.
