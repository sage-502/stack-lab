# memo

메모장 :)

---

## Procedure

제작 순서

1. [stack-bof-basic](https://github.com/sage-502/pwnable-lab/tree/main/stack-bof-basic)
2. [format-string-vuln](https://github.com/sage-502/pwnable-lab/tree/main/format-string-vuln)
3. [format-string-vuln2](https://github.com/sage-502/pwnable-lab/tree/main/format-string-vuln2)
4. [fsb-leak](https://github.com/sage-502/pwnable-lab/tree/main/fsb-leak)
5. [bof-ret2libc-epilogue](https://github.com/sage-502/pwnable-lab/tree/main/bof-ret2libc-epilogue)
6. [bof-ret2libc-basic](https://github.com/sage-502/pwnable-lab/tree/main/bof-ret2libc-basic)
7. [fsb-bof-ret2libc](https://github.com/sage-502/pwnable-lab/tree/main/fsb-bof-ret2libc)
8. [fsb-local-overwrite](https://github.com/sage-502/pwnable-lab/tree/main/fsb-local-overwrite)
9. [fsb-local-overwrite](https://github.com/sage-502/pwnable-lab/tree/main/fsb-got-overwrite)
10. [fsb-1input-got-rce](https://github.com/sage-502/pwnable-lab/tree/main/fsb-1input-got-rce)
11. [fsb-canary-leak](https://github.com/sage-502/pwnable-lab/tree/main/fsb-canary-leak)
12. [bof-fsb-canary-bypass](https://github.com/sage-502/pwnable-lab/tree/main/bof-fsb-canary-bypass)
13. [bof-rop-pivot](https://github.com/sage-502/pwnable-lab/tree/main/bof-rop-pivot)
14. [bof-rop-orw](https://github.com/sage-502/pwnable-lab/tree/main/bof-rop-orw)

---

## Want to do

- [x] stack bof basic - ret2win : ASLR off
- [x] format string vuln1 - local overwrite : ASLR off, 로컬 변수 주소 제시 (개념용)
- [x] format string vuln2 - ret2win : ASLR off
  - GDB 내부에서 system("/bin/bash")로 쉘 쓰는 게 어려웠음.
- [x] fsb leak - stack leak, libc leak : ASLR off, on 각각
  - off 하는 거 까먹음.
- [x] bof ret2libc - epilogue : ASLR off
  - 프롤로그/에필로그가 이상하게 나옴.
  - 케이스 스터디 느낌으로 그냥 해봄.
- [x] bof ret2libc - clean : ASLR off
  - `-fno-omit-frame-pointer` 옵션 추가로 예쁘게
  - `vuln()` 함수 따로 파서 ret overwrite 깔끔하게
- [x] fsb bof ret2libc : ASLR on
  - fsb로 libc leak, bof로 ret overwrite
- [x] fsb local overwrite - local overwrite : ASLR on
  - input2번 : 1번째 leak, 2번째 overwrite
- [x] fsb got overwrite : ASLR on, PIE off
  - eixt의 got를 main으로 바꿔 무한 루프 돌리기
  - 원래 쉘 따고 싶었는데, 인자 때문에 애매했음 (그래서 puts(buf) 계획)
- [x] fsb got overwrite2
  - printf(buf) + puts(buf)
  - got overwrite로 puts를 system으로 보내기
  - 디렉 이름... fsb-1input-got-rce?
- [x] fsb canary leak
  - canary 개념, 작동 방식 정리
  - fsb로 leak만
- [x] fsb cananry bypass
  - fsb로 canary leak + bof로 ret2libc
  - cananry bypass
  - 보호기법 공부를 좀 해와야겠음...
    → 레포 하나 더 팔까 함. 이름은 32bit-mitigation-lab...?
- [x] bof + ROP
  - 32bit로 하니까 가젯이 안 나옴... ROP_bank로 치트키 쓰기로 함.
  - syscall 쓰기로 함. 체인이 뚱뚱해짐. 스택은 너무 째깐함... pivot 쓰기로 함.
  - read 400bytes라 사실 pivot 안 써도 가능하긴 함.
  - bof-rop-basic 이 bof-rop-pivot이 됨.
- [x] bof + ROP 난이도 하향 ver
  - 발표용...
  - bof-rop-pivot 변형
  - 원본과 다른 점: pivot 제거, 전역에 flag 경로와 read/write용 버퍼 선언, 권한세팅 main에서.

---

### Vulnerability

- Buffer overflow : bof
- Format string vulnerability : fsb

---

### Method

- local overwrite
- ret overwrite : ret2win, ret2libc
- got overwrite
- leak
- return oriented programming(ROP)
