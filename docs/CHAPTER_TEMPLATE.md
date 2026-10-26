# 챕터 템플릿

새 챕터는 `chapters/NN-slug/` 아래에 이 구조로 만든다.

```
chapters/NN-slug/
├── README.md        ← 아래 본문 형식
└── code/
    ├── Makefile     ← include ../../../mk/common.mk, 타깃: build / run / clean
    ├── run.sh       ← root로 실행되는 실습 스크립트 (결과는 out/run.log)
    └── ...
```

## code/Makefile 규칙

- `build`: **root 없이** 동작해야 한다(컴파일, bpf2go, go build).
- `run`: root가 필요한 실행. 이미 빌드된 산출물만 쓰고 `go`/`clang`을 다시 부르지 않는다(root 소유 산출물 방지).
  출력은 `| tee $(RUN_LOG)`로 남긴다.
- `clean`: 빌드 산출물과 `out/` 삭제.
- 무한히 도는 프로그램은 `-d 4s` 같은 실행 시간 옵션을 두고, 부하(workload)를 스크립트가 직접 만든다.
- README에 붙이는 결과 예시는 **부하와 관련된 줄만** 걸러서 싣는다(호스트의 다른 프로세스 정보가 섞이지 않게).

---

## README.md 본문 형식 (복사해서 사용)

```markdown
# NN. 제목

> **핵심 요약**
> 1. …
> 2. …
> 3. …

## 1. 개념

용어는 처음 나올 때 `한국어(영어)`로 쓴다. 그림은 mermaid.

## 2. 예제

| 파일 | 내용 |
|---|---|

### 실행

    make build                 # root 불필요
    make run                   # 내부에서 sudo. 결과: out/run.log

### 실행 결과 (Linux 6.17 x86_64)

    (실제 출력. 길면 일부만, 생략은 … 로 표시)

### 코드 해설

## 3. 직접 해보기

1. …

## 4. 자주 하는 실수

- **증상** — 원인과 해결

## 5. 더 읽을거리

| 자료 | 라이선스 | 이 챕터에서의 사용 |
|---|---|---|
| [제목](링크) | CC BY 4.0 등 | 참고·재서술 / 일부 번역 |
```
