# ebpf-fundamentals-kr — 작업 규칙

- 개인 **public** repo: `github.com/Y-JaeHyun/ebpf-fundamentals-kr`. **기준 브랜치는 `main`** — 전역 CLAUDE.md의 `proto` 기준 규칙은 회사 repo 전용이며 여기엔 해당 없음.
- 시작 시 `docs/BRIEF.md`(목표·커리큘럼·형식·번역 규칙)를 먼저 읽는다.
- **공개 저장소다.** 회사 관련 내용·내부 경로·사내 코드·토큰은 절대 커밋하지 않는다. push 전에 `git diff --cached`로 확인한다.
- 모든 예제는 실제로 빌드·실행 확인 후 싣는다. root가 필요하면 사용자에게 `! sudo ...` 실행을 요청한다(비밀번호 없는 sudo 불가).
- 환경: Ubuntu, kernel 6.17, BTF 있음, Go 1.26, clang 18, bpftool/bpftrace, Docker 29. LSM-BPF는 현재 비활성(`lsm=` 부팅 인자에 bpf 없음).
- 모든 문서는 한국어로 쓴다. 영어 원문은 번역 또는 재서술하고 출처·라이선스를 표기한다.
