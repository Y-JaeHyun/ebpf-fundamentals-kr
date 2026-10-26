#!/bin/bash
# 08번용 부하: 닫힌 포트로 TCP 연결 시도 (실패해도 tcp_connect는 호출된다)
exec 3<>/dev/tcp/127.0.0.1/1 2>/dev/null || true
