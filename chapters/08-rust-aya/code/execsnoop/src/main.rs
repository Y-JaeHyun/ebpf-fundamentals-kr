// SPDX-License-Identifier: MIT
//! 08장: Aya로 작성한 execsnoop 로더. 07장 Go 버전과 같은 동작을 한다.
//!
//!   execsnoop [-d 초] [-uid UID]
use std::time::Duration;

use anyhow::{Context as _, bail};
use aya::{
    EbpfLoader,
    maps::{PerCpuArray, RingBuf},
    programs::TracePoint,
};
use execsnoop_common::Event;
use tokio::{io::unix::AsyncFd, signal};

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // 인자: -d 초, -uid UID (의존성을 줄이려고 직접 파싱)
    let (mut secs, mut uid) = (0u64, u32::MAX);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let v = args.next().context("값이 빠졌다")?;
        match a.as_str() {
            "-d" => secs = v.parse()?,
            "-uid" => uid = v.parse()?,
            _ => bail!("사용법: execsnoop [-d 초] [-uid UID]"),
        }
    }

    // ① 로드: BPF 오브젝트는 build.rs가 빌드해 실행 파일 안에 넣어 두었다(Go의 go:embed와 같은 역할).
    //    override_global = cilium/ebpf의 Variables["..."].Set, libbpf의 skel->rodata->...
    let mut ebpf = EbpfLoader::new()
        .override_global("FILTER_UID", &uid, true)
        .load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/execsnoop")))?;

    // ② attach: 프로그램을 이름으로 꺼내 타입을 확정한 뒤 load(verifier) → attach
    let prog: &mut TracePoint = ebpf.program_mut("execsnoop").context("프로그램 없음")?.try_into()?;
    prog.load()?;
    let link = prog.attach("syscalls", "sys_enter_execve")?;

    // ③ ring buffer: fd를 tokio에 등록해 읽을 거리가 생기면 깨어난다
    let rb = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS 없음")?)?;
    // SAFETY: RingBuf가 map fd를 소유하고, AsyncFd가 살아 있는 동안 닫거나 바꾸지 않는다.
    let mut rb = unsafe { AsyncFd::register(rb) }.map_err(|e| e.into_parts().1)?;

    println!("{:<8} {:<6} {:<16} FILENAME", "PID", "UID", "COMM");
    // -d 0이면 시간 제한 없이 Ctrl-C까지
    let timeout = tokio::time::sleep(Duration::from_secs(secs));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = &mut timeout, if secs > 0 => break,
            guard = rb.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    // 크기를 확인한 뒤 Event로 읽는다(정렬이 맞지 않을 수 있어 read_unaligned)
                    if item.len() < size_of::<Event>() {
                        continue;
                    }
                    let e: Event = unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) };
                    println!("{:<8} {:<6} {:<16} {}", e.pid, e.uid, cstr(&e.comm), cstr(&e.filename));
                }
                guard.clear_ready();
            }
        }
    }

    // ④ 정리: 먼저 detach해 새 이벤트를 막고, 남은 이벤트를 마저 읽는다(06·07장과 같은 순서).
    //    ebpf가 drop될 때 나머지 fd도 모두 닫힌다.
    let prog: &mut TracePoint = ebpf.program_mut("execsnoop").context("프로그램 없음")?.try_into()?;
    prog.detach(link)?;
    {
        let rb = rb.get_mut();
        while let Some(item) = rb.next() {
            if item.len() >= size_of::<Event>() {
                let e: Event = unsafe { std::ptr::read_unaligned(item.as_ptr().cast()) };
                println!("{:<8} {:<6} {:<16} {}", e.pid, e.uid, cstr(&e.comm), cstr(&e.filename));
            }
        }
    }
    let stats = PerCpuArray::<_, u64>::try_from(ebpf.map("STATS").context("STATS 없음")?)?;
    let sum = |i: u32| -> anyhow::Result<u64> { Ok(stats.get(&i, 0)?.iter().sum()) };
    println!("보낸 이벤트 {}개, 유실 {}개", sum(0)?, sum(1)?);
    Ok(())
}
