// SPDX-License-Identifier: MIT OR GPL-2.0
//! 08장: 07장 execsnoop.bpf.c를 Rust로 옮긴 BPF 프로그램.
#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, generated},
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use execsnoop_common::{Event, FILENAME_LEN, TASK_COMM_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// [0]=보낸 이벤트, [1]=ring buffer가 가득 차서 버린 이벤트
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

// C의 `const volatile u32 filter_uid`에 해당한다. 로더가 override_global로 값을 바꾼다.
// no_mangle: 심볼 이름을 그대로 남겨 로더가 이름으로 찾게 한다.
#[unsafe(no_mangle)]
static FILTER_UID: u32 = u32::MAX;

// sys_enter_execve 형식: 공통 필드 8바이트 + __syscall_nr(4) + 패딩(4) 뒤에 args[0](filename)
const FILENAME_PTR_OFFSET: usize = 16;

#[tracepoint]
pub fn execsnoop(ctx: TracePointContext) -> u32 {
    let _ = try_execsnoop(&ctx);
    0
}

fn try_execsnoop(ctx: &TracePointContext) -> Result<(), i64> {
    let uid = bpf_get_current_uid_gid() as u32;
    // read_volatile: 컴파일러가 u32::MAX로 상수 접기를 하지 못하게 한다(C의 volatile 역할)
    let filter = unsafe { core::ptr::read_volatile(&FILTER_UID) };
    if filter != u32::MAX && uid != filter {
        return Ok(());
    }

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump(1);
        return Ok(());
    };
    // reserve로 받은 메모리는 초기화되지 않은 MaybeUninit<Event>다.
    // 초기화 안 된 메모리에 &/&mut 참조를 만들면 Rust에서는 그것만으로 UB이므로,
    // 필드 주소는 &raw mut 로 원시 포인터만 얻어 helper에 넘기고 값도 포인터로 쓴다.
    let e = entry.as_mut_ptr();
    unsafe {
        (&raw mut (*e).pid).write((bpf_get_current_pid_tgid() >> 32) as u32);
        (&raw mut (*e).uid).write(uid);
        // 안전한 래퍼 bpf_get_current_comm()은 [u8; 16]을 값으로 돌려줘서 복사 코드가 붙는다.
        // C처럼 목적지 포인터를 넘기는 원시 helper를 쓰면 ring buffer 메모리에 바로 쓴다(README 참고).
        let comm = (&raw mut (*e).comm).cast::<u8>();
        if generated::bpf_get_current_comm(comm.cast(), TASK_COMM_LEN as u32) != 0 {
            comm.write(0);
        }
        let name = (&raw mut (*e).filename).cast::<u8>();
        let src = ctx.read_at::<u64>(FILENAME_PTR_OFFSET).unwrap_or(0) as *const c_void;
        if generated::bpf_probe_read_user_str(name.cast(), FILENAME_LEN as u32, src) < 0 {
            name.write(0);
        }
    }
    // 문자열 NUL 뒤의 바이트는 채우지 않는다. 사용자 공간은 NUL까지만 읽는다(07장 C 버전과 같음).
    entry.submit(0);
    bump(0);
    Ok(())
}

fn bump(idx: u32) {
    if let Some(v) = STATS.get_ptr_mut(idx) {
        unsafe { *v += 1 }; // per-CPU 값이라 원자 연산이 필요 없다
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
