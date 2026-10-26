// SPDX-License-Identifier: MIT
//! 커널(BPF)과 사용자 공간이 함께 쓰는 이벤트 구조체.
//! C에서 bpf2go -type 으로 맞추던 일을, 여기서는 같은 크레이트를 양쪽이 가져다 쓰는 것으로 해결한다.
#![no_std]

pub const TASK_COMM_LEN: usize = 16;
pub const FILENAME_LEN: usize = 128;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
}

// 사용자 공간에서 바이트를 그대로 이 타입으로 읽어도 된다는 표시 (패딩 없는 순수 데이터)
#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
