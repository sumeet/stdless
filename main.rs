#![feature(lang_items)]
#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

fn exit(code: u8) -> ! {
    const SYSCALL_EXIT: u64 = 60;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYSCALL_EXIT,
            in("dil") code,
            options(noreturn)
        )
    }
}

fn print(s: &str) {
    const SYSCALL_WRITE: u64 = 1;
    const STDOUT: u64 = 1;
    let s = s.as_bytes();
    unsafe {
        asm!(
            "syscall",
            in("rax") SYSCALL_WRITE,
            in("rdi") STDOUT,
            in("rsi") s.as_ptr() as u64,
            in("rdx") s.len() as u64,
        )
    }
}

#[no_mangle]
fn _start() {
    print("Hello, world!");
    exit(0);
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}
