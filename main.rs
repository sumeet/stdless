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

#[no_mangle]
fn _start() {
    exit(2);
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}
