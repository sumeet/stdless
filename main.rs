#![feature(lang_items)]
#![no_std]
#![no_main]

use core::arch::asm;
use core::mem::size_of;
use core::panic::PanicInfo;

const AF_INET: i32 = 2;

type SocklenT = u32;

const PAYLOAD: &'static str = r#"<marquee>Hello, Web!</marquee>"#;

fn write_num(fd: i32, mut num: usize) {
    if num == 0 {
        return write(fd, &[b'0']);
    }
    const BUFFER_SIZE: usize = 10;
    let mut buffer: [u8; BUFFER_SIZE] = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut i = BUFFER_SIZE;
    while num > 0 {
        if i == 0 {
            panic!("overflowed buffer for content length");
        } else {
            i -= 1;
        }

        let this_digit = (num % 10) as u8;
        num /= 10;
        buffer[i] = this_digit + b'0';
    }
    write(fd, &buffer[i..BUFFER_SIZE]);
}

fn write_http_resp_header(fd: i32, len: usize) {
    write(
        fd,
        br#"HTTP/1.0 200 OK
Content-type: text/html; charset=UTF-8
Content-Length: "#,
    );
    write_num(fd, len);
    write(fd, b"\n\n");
}

#[no_mangle]
fn _start() {
    print("Webserver listening on port 8080...\n");

    let fd = tcp_socket();
    bind(fd, 8080);
    listen(fd);
    loop {
        let conn_fd = accept(fd);
        write_http_resp_header(conn_fd, PAYLOAD.len());
        write(conn_fd, PAYLOAD.as_bytes());
        print("Send response to client who connected\n");
    }
}

fn accept(fd: i32) -> i32 {
    const SYSCALL_ACCEPT: i32 = 43;
    let sockaddr_in = SockaddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0, 0, 0, 0, 0, 0, 0, 0],
    };
    let sockaddr_in_ptr = &sockaddr_in as *const SockaddrIn;
    let sizeof_sockaddr_in = size_of::<SockaddrIn>() as SocklenT;
    let sizeof_sockaddr_in_ptr = &sizeof_sockaddr_in as *const SocklenT;
    let mut ret;
    unsafe {
        asm!(
            "syscall",
            inout("rax") SYSCALL_ACCEPT => ret,
            in("rdi") fd,
            in("rsi") sockaddr_in_ptr,
            in("rdx") sizeof_sockaddr_in_ptr,
        );
    }
    ret
}

fn htons(port: u16) -> u16 {
    unsafe { core::mem::transmute(port.to_be_bytes()) }
}

fn bind(fd: i32, port: u16) {
    const SYSCALL_BIND: u64 = 49;
    let sockaddr_in = SockaddrIn {
        sin_family: AF_INET as _,
        sin_port: htons(port),
        // listen on 0.0.0.0
        sin_addr: 0,
        // padding
        sin_zero: [0, 0, 0, 0, 0, 0, 0, 0],
    };
    let sockaddr_in_ptr = &sockaddr_in as *const SockaddrIn;
    let sizeof_sockaddr_in = size_of::<SockaddrIn>();
    unsafe {
        asm!(
            "syscall",
            in("rax") SYSCALL_BIND,
            in("rdi") fd,
            in("rsi") sockaddr_in_ptr,
            in("rdx") sizeof_sockaddr_in,
        )
    }
}

fn listen(fd: i32) {
    const SYSCALL_LISTEN: u64 = 50;
    let backlog: i32 = 0;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYSCALL_LISTEN,
            in("rdi") fd,
            in("rsi") backlog,
        )
    }
}

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    // to listen on all ports, zero this out
    sin_addr: u32,
    sin_zero: [u8; 8],
}

// returns a file descriptor
fn tcp_socket() -> i32 {
    const SYSCALL_SOCKET: i32 = 41;
    const SOCK_STREAM: i32 = 1;
    const TYPE: i32 = 0; // not sure if this is right yet
    let mut ret;
    unsafe {
        asm!(
        "syscall",
        inout("rax") SYSCALL_SOCKET => ret,
        in("rdi") AF_INET,
        in("rsi") SOCK_STREAM,
        in("rdx") TYPE,
        );
    }
    ret
}

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

fn write(fd: i32, s: &[u8]) {
    const SYSCALL_WRITE: u64 = 1;
    unsafe {
        asm!(
        "syscall",
        in("rax") SYSCALL_WRITE,
        // argument #1
        in("rdi") fd,
        // argument #2
        in("rsi") s.as_ptr() as u64,
        // argument #2
        in("rdx") s.len() as u64,
        )
    }
}

fn print(s: &str) {
    const STDOUT: i32 = 1;
    write(STDOUT, s.as_bytes());
}

#[panic_handler]
fn panic(panic_info: &PanicInfo<'_>) -> ! {
    // TODO: print out panic.location.file, line_number, etc.
    const STDERR: i32 = 2;
    write(STDERR, b"\n\n\npanic! at ");
    match panic_info.location() {
        None => {}
        Some(loc) => {
            write(STDERR, loc.file().as_bytes());
            write(STDERR, b":");
            write_num(STDERR, loc.line() as _);
            write(STDERR, b":");
            write_num(STDERR, loc.column() as _);
            write(STDERR, b"\n");
        }
    }
    exit(1);
}
