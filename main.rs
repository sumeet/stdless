#![feature(lang_items)]
#![feature(maybe_uninit_uninit_array)]
#![no_std]
#![no_main]

// Rust standard library (Vec, String, Everything you would want to use...)
// |-> no_std (Our project right now)
//      -> Kernel (directly through Syscalls) (Linux)
//         For a syscall, you dump arguments into registers
//         You dump a syscall NUMBER into the "RAX" register
//         Call the "syscall" instruction
// |
// |
// | std (not using this)
// -> libc (C standard library) communicate with the operating system and with the hardware
//        -> Kernel (Linux)
//   malloc,memcpy,memset

use core::panic::PanicInfo;
mod linux;
use linux::STDOUT;

const ROOT_INDEX: &'static [u8] = b"index.htm";

// LLVM depends on these functions, so we need these or else we get linker errors
#[no_mangle]
fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            *dest.add(i) = *src.add(i);
        }
    }
    dest
}

#[no_mangle]
fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            *s.add(i) = c as u8;
        }
    }
    s
}

fn write_num(fd: i32, mut num: usize) {
    if num == 0 {
        return linux::write(fd, &[b'0']);
    }
    const BUFFER_SIZE: usize = 10;
    let mut buffer: [u8; BUFFER_SIZE] = [0u8; BUFFER_SIZE];
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
    linux::write(fd, &buffer[i..BUFFER_SIZE]);
}

const NOT_FOUND_MSG: &[u8] = b"<marquee>404 Page Not Found</marquee>";

fn write_http_resp_from_filename(out_fd: i32, filename: &[u8]) {
    let fd = linux::open(filename);
    if fd.is_none() {
        write_http_resp_header(out_fd, 404, NOT_FOUND_MSG.len());
        linux::write(out_fd, NOT_FOUND_MSG);
        return;
    }

    let fd = fd.unwrap();
    let stats = linux::fstat(fd);
    write_http_resp_header(out_fd, 200, stats.st_size as _);

    let mut buf: [u8; 32] = [0u8; 32];
    loop {
        let bytes_read = linux::read(fd, &mut buf);
        if bytes_read > 0 {
            linux::write(out_fd, &buf[..bytes_read as _]);
        } else {
            break;
        }
    }
    linux::close(fd);
}

fn write_http_resp_header(fd: i32, code: usize, len: usize) {
    linux::write(fd, br#"HTTP/1.0 "#);
    write_num(fd, code);
    linux::write(
        fd,
        br#" OK
Content-type: text/html; charset=UTF-8
Content-Length: "#,
    );
    write_num(fd, len);
    linux::write(fd, b"\n\n");
}

fn extract_path_from_http_req(req: &[u8]) -> &[u8] {
    let mut i = 0;
    while req[i] != b' ' {
        i += 1;
    }

    #[allow(unused)]
    let request_method = &req[0..i];

    // skip the next char which is a space
    i += 1;

    // skip the leading / in the request, because that won't map to the filesystem
    if req[i] == b'/' {
        i += 1;
    }
    let start_of_path = i;
    while req[i] != b' ' && i < req.len() - 2 {
        i += 1;
    }
    &req[start_of_path..i]
}

#[no_mangle]
fn _start() {
    const PORT: u16 = 8080;
    print("Webserver listening on port ");
    write_num(STDOUT, PORT as _);
    print("...\n");

    let fd = linux::tcp_socket();
    linux::bind(fd, PORT);
    linux::listen(fd);
    // main web request loop
    loop {
        let conn_fd = linux::accept(fd);

        // parse the request
        const REQ_BUF_SIZE: usize = 1024;
        let mut req_buf: [u8; REQ_BUF_SIZE] =
            unsafe { core::mem::MaybeUninit::uninit().assume_init() };
        let num_bytes_read = linux::read(conn_fd, &mut req_buf);
        let req = &req_buf[..num_bytes_read as _];
        let requested_path = extract_path_from_http_req(req);

        linux::write(STDOUT, b"Read ");
        write_num(STDOUT, num_bytes_read as _);
        linux::write(STDOUT, b" bytes:\n");
        linux::write(STDOUT, &req_buf[..num_bytes_read as _]);
        // end of parse the request

        if requested_path.is_empty() {
            write_http_resp_from_filename(conn_fd, ROOT_INDEX);
        } else {
            write_http_resp_from_filename(conn_fd, requested_path);
        }
        print("Send response to client who connected\n");
    }
}

fn htons(port: u16) -> u16 {
    port.to_be()
}

fn print(s: &str) {
    linux::write(STDOUT, s.as_bytes());
}

#[panic_handler]
fn panic(panic_info: &PanicInfo<'_>) -> ! {
    // TODO: print out panic.location.file, line_number, etc.
    const STDERR: i32 = 2;
    linux::write(STDERR, b"\n\n\npanic! at ");
    match panic_info.location() {
        None => {}
        Some(loc) => {
            linux::write(STDERR, loc.file().as_bytes());
            linux::write(STDERR, b":");
            write_num(STDERR, loc.line() as _);
            linux::write(STDERR, b":");
            write_num(STDERR, loc.column() as _);
            linux::write(STDERR, b"\n");
        }
    }
    linux::exit(1);
}
