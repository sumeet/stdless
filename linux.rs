// linux syscalls layer

use core::arch::asm;
use core::mem::size_of;

type SocklenT = u32;
const AF_INET: i32 = 2;

pub fn read(fd: i32, buf: &mut [u8]) -> u32 {
    const SYSCALL_READ: u64 = 0;
    let res: i64;
    unsafe {
        //  ssize_t read(int fd, void *buf, size_t count);
        asm!(
        "syscall",
        inout("rax") SYSCALL_READ => res,
        // argument #1
        in("rdi") fd,
        // argument #2
        in("rsi") buf.as_ptr(),
        // argument #2
        in("rdx") buf.len(),
        )
    }

    if res < 0 {
        panic!("read failed");
    }
    res as u32
}

pub fn close(fd: i32) {
    const SYSCALL_CLOSE: u64 = 3;
    let res: i64;
    unsafe {
        // int close(int fd);
        asm!(
        "syscall",
        inout("rax") SYSCALL_CLOSE => res,
        // argument #1
        in("rdi") fd,
        )
    }

    if res < 0 {
        panic!("close failed");
    }
}

pub fn open(path: &[u8]) -> Option<i32> {
    // converting a rust string into a c string
    const BUFFER_SIZE: usize = 1024;
    let mut buffer: [u8; BUFFER_SIZE] = unsafe { core::mem::MaybeUninit::uninit().assume_init() };
    let path_bytes = path;
    if path_bytes.len() + 1 > BUFFER_SIZE {
        panic!("path is too long");
    }
    buffer[0..path_bytes.len()].copy_from_slice(path_bytes);
    buffer[path.len()] = 0;

    let fd: i32;
    let filepath_cstr = &buffer as *const u8;

    const SYSCALL_OPEN: i32 = 2;
    const O_RDONLY: i32 = 0;

    unsafe {
        // int open(char *file, int omode)
        asm!(
        "syscall",
        inout("rax") SYSCALL_OPEN => fd,
        // argument #1
        in("rdi") filepath_cstr,
        // argument #2
        in("rsi") O_RDONLY,
        )
    }

    if fd < 0 {
        None
    } else {
        Some(fd)
    }
}

// copilot wrote this struct, we can grab the size, not sure if it's even the correct size
// so maybe fstat is like writing into garbage memory because the struct isn't big enough
#[repr(C)]
pub struct Stat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u64,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    pub st_size: i64,
    st_blksize: u64,
    st_blocks: u64,
    st_atime: u64,
    st_atime_nsec: u64,
    st_mtime: u64,
    st_mtime_nsec: u64,
    st_ctime: u64,
    st_ctime_nsec: u64,
}

// fstat => 5
pub fn fstat(fd: i32) -> Stat {
    const SYSCALL_FSTAT: i32 = 5;
    let mut stat: Stat = Stat {
        st_dev: 0,
        st_ino: 0,
        st_mode: 0,
        st_nlink: 0,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atime: 0,
        st_atime_nsec: 0,
        st_mtime: 0,
        st_mtime_nsec: 0,
        st_ctime: 0,
        st_ctime_nsec: 0,
    };
    let mut res: i32;
    unsafe {
        // int fstat(int fd, struct stat *buf)
        asm!(
        "syscall",
        inout("rax") SYSCALL_FSTAT => res,
        // argument #1
        in("rdi") fd,
        // argument #2
        in("rsi") &mut stat as *mut Stat,
        )
    }

    if res < 0 {
        panic!("stat failed");
    }
    stat
}

pub fn accept(fd: i32) -> i32 {
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

pub fn bind(fd: i32, port: u16) {
    const SYSCALL_BIND: u64 = 49;
    let sockaddr_in = SockaddrIn {
        sin_family: AF_INET as _,
        sin_port: crate::htons(port),
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

pub fn listen(fd: i32) {
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
pub fn tcp_socket() -> i32 {
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

pub fn exit(code: u8) -> ! {
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

pub fn write(fd: i32, s: &[u8]) {
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

pub const STDOUT: i32 = 1;
