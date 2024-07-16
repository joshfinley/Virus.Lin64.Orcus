#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::mem;
use core::ptr;
use core::mem::MaybeUninit;

const SYS_EXIT: usize = 60;
const SYS_WRITE: usize = 1;
const SYS_OPEN: usize = 2;
const SYS_CLOSE: usize = 3;
const SYS_OPENAT: usize = 257;
const SYS_GETDENTS64: usize = 217;

const AT_FDCWD: isize = -100;
const O_RDONLY: usize = 0;
const O_RDWR: usize = 2;
const O_NONBLOCK: usize = 0x4000;
const O_DIRECTORY: usize = 0x200000;
const O_CLOEXEC: usize =   0x2000000;

const STDOUT: usize = 1;

#[repr(C)]
struct linux_dirent64 {
    d_ino: u64,        // Inode number
    d_off: i64,        // Offset to next dirent
    d_reclen: u16,     // Length of this record
    d_type: u8,        // Type of file
    d_name: [u8; 256], // Filename (null-terminated)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let dir = b".\0";  // Current directory
    let fd = unsafe {
        syscall(
            SYS_OPENAT,
            AT_FDCWD as usize,
            dir.as_ptr() as usize,
            O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC
        )
    };

    if fd < 0 {
        exit(1);
    }

    const BUFFER_SIZE: usize = 32768;
    let mut buffer: [MaybeUninit<u8>; BUFFER_SIZE] = unsafe { MaybeUninit::uninit().assume_init() };

    let bytes_read = unsafe {
        syscall(
            SYS_GETDENTS64,
            fd as usize,
            buffer.as_mut_ptr() as usize,
            BUFFER_SIZE
        )
    };

    if bytes_read < 0 {
        exit(2);
    }

    let buffer = unsafe { &*(buffer.as_ptr() as *const [u8; BUFFER_SIZE]) };

    let mut offset = 0;
    while offset < bytes_read as usize {
        let dirent = unsafe { &*(buffer.as_ptr().add(offset) as *const linux_dirent64) };
        
        let len = dirent.d_reclen as usize;
        if len == 0 {
            break;
        }

        // Print the filename
        let mut name_len = 0;
        while name_len < 256 && dirent.d_name[name_len] != 0 {
            name_len += 1;
        }

        unsafe {
            syscall(SYS_WRITE, STDOUT, dirent.d_name.as_ptr() as usize, name_len);
            syscall(SYS_WRITE, STDOUT, b"\n".as_ptr() as usize, 1);
        }

        offset += len;
    }

    unsafe {
        syscall(SYS_CLOSE, fd as usize, 0, 0);
    }

    exit(0);
}

#[inline(always)]
unsafe fn syscall(id: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let ret: usize;
    core::arch::asm!(
        "syscall",
        in("rax") id,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        lateout("rax") ret,
    );
    ret
}

#[inline(always)]
fn exit(code: usize) -> ! {
    unsafe {
        syscall(SYS_EXIT, code, 0, 0);
    }
    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
