#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::mem;
use core::ptr;
use core::mem::MaybeUninit;

const SYS_EXIT: usize = 60;
const SYS_READ: usize = 0;
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

const SYS_FSTAT: usize = 5;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const MAX_PATH_LEN: usize = 256;

#[repr(C)]
struct linux_stat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    __unused: [i64; 3],
}

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
    print_str(b"Opening directory...\n");
    let dir = b".\0";
    let fd = unsafe {
        syscall(
            SYS_OPENAT,
            AT_FDCWD as usize,
            dir.as_ptr() as usize,
            O_RDONLY|O_NONBLOCK|O_CLOEXEC  // Removed O_DIRECTORY
        )
    };
    if fd > isize::MAX as usize {
        print_str(b"Error opening directory. Error code: ");
        print_isize(-(fd as isize));
        print_str(b"\n");
        exit(1);
    }

    print_str(b"File opened successfully. FD: ");
    print_usize(fd);
    print_str(b"\n");

    // Check file status
    let mut statbuf: MaybeUninit<linux_stat> = MaybeUninit::uninit();
    let fstat_result = unsafe {
        syscall(SYS_FSTAT, fd, statbuf.as_mut_ptr() as usize, 0)
    };
    if fstat_result > isize::MAX as usize {
        print_str(b"Error checking file status. Error code: ");
        print_isize(-(fstat_result as isize));
        print_str(b"\n");
        unsafe { syscall(SYS_CLOSE, fd, 0, 0); }
        exit(1);
    }
    
    let st_mode = unsafe { (*statbuf.as_ptr()).st_mode };
    print_str(b"File mode: ");
    print_usize(st_mode as usize);
    print_str(b"\n");

    // Check file status
    let mut statbuf: MaybeUninit<linux_stat> = MaybeUninit::uninit();
    let fstat_result = unsafe {
        syscall(SYS_FSTAT, fd, statbuf.as_mut_ptr() as usize, 0)
    };
    if fstat_result > isize::MAX as usize {
        print_str(b"Error checking file status. Error code: ");
        print_isize(-(fstat_result as isize));
        print_str(b"\n");
        unsafe { syscall(SYS_CLOSE, fd, 0, 0); }
        exit(1);
    }

    print_str(b"Reading directory entries...\n");

    const BUFFER_SIZE: usize = 1024;
    let mut buffer: [MaybeUninit<u8>; BUFFER_SIZE] = unsafe { MaybeUninit::uninit().assume_init() };

    let bytes_read = unsafe {
        syscall(
            SYS_GETDENTS64,
            fd,
            buffer.as_mut_ptr() as usize,
            BUFFER_SIZE
        )
    };

    print_str(b"Syscall return value: ");
    print_usize(bytes_read);
    print_str(b"\n");

    if bytes_read > isize::MAX as usize {
        print_str(b"Error reading directory. Error code: ");
        print_usize(!bytes_read + 1);
        print_str(b"\n");
    } else {
        print_str(b"Directory read successfully. Bytes read: ");
        print_usize(bytes_read);
        print_str(b"\n");

        // Process directory entries
        let buffer = unsafe { &*(buffer.as_ptr() as *const [u8; BUFFER_SIZE]) };
        let mut offset = 0;
        while offset < bytes_read {
            let dirent = unsafe { &*(buffer.as_ptr().add(offset) as *const linux_dirent64) };

            // Check if it's a regular file
            if dirent.d_type == 8 {
                let name_len = dirent.d_name.iter().position(|&c| c == 0).unwrap_or(256);
                let file_fd = unsafe {
                    syscall3(SYS_OPENAT, fd, dirent.d_name.as_ptr() as usize, O_RDWR)
                };

                if file_fd <= isize::MAX as usize {
                    let mut header = [0u8; 4];
                    let bytes_read = unsafe {
                        syscall3(SYS_READ, file_fd, header.as_mut_ptr() as usize, 4)
                    };
                    if bytes_read == 4 && header == ELF_MAGIC {
                        print_str(b"ELF file found: ");
                        print_str(&dirent.d_name[..name_len]);
                        print_str(b"\n");
                        // Here you can add your file writing logic
                    } 
                    unsafe { syscall1(SYS_CLOSE, file_fd); }
                }
            }

            offset += dirent.d_reclen as usize;
        }
    }

    // Close the directory
    unsafe {
        syscall(SYS_CLOSE, fd, 0, 0);
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

fn print_isize(mut n: isize) {
    if n == 0 {
        print_char(b'0');
        return;
    }

    if n < 0 {
        print_char(b'-');
        // Handle edge case of minimum isize value
        if n == isize::MIN {
            print_str(b"9223372036854775808");
            return;
        }
        n = -n;
    }

    // Convert to usize now that we've handled the negative case
    print_usize(n as usize);
}

fn print_usize(mut n: usize) {
    if n == 0 {
        return; // This case is handled in print_isize
    }

    let digits = b"0123456789";
    let mut digit_count = 0;
    let mut temp = n;

    // Count digits
    while temp > 0 {
        digit_count += 1;
        temp /= 10;
    }

    // Print digits from most significant to least
    while digit_count > 0 {
        digit_count -= 1;
        let digit = (n / 10_usize.pow(digit_count as u32)) % 10;
        print_char(digits[digit]);
    }
}

fn print_char(c: u8) {
    unsafe {
        syscall(SYS_WRITE, STDOUT, &c as *const u8 as usize, 1);
    }
}

fn print_str(s: &[u8]) {
    unsafe {
        syscall(SYS_WRITE, STDOUT, s.as_ptr() as usize, s.len());
    }
}

unsafe fn syscall1(n: usize, a1: usize) -> usize {
    let ret: usize;
    core::arch::asm!(
        "syscall",
        in("rax") n,
        in("rdi") a1,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
    );
    ret
}

unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let ret: usize;
    core::arch::asm!(
        "syscall",
        in("rax") n,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
    );
    ret
}