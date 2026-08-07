
use std::os::unix::io::RawFd;

// uapi statx is fixed at 256 bytes; any layout drift breaks the abi.
const _: () = assert!(std::mem::size_of::<Statx>() == 256);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    __statx_pad0: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    pub stx_subvol: u64,
    pub stx_atomic_write_unit_min: u32,
    pub stx_atomic_write_unit_max: u32,
    pub stx_atomic_write_segments_max: u32,
    pub stx_dio_read_offset_align: u32,
    pub stx_atomic_write_unit_max_opt: u32,
    __statx_pad2: u32,
    __statx_pad3: [u64; 8],
}

impl Statx {
    pub const STATX_BASIC_STATS: u32 = 0x0000_07ff;
    pub const STATX_ATTR_IMMUTABLE: u32 = 0x0000_0010;
    pub const STATX_ATTR_APPEND: u32 = 0x0000_0020;
    pub const STATX_ATTR_NODUMP: u32 = 0x0000_0040;
    pub const STATX_ATTR_MOUNT_ROOT: u32 = 0x0000_2000;
    pub const STATX_ATTR_MOUNT_POINT: u32 = 0x0000_4000;
}

/// call the `statx` syscall. returns 0 on success or -1 with `errno` set.
pub unsafe fn statx(
    dirfd: RawFd,
    path: *const libc::c_char,
    flags: libc::c_int,
    mask: u32,
    st: &mut Statx,
) -> libc::c_int {
    unsafe {
        libc::syscall(
            libc::SYS_statx,
            dirfd as libc::c_long,
            path,
            flags as libc::c_long,
            mask as libc::c_long,
            st as *mut Statx,
        ) as libc::c_int
    }
}
