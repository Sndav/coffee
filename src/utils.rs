use std::ffi::c_void;

pub(crate) fn show_mem_hexdump(addr: *mut c_void, size: usize) -> anyhow::Result<()> {
    let arr = addr as *mut u8;
    for i in 0..size {
        print!("{:02x} ", unsafe { *arr.offset(i as isize) });
        if i % 16 == 0xf {
            println!();
        }
    }
    if size % 16 != 0 {
        println!();
    }
    Ok(())
}

pub(crate) fn hexdump(data: &[u8]) {
    let mut i = 0;
    while i < data.len() {
        print!("{:02x} ", data[i]);
        if i % 16 == 0xf {
            println!();
        }
        i += 1;
    }
}
