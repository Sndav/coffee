mod coffee;
mod function_table;
mod utils;

use crate::coffee::Coffee;
use elf::{
    abi,
    abi::{ET_REL, SHN_ABS, SHT_NULL},
    endian::AnyEndian,
    ElfBytes,
};
use log::debug;
use nix::libc::{malloc, memcmp};
use std::{ffi::c_void, fs, path::Path};

fn execute_obj(path: &str) -> anyhow::Result<()> {
    let obj_path = Path::new(path);
    let file_data = fs::read(obj_path)?;

    let mut coffee = Coffee::new(&file_data)?;
    coffee.register_functions();
    coffee.map_data()?;
    coffee.relo_symbols()?;
    coffee.execute()?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    simple_logger::SimpleLogger::new().env().init()?;
    execute_obj("/Users/sndav/Code/TinyShell/tinyloader/test.o")?;
    Ok(())

    // println!("Hello, world!");
}
