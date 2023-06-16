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
use log::{debug, info};
use nix::libc::{malloc, memcmp};
use std::{ffi::c_void, fs, path::Path};
use std::env::args;

pub extern "C" fn hello_world() {
    println!("Hello, world!");
}

fn execute_obj(path: &str) -> anyhow::Result<()> {
    info!("execute obj: {}", path);

    let obj_path = Path::new(path);
    let file_data = fs::read(obj_path)?;

    let mut coffee = Coffee::new(&file_data)?;
    coffee.register_functions();
    coffee.register_function("hello_world", hello_world as *const c_void);
    coffee.map_data()?;
    coffee.relo_symbols()?;
    coffee.execute()?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    simple_logger::SimpleLogger::new().env().init()?;
    let file_pah = args().nth(1).expect("no file path");
    execute_obj(&file_pah)?;
    Ok(())

}
