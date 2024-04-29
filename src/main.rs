mod coffee;
mod symbol_table;
mod utils;

mod elf_const;

use crate::coffee::Coffee;

use log::{info};

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
    coffee.register_symbol("hello_world", hello_world as *const c_void);
    
    let args = vec![
        "coffee\0",
        "hello_world\0",
    ];
    coffee.execute(args)?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    simple_logger::SimpleLogger::new().env().init()?;
    let file_pah = args().nth(1);
    if file_pah.is_none() {
        println!("USAGE: coffee [obj file path]");
        return Ok(())
    }
    execute_obj(&file_pah.unwrap())?;
    Ok(())

}
