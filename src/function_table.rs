use crate::coffee::Coffee;
use log::debug;
use std::{
    collections::HashMap,
    ffi::{c_char, c_void},
};

pub struct FunctionTable(HashMap<String, *const c_void>);

impl FunctionTable {
    pub fn new() -> Self {
        FunctionTable(HashMap::new())
    }

    pub fn add(&mut self, name: String, addr: *const c_void) {
        self.0.insert(name, addr);
    }

    pub fn get(&self, name: &str) -> Option<*const c_void> {
        self.0.get(name).copied()
    }
}

impl<'data> Coffee<'data> {
    pub fn register_function(&mut self, name: &str, addr: *const c_void) {
        self.func_table.add(name.to_string(), addr);
    }

    pub fn get_function(&self, name: &str) -> Option<*const c_void> {
        self.func_table.get(name)
    }

    pub fn register_functions(&mut self) {
        self.register_function("println", println as *const c_void);
        self.register_function("debugln", debugln as *const c_void);
    }
}

pub extern "C" fn debugln(inp: *const c_char) {
    let c_str = unsafe {
        assert!(!inp.is_null());
        std::ffi::CStr::from_ptr(inp)
    };
    debug!("{}", c_str.to_str().unwrap());
}

pub extern "C" fn println(inp: *const c_char) {
    let c_str = unsafe {
        assert!(!inp.is_null());
        std::ffi::CStr::from_ptr(inp)
    };
    println!("{}", c_str.to_str().unwrap());
}
