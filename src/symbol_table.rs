use crate::coffee::Coffee;
use std::{collections::HashMap, ffi::c_void};

pub struct CustomSymbolTable(HashMap<String, *const c_void>);

impl CustomSymbolTable {
    pub fn new() -> Self {
        CustomSymbolTable(HashMap::new())
    }

    pub fn add(&mut self, name: String, addr: *const c_void) {
        self.0.insert(name, addr);
    }

    pub fn get(&self, name: &str) -> Option<*const c_void> {
        self.0.get(name).copied()
    }
}

impl<'data> Coffee<'data> {
    pub fn register_symbol(&mut self, name: &str, addr: *const c_void) {
        self.symbol_table.add(name.to_string(), addr);
    }

    pub(crate) fn lookup_symbol(&self, name: &str) -> Option<*const c_void> {
        self.symbol_table.get(name)
    }
}
