use crate::{
    function_table::{println, FunctionTable},
    utils::{hexdump, show_mem_hexdump},
};
use elf::{
    abi,
    endian::AnyEndian,
    relocation::Rela,
    section::{SectionHeader, SectionHeaderTable},
    string_table::StringTable,
    symbol::{Symbol, SymbolTable},
    ElfBytes,
};
use log::debug;
use nix::{
    errno::{errno, Errno::EACCES},
    libc::{malloc, memcmp, mprotect, strerror, PROT_EXEC, PROT_READ, PROT_WRITE},
};
use std::{any::Any, ffi::c_void, num::Wrapping, ptr, thread::sleep, time::Duration};

pub struct Coffee<'data> {
    elf: ElfBytes<'data, AnyEndian>,
    sections: Vec<SectionItem>,
    sh_table: SectionHeaderTable<'data, AnyEndian>, // section header table
    sh_strtab: StringTable<'data>,                  // section header string table
    strtab: StringTable<'data>,                     // string table
    symtab: SymbolTable<'data, AnyEndian>,          // symbol table
    pub(crate) func_table: FunctionTable,
}

pub struct SectionItem {
    pub start_address: usize,
    pub data: Vec<u8>,
    pub size: usize,

    pub name: String,
    pub rela: Vec<Rela>,
    pub hdr: SectionHeader,
}

impl<'data> Coffee<'data> {
    pub fn new(data: &'data [u8]) -> anyhow::Result<Self> {
        let elf = ElfBytes::<AnyEndian>::minimal_parse(data)?;

        let sym = elf.symbol_table()?;

        if sym.is_none() {
            anyhow::bail!("symbol table not found");
        }

        let (symtab, strtab) = sym.unwrap();

        let (shdrs, sh_strtab) = elf.section_headers_with_strtab()?;
        if shdrs.is_none() {
            anyhow::bail!("section header table not found");
        }

        if sh_strtab.is_none() {
            anyhow::bail!("section header string table not found");
        }

        Ok(Coffee {
            elf,
            sections: Vec::new(),
            sh_table: shdrs.unwrap(),
            sh_strtab: sh_strtab.unwrap(),
            strtab,
            symtab,
            func_table: FunctionTable::new(),
        })
    }

    pub fn map_data(&mut self) -> anyhow::Result<()> {
        for idx in 0..self.sh_table.len() {
            let section_header = self.sh_table.get(idx)?;
            let section_name = self.sh_strtab.get(section_header.sh_name as usize)?;

            if section_header.sh_size == 0 {
                self.sections.push(SectionItem {
                    start_address: 0 as _,
                    data: vec![],
                    size: section_header.sh_size as usize,
                    rela: Vec::new(),
                    name: section_name.to_string(),
                    hdr: section_header,
                });
                continue;
            }

            let (data, compress) = self.elf.section_data(&section_header)?;

            if let Some(compress) = compress {
                anyhow::bail!("compressed sections not supported: {:?}", compress);
            }

            let mut section_data = vec![0; section_header.sh_size as usize];

            section_data.copy_from_slice(&data);

            let start_address = section_data.as_ptr();

            // parse rela section

            debug!("map {} to {:p}", section_name, start_address);

            // println!("======origin========");
            // hexdump(&data);
            // println!("======memcpy========");
            // hexdump(unsafe {
            //     std::slice::from_raw_parts(ptr as *const u8, section_header.sh_size as usize)
            // });

            let mut rela = Vec::new();
            if let Some(rela_section_header) = self
                .elf
                .section_header_by_name(format!(".rela{}", section_name).as_str())?
            {
                let rela_section = self.elf.section_data_as_relas(&rela_section_header)?;
                for rela_item in rela_section {
                    rela.push(rela_item);
                }
            }

            self.sections.push(SectionItem {
                start_address: start_address as _,
                data: section_data,
                size: section_header.sh_size as usize,
                rela,
                name: section_name.to_string(),
                hdr: section_header,
            });
        }

        Ok(())
    }

    pub fn relo_symbols(&mut self) -> anyhow::Result<()> {
        for section in self.sections.iter() {
            if section.rela.is_empty() {
                continue;
            }
            debug!("relocating section: {}", section.name);
            for rela in section.rela.iter() {
                let sym = self.symtab.get(rela.r_sym as usize)?;
                let sym_name = self.strtab.get(sym.st_name as usize)?;
                let patch_addr = section.start_address + rela.r_offset as usize;
                let (sym_addr, sym_size) = self.get_symbol_addr(&sym)?;

                if sym.st_shndx == abi::SHN_UNDEF {
                    debug!(
                        "SHN_UNDEF symbol: sym_name:{} r_offset:{:x} r_addend:{} addr:{:x}, size:{}",
                        sym_name, rela.r_offset, rela.r_addend, sym_addr, sym_addr
                    );

                    match rela.r_type {
                        abi::R_X86_64_64 => {
                            let patch_value =
                                (Wrapping(sym_addr) - Wrapping(patch_addr) - Wrapping(4)).0;
                            unsafe {
                                ptr::write_unaligned(patch_addr as *mut u64, patch_value as u64);
                            }
                        }
                        abi::R_X86_64_PC32 | abi::R_X86_64_PLT32 => {
                            let patch_value =
                                (Wrapping(sym_addr) - Wrapping(patch_addr) - Wrapping(4)).0;

                            unsafe {
                                ptr::write_unaligned(patch_addr as *mut u32, patch_value as u32);
                            }
                        }
                        _ => {
                            anyhow::bail!("unsupported relocation type: {}", rela.r_type);
                        }
                    }
                } else {
                    let sym_section = self.sections.get(sym.st_shndx as usize).unwrap();
                    let sym_section_name = sym_section.name.as_str();

                    debug!(
                        "relo symbol: sym_name:{}, sym_section:{}, r_offset:{:x} r_addend:{}, addr:{:x}, size:{}",
                        sym_name, sym_section_name, rela.r_offset, rela.r_addend, sym_addr, sym_size
                    );

                    match rela.r_type {
                        abi::R_X86_64_64 => {
                            let patch_value = Wrapping(sym_addr) + Wrapping(rela.r_addend as usize);
                            unsafe {
                                ptr::write_unaligned(patch_addr as *mut u64, patch_value.0 as u64);
                            }
                        }
                        abi::R_X86_64_PC32 | abi::R_X86_64_PLT32 => {
                            let patch_value = Wrapping(sym_addr) + Wrapping(rela.r_addend as usize)
                                - Wrapping(patch_addr);

                            unsafe {
                                ptr::write_unaligned(patch_addr as *mut u32, patch_value.0 as u32);
                            }
                        }
                        _ => {
                            anyhow::bail!("unsupported relocation type: {}", rela.r_type);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn get_symbol_addr(&self, sym: &Symbol) -> anyhow::Result<(usize, usize)> {
        if sym.st_shndx == abi::SHN_UNDEF {
            Ok(self.load_symbol(self.strtab.get(sym.st_name as usize)?)?)
        } else {
            let section = self.sections.get(sym.st_shndx as usize).unwrap();
            let sym_addr = section.start_address as usize + sym.st_value as usize;
            Ok((sym_addr, sym.st_size as _))
        }
    }

    pub fn load_symbol(&self, name: &str) -> anyhow::Result<(usize, usize)> {
        if let Some(addr) = self.get_function(name) {
            Ok((addr as usize, 0))
        } else {
            Err(anyhow::anyhow!("symbol not found: {}", name))
        }
    }

    pub fn execute(&mut self) -> anyhow::Result<()> {
        for sym in self.symtab.iter() {
            if sym.st_symtype() != abi::STT_FUNC {
                continue;
            }
            let sym_name = self.strtab.get(sym.st_name as usize)?;
            if sym_name == "main" {
                let (addr, _) = self.get_symbol_addr(&sym)?;
                debug!("main function found: {:x}", addr);
                let section = self.sections.get(sym.st_shndx as usize).unwrap();
                let mprotet_start_addr = section.start_address - (section.start_address % 0x1000);
                let mprotect_size = section.start_address % 0x1000 + section.size;

                let res = unsafe {
                    mprotect(
                        mprotet_start_addr as _,
                        mprotect_size as _,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                    )
                };

                if res != 0 {
                    let err = unsafe {
                        std::ffi::CStr::from_ptr(strerror(errno()))
                            .to_string_lossy()
                            .into_owned()
                    };
                    anyhow::bail!("mprotect failed: {}", err);
                }

                debug!("mprotect ok");

                let func = unsafe { std::mem::transmute::<_, fn() -> u64>(addr) };

                // sleep(Duration::from_secs(2));
                let ret = func();
                let res = unsafe {
                    mprotect(
                        mprotet_start_addr as _,
                        mprotect_size as _,
                        PROT_READ | PROT_WRITE,
                    )
                };

                if res != 0 {
                    let err = unsafe {
                        std::ffi::CStr::from_ptr(strerror(errno()))
                            .to_string_lossy()
                            .into_owned()
                    };
                    anyhow::bail!("mprotect failed: {}", err);
                }

                debug!("main return: {:x}", ret);
                break;
            }
        }
        Ok(())
    }
}
