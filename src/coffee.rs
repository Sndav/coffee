use std::collections::HashMap;
use std::mem::size_of;
use std::{env, ffi::c_void, ptr};

use anyhow::bail;
use elf::abi::{
    R_ARM_CALL, R_ARM_JUMP24, SHN_UNDEF, SHT_LOPROC, SHT_NOBITS, SHT_PROGBITS,
    SHT_REL, SHT_RELA,
};
use elf::relocation::Rel;
use elf::{
    abi,
    endian::AnyEndian,
    relocation::Rela,
    section::{SectionHeader, SectionHeaderTable},
    string_table::StringTable,
    symbol::SymbolTable,
    ElfBytes,
};
use libc::{c_char, mmap};
use log::debug;
use nix::errno::Errno;
use nix::libc::{PROT_EXEC, PROT_READ, PROT_WRITE};

use crate::elf_const::R_386_GOTOFF;
use crate::{elf_const, symbol_table::CustomSymbolTable};

const MAX_NUM_EXTERNAL_FUNCTIONS: usize = 256;
const PAGE_SIZE: usize = 4096;
const MAX_SECTION_SIZE: usize = 8 * PAGE_SIZE;

type GoFunc = extern "C" fn(argc: i32, argv: *const *const c_char) -> i32;

pub struct Coffee<'data> {
    elf: ElfBytes<'data, AnyEndian>,

    mem_pool: *mut c_void,
    map_offset: usize,

    sections: Vec<SectionItem>,
    sh_table: SectionHeaderTable<'data, AnyEndian>,
    // section header table
    sh_strtab: StringTable<'data>,
    // section header string table
    strtab: StringTable<'data>,
    // string table
    symtab: SymbolTable<'data, AnyEndian>,
    // symbol table
    pub(crate) symbol_table: CustomSymbolTable,


    got_table: HashMap<usize, u32>,
    // GOT table
    got_ptr: usize, // GOT table start address

    libc_handle: *mut c_void,
}

#[derive(Clone)]
pub enum Reloc {
    Rela(Rela),
    Rel(Rel),
}

impl Reloc {
    pub fn r_offset(&self) -> usize {
        match self {
            Reloc::Rela(reloc) => reloc.r_offset as usize,
            Reloc::Rel(reloc) => reloc.r_offset as usize,
        }
    }

    pub fn r_sym(&self) -> usize {
        match self {
            Reloc::Rela(reloc) => reloc.r_sym as usize,
            Reloc::Rel(reloc) => reloc.r_sym as usize,
        }
    }

    pub fn r_type(&self) -> u32 {
        match self {
            Reloc::Rela(reloc) => reloc.r_type as _,
            Reloc::Rel(reloc) => reloc.r_type as _,
        }
    }

    pub fn r_addend(&self, ptr: usize) -> isize {
        match self {
            Reloc::Rela(reloc) => reloc.r_addend as isize,
            Reloc::Rel(_) => {
                let addend = unsafe { ptr::read(ptr as *const isize) };
                addend
            }
        }
    }
}

#[derive(Clone)]
pub struct SectionItem {
    pub start_address: usize,
    pub size: usize,

    pub name: String,
    pub reloc_header: SectionHeader,
    pub reloc: Vec<Reloc>,
    pub hdr: SectionHeader,
}

impl Default for SectionItem {
    fn default() -> Self {
        Self {
            start_address: 0,
            size: 0,
            name: "".to_string(),
            reloc_header: SectionHeader {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
            reloc: vec![],
            hdr: SectionHeader {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
        }
    }
}

impl SectionItem {
    pub fn add_rela(&mut self, reloc: Rela) {
        self.reloc.push(Reloc::Rela(reloc));
    }

    pub fn add_rel(&mut self, reloc: Rel) {
        self.reloc.push(Reloc::Rel(reloc));
    }
}

impl<'data> Coffee<'data> {
    pub fn new(data: &'data [u8]) -> anyhow::Result<Self> {
        let elf = ElfBytes::<AnyEndian>::minimal_parse(data)?;

        let sym = elf.symbol_table()?;

        if sym.is_none() {
            bail!("symbol table not found");
        }

        let (symtab, strtab) = sym.unwrap();

        let (shdrs, sh_strtab) = elf.section_headers_with_strtab()?;
        if shdrs.is_none() {
            bail!("section header table not found");
        }

        let shdrs = shdrs.unwrap();

        if sh_strtab.is_none() {
            bail!("section header string table not found");
        }

        let sh_strtab = sh_strtab.unwrap();

        let mem_pool = unsafe {
            mmap(
                std::ptr::null_mut(),
                MAX_SECTION_SIZE * (1 + shdrs.len()), // need page for got
                PROT_READ | PROT_WRITE | PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if mem_pool == libc::MAP_FAILED {
            bail!("mmap failed: {}", Errno::last());
        }

        debug!("Memory Pool: {:p}", mem_pool);

        Ok(Coffee {
            elf,
            sections: Vec::new(),
            sh_table: shdrs,
            sh_strtab,
            strtab,
            symtab,

            mem_pool,
            got_ptr: mem_pool as usize,
            got_table: HashMap::new(),
            map_offset: MAX_SECTION_SIZE,

            symbol_table: CustomSymbolTable::new(),
            libc_handle: unsafe { libc::dlopen("libc.so.6\x00".as_ptr() as _, libc::RTLD_LAZY) },
        })
    }

    fn alloc_from_pool(&mut self, size: usize) -> *mut c_void {
        let addr = self.mem_pool as usize + self.map_offset;
        self.map_offset += size;
        addr as *mut c_void
    }

    fn get_got_func_ptr(&mut self, func_ptr: usize) -> anyhow::Result<u32> {
        let got_entry = match self.got_table.get(&func_ptr) {
            Some(got_entry) => *got_entry,
            None => {

                let got_entry = self.got_table.len() as u32;
                if got_entry >= MAX_NUM_EXTERNAL_FUNCTIONS as u32 {
                    bail!("too many external functions");
                }
                self.got_table.insert(func_ptr, got_entry);

                let got_offset = got_entry as usize * size_of::<usize>();
                let got_entry_addr = self.got_ptr + got_offset;

                unsafe {
                    ptr::write_unaligned(got_entry_addr as *mut usize, func_ptr);
                }

                got_entry
            }
        };
        Ok(got_entry)
    }


    fn map_data(&mut self) -> anyhow::Result<()> {
        debug!("Number of Sections: {}", self.sh_table.len());

        for idx in 0..self.sh_table.len() {
            debug!("Section Index: {}", idx);
            let mut section_item = SectionItem::default();

            let section_header = self.sh_table.get(idx)?;
            let section_name = self.sh_strtab.get(section_header.sh_name as usize)?;

            section_item.size = section_header.sh_size as usize;
            section_item.name = section_name.to_string();
            section_item.hdr = section_header.clone();

            debug!("\tName: {}", section_name);
            debug!("\tType: 0x{:x}", section_header.sh_type);
            debug!("\tFlags: 0x{:x}", section_header.sh_flags);
            debug!("\tSize: 0x{:x}", section_header.sh_size);
            debug!("\tEntSize: {}", section_header.sh_entsize);
            debug!("\tOffset: 0x{:x}", section_header.sh_offset);
            debug!("\tAddr: 0x{:x}", section_header.sh_addr);
            debug!("\tLink: {}", section_header.sh_link);
            debug!("\tInfo: {}", section_header.sh_info);

            let (data, compress) = self.elf.section_data(&section_header)?;

            if let Some(compress) = compress {
                bail!("compressed sections not supported: {:?}", compress);
            }

            if (section_header.sh_type == SHT_PROGBITS
                || section_header.sh_type == SHT_NOBITS
                || section_header.sh_type == (SHT_PROGBITS | SHT_LOPROC))
                && section_header.sh_size > 0
            {
                let section_data_ptr =
                    self.alloc_from_pool(section_header.sh_size as usize) as *mut u8;

                unsafe {
                    ptr::copy_nonoverlapping(
                        data.as_ptr(),
                        section_data_ptr,
                        section_header.sh_size as usize,
                    );
                }

                debug!("\tMap {} to {:p}", section_name, section_data_ptr);
                section_item.start_address = section_data_ptr as _;
            }
            self.sections.push(section_item);
        }

        let sht_rel_type = if size_of::<usize>() == 8 {
            SHT_RELA
        } else {
            SHT_REL
        };

        debug!("Parse Relocation Section Type: 0x{:x}", sht_rel_type);
        debug!("Number of Sections: {}", self.sh_table.len());
        for idx in 0..self.sh_table.len() {
            let section_header = self.sh_table.get(idx)?;
            let section_name = self.sh_strtab.get(section_header.sh_name as usize)?;

            if section_header.sh_type == SHT_RELA {
                debug!("Section Type: SHT_RELA")
            } else if section_header.sh_type == SHT_REL {
                debug!("Section Type: SHT_REL")
            }

            if section_header.sh_type == sht_rel_type {
                let origin_section = match self.sections.get_mut(section_header.sh_info as usize) {
                    Some(section) => section,
                    None => bail!("reloc section not found: {}", section_name),
                };
                origin_section.reloc_header = section_header.clone();

                debug!(
                    "ENTRIES (Section: {}) for {}",
                    section_name, origin_section.name
                );

                if sht_rel_type == SHT_RELA {
                    let relocs = self.elf.section_data_as_relas(&section_header)?;
                    for reloc in relocs {
                        let sym = self.symtab.get(reloc.r_sym as usize)?;
                        let sym_name = self.strtab.get(sym.st_name as usize)?;

                        debug!(
                            "\tAdd Rela: {} r_offset:{:x} r_addend:{} r_sym:{} r_type:{}",
                            sym_name, reloc.r_offset, reloc.r_addend, reloc.r_sym, reloc.r_type
                        );
                        origin_section.add_rela(reloc);
                    }
                } else if sht_rel_type == SHT_REL {
                    let relocs = self.elf.section_data_as_rels(&section_header)?;
                    for reloc in relocs {
                        let sym = self.symtab.get(reloc.r_sym as usize)?;
                        let sym_name = self.strtab.get(sym.st_name as usize)?;

                        debug!(
                            "\tAdd Rel: {} r_offset:{:x} r_sym:{} r_type:{}",
                            sym_name, reloc.r_offset, reloc.r_sym, reloc.r_type
                        );

                        origin_section.add_rel(reloc);
                    }
                }
            }
        }

        Ok(())
    }

    fn reloc_symbols(&mut self) -> anyhow::Result<()> {
        let sections = self.sections.clone();
        for section in sections.iter() {
            if section.reloc.is_empty() {
                continue;
            }
            debug!("Relocating Section: {}", section.name);
            for reloc in section.reloc.iter() {
                let sym = self.symtab.get(reloc.r_sym())?;
                let addr_p = section.start_address + reloc.r_offset();
                let st_shndx_section = self.sections.get(sym.st_shndx as usize).unwrap();
                let addend = reloc.r_addend(addr_p);
                let sym_name = self.strtab.get(sym.st_name as usize)?;
                let r_type = reloc.r_type();
                let mut addr_s = st_shndx_section.start_address + sym.st_value as usize;
                let got_entry;
                let mut got_entry_addr = 0;

                debug!("Relocating Symbol: {}", sym_name);
                debug!("\tSymbol Address: {:x}", addr_s);
                debug!("\tSymbol Section: {}", sym.st_shndx);
                debug!("\tRelocation Address: {:x}", addr_p);
                debug!("\tAddend: {}", addend);
                debug!("\tOffset: {}", reloc.r_offset());
                debug!("\tType: {}", r_type);

                // Undefined symbol
                if sym.st_shndx == SHN_UNDEF {
                    debug!("\tMode: External Function");
                    let func_ptr = self.load_external_symbol(sym_name)?;
                    debug!("\t\tFunction Address: {:x}", func_ptr);

                    // Map function address to GOT and PLT
                    got_entry = self.get_got_func_ptr(func_ptr)?;
                    got_entry_addr = self.got_ptr + (got_entry as usize * size_of::<usize>());

                    debug!("\t\tGOT Entry: {:x}", got_entry);
                    debug!("\t\tGOT Entry Address: {:x}", got_entry_addr);

                    addr_s = func_ptr;
                }

                if env::consts::ARCH == "aarch64" {
                    debug!("\tMode: AARCH64 SHF_INFO_LINK");
                    match r_type {
                        abi::R_AARCH64_ADR_PREL_PG_HI21 => {
                            debug!("\tMode: R_AARCH64_ADR_PREL_PG_HI21");
                            let s_plus_a_page = (addr_s as i64 + addend as i64) & !0xfff;
                            let p_page = (addr_p as i64) & !0xfff;

                            let pc_offset_21 =
                                ((s_plus_a_page - p_page) & 0x0000_0001_ffff_f000) >> 12;
                            let pc_offset_19_hi =
                                ((pc_offset_21 & 0x0000_0000_001f_fffc) as u32) << 3;
                            let pc_offset_2_lo =
                                ((pc_offset_21 & 0x0000_0000_0000_0003) as u32) << 29;

                            let mut encoding = unsafe { ptr::read_unaligned(addr_p as *const u32) };
                            encoding = encoding | pc_offset_19_hi | pc_offset_2_lo;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut u32, encoding);
                            }
                        }
                        abi::R_AARCH64_ADD_ABS_LO12_NC => {
                            debug!("\tMode: R_AARCH64_ADD_ABS_LO12_NC");
                            let s_plus_a = (addr_s as i64) + addend as i64;
                            let imm = ((s_plus_a & 0xfff) as u32) << 10;

                            let mut encoding = unsafe { ptr::read_unaligned(addr_p as *const u32) };
                            encoding |= imm;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut u32, encoding);
                            }
                        }
                        abi::R_AARCH64_CALL26 | abi::R_AARCH64_JUMP26 => {
                            debug!("\tMode: R_AARCH64_CALL26 | R_AARCH64_JUMP26");
                            let offset = ((addr_s as isize + addend - addr_p as isize)
                                as i32
                                & 0x0fff_ffff)
                                >> 2;
                            let val = if r_type == abi::R_AARCH64_CALL26 {
                                0x94000000 | offset as u32
                            } else {
                                0x14000000 | offset as u32
                            };

                            let target_addr = addr_p as *mut u32;
                            unsafe {
                                ptr::write_unaligned(target_addr, val);
                            }
                        }
                        abi::R_AARCH64_ABS64 => {
                            debug!("\tMode: R_AARCH64_ABS64");
                            let relative_offset = (addr_s as i64) + addend as i64;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut i64, relative_offset);
                            }
                        }
                        abi::R_AARCH64_PREL32 => {
                            debug!("\tMode: R_AARCH64_PREL32");
                            let relative_offset =
                                ((addr_s as i64) + addend as i64 - addr_p as i64) as i32;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut i32, relative_offset);
                            }
                        }
                        abi::R_AARCH64_LDST8_ABS_LO12_NC => {
                            debug!("\tMode: R_AARCH64_LDST8_ABS_LO12_NC");
                            let s_plus_a = (addr_s as i64) + addend as i64;
                            let imm = ((s_plus_a & 0xfff) as u32) << 10;

                            let mut encoding = unsafe { ptr::read_unaligned(addr_p as *const u32) };
                            encoding |= imm;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut u32, encoding);
                            }
                        }
                        abi::R_AARCH64_LDST16_ABS_LO12_NC => {
                            debug!("\tMode: R_AARCH64_LDST16_ABS_LO12_NC");
                            let s_plus_a = (addr_s as i64) + addend as i64;
                            let imm = ((s_plus_a & 0xffe) as u32) << 9;

                            let mut encoding = unsafe { ptr::read_unaligned(addr_p as *const u32) };
                            encoding |= imm;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut u32, encoding);
                            }
                        }
                        abi::R_AARCH64_LDST32_ABS_LO12_NC => {
                            debug!("\tMode: R_AARCH64_LDST32_ABS_LO12_NC");
                            let s_plus_a = (addr_s as i64) + addend as i64;
                            let imm = ((s_plus_a & 0xffc) as u32) << 8;

                            let mut encoding = unsafe { ptr::read_unaligned(addr_p as *const u32) };
                            encoding |= imm;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut u32, encoding);
                            }
                        }
                        abi::R_AARCH64_LDST64_ABS_LO12_NC => {
                            debug!("\tMode: R_AARCH64_LDST64_ABS_LO12_NC");
                            let s_plus_a = (addr_s as i64) + addend as i64;
                            let imm = ((s_plus_a & 0xff8) as u32) << 7;

                            let mut encoding = unsafe { ptr::read_unaligned(addr_p as *const u32) };
                            encoding |= imm;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut u32, encoding);
                            }
                        }
                        abi::R_AARCH64_LDST128_ABS_LO12_NC => {
                            debug!("\tMode: R_AARCH64_LDST128_ABS_LO12_NC");
                            let s_plus_a = (addr_s as i64) + addend as i64;
                            let imm = ((s_plus_a & 0xff0) as u32) << 6;

                            let mut encoding = unsafe { ptr::read_unaligned(addr_p as *const u32) };
                            encoding |= imm;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut u32, encoding);
                            }
                        }
                        _ => {
                            bail!("unsupported relocation type: {}", r_type);
                        }
                    }
                } else if env::consts::ARCH == "arm" {
                    match r_type {
                        abi::R_ARM_REL32 => {
                            debug!("\tMode: R_ARM_REL32");
                            let relative_offset =
                                (addr_s as i64 + addend as i64 - addr_p as i64) as i32;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut i32, relative_offset);
                            }
                        }
                        abi::R_ARM_ABS32 => {
                            debug!("\tMode: R_ARM_ABS32");
                            let relative_offset = (addr_s as i64 + addend as i64) as i32;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut i32, relative_offset);
                            }
                        }
                        R_ARM_CALL | R_ARM_JUMP24 => {
                            debug!("\tMode: R_ARM_CALL | R_ARM_JUMP24");
                            let encoding = unsafe { ptr::read_unaligned(addr_p as *const i32) };

                            let a = encoding & 0x00_ff_ff_ff << 2;

                            let relative_offset =
                                ((addr_s as i64 + a as i64 - addr_p as i64) as i32) & 0x03ff_fffe;

                            let opcode = if reloc.r_type() == abi::R_ARM_CALL {
                                0xeb000000
                            } else {
                                0xea000000
                            };

                            let new_encoding = opcode | ((relative_offset >> 2) as u32);
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut u32, new_encoding);
                            }
                        }
                        abi::R_ARM_PREL31 => {
                            debug!("\tMode: R_ARM_PREL31");
                            todo!("R_ARM_PREL31")
                        }
                        _ => {
                            bail!("unsupported relocation type: {}", r_type);
                        }
                    }
                } else if env::consts::ARCH == "x86_64" {
                    match r_type {
                        abi::R_X86_64_64 => {
                            debug!("\tMode: R_X86_64_64");
                            let addr = (addr_s as u64).wrapping_add(addend as u64);
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut usize, addr as usize);
                            }
                        }
                        abi::R_X86_64_PC32 | abi::R_X86_64_PLT32 => {
                            debug!("\tMode: R_X86_64_PC32 | R_X86_64_PLT32");
                            let relative_offset =
                                (addr_s as i64 + addend as i64 - addr_p as i64) as i32;

                            debug!("\t\trelative_offset: {:x}", relative_offset);

                            unsafe {
                                ptr::write_unaligned(addr_p as *mut i32, relative_offset);
                            }
                        }
                        abi::R_X86_64_GOTPCREL => {
                            debug!("\tMode: R_X86_64_GOTPCREL");
                            let relative_offset =
                                (got_entry_addr as isize + addend - addr_p as isize) as i32;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut i32, relative_offset);
                            }
                        }
                        _ => {
                            bail!("unsupported relocation type: {}", r_type);
                        }
                    }
                } else if env::consts::ARCH == "x86" {
                    match r_type {
                        elf_const::R_386_32 => {
                            debug!("\tMode: R_386_32");
                            let addr = (addr_s as u64).wrapping_add(addend as u64);
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut usize, addr as usize);
                            }
                        }
                        R_386_GOTOFF => {
                            // R_386_GOTOFF
                            // S + A – GOT
                            debug!("\tMode: R_386_GOTOFF");
                            let relative_offset =
                                (addr_s as i64 + addend as i64 - self.got_ptr as i64) as i32;
                            unsafe {
                                ptr::write_unaligned(addr_p as *mut i32, relative_offset);
                            }
                        }
                        _ => {
                            bail!("unsupported relocation type: {}", r_type);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn load_external_symbol(&self, name: &str) -> anyhow::Result<usize> {
        if let Some(addr) = self.lookup_symbol(name) {
            Ok(addr as usize)
        } else {
            // fallback to libc
            let sym = unsafe { libc::dlsym(self.libc_handle, name.as_ptr() as _) };
            if sym.is_null() {
                bail!("symbol not found: {}", name);
            }
            Ok(sym as usize)
        }
    }

    pub fn execute(&mut self, args: Vec<&str>) -> anyhow::Result<()> {
        self.map_data()?;
        self.reloc_symbols()?;

        for sym in self.symtab.iter() {
            if sym.st_symtype() != abi::STT_FUNC {
                continue;
            }
            let sym_name = self.strtab.get(sym.st_name as usize)?;
            debug!("Symbol: {}", sym_name);
            if sym_name == "go" {
                let section = self.sections.get(sym.st_shndx as usize).unwrap();
                let addr = section.start_address + sym.st_value as usize;

                debug!("go function found: {:x}", addr);
                let _section = self.sections.get(sym.st_shndx as usize).unwrap();

                let func: GoFunc = unsafe { std::mem::transmute(addr) };

                let mut argv = Vec::new();
                argv.push("coffee\0".as_ptr() as *const c_char);

                for arg in args.iter() {
                    argv.push(arg.as_ptr() as *const c_char);
                }

                // sleep(Duration::from_secs(2));
                let ret = func(argv.len() as i32, argv.as_ptr());

                debug!("main return: {:x}", ret);
                break;
            }
        }
        Ok(())
    }
}
