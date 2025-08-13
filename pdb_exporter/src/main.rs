use pdb::{FallibleIterator, SymbolData, PDB};
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::fs::File;

#[derive(Serialize)]
struct Function {
    name: String,
    rva: u32,
    len: Option<u32>,
    type_index: Option<u32>,
}

#[derive(Serialize)]
struct GlobalVar {
    name: String,
    rva: u32,
    type_index: Option<u32>,
}

#[derive(Serialize)]
struct Output {
    pdb: String,
    functions: Vec<Function>,
    globals: Vec<GlobalVar>
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let pdb_path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: pdb_dump <file.pdb> [out.json]");
            std::process::exit(2);
        }
    };
    let out_path = args.next();

    let file = File::open(&pdb_path)?;
    let mut pdb = PDB::open(file)?;

    let address_map = pdb.address_map()?;
    let symbol_table = pdb.global_symbols()?;

    let mut funcs_by_rva: HashMap<u32, Function> = HashMap::new();
    let mut globals: Vec<GlobalVar> = Vec::new();

    let mut siter = symbol_table.iter();
    while let Some(sym) = siter.next()? {
        if let Ok(sd) = sym.parse() {
            match sd {
                SymbolData::Procedure(p) => {
                    if let Some(rva) = p.offset.to_rva(&address_map) {
                        funcs_by_rva.insert(
                            rva.0,
                            Function {
                                name: p.name.to_string().into_owned(),
                                rva: rva.0,
                                len: Some(p.len),
                                type_index: Some(p.type_index.0),
                            },
                        );
                    }
                }
                SymbolData::Public(p) if p.function => {
                    if let Some(rva) = p.offset.to_rva(&address_map) {
                        funcs_by_rva.entry(rva.0).or_insert(Function {
                            name: p.name.to_string().into_owned(),
                            rva: rva.0,
                            len: None,
                            type_index: None,
                        });
                    }
                }
                SymbolData::Public(p) if !p.function => {
                    if let Some(rva) = p.offset.to_rva(&address_map) {
                        globals.push(GlobalVar {
                            name: p.name.to_string().into_owned(),
                            rva: rva.0,
                            type_index: None,
                        });
                    }
                }
                SymbolData::Data(d) if d.global => {
                    if let Some(rva) = d.offset.to_rva(&address_map) {
                        globals.push(GlobalVar {
                            name: d.name.to_string().into_owned(),
                            rva: rva.0,
                            type_index: Some(d.type_index.0),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    let mut functions: Vec<Function> = funcs_by_rva.into_values().collect();
    functions.sort_by_key(|f| f.rva);
    globals.sort_by_key(|g| g.rva);

    let out = Output {
        pdb: pdb_path.clone(),
        functions,
        globals
    };

    let json = serde_json::to_string_pretty(&out)?;
    if let Some(p) = out_path {
        std::fs::write(p, json)?;
    } else {
        println!("{}", json);
    }
    Ok(())
}
