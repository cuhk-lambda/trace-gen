#![allow(dead_code)]
use serde::*;
#[derive(Debug, Serialize, Deserialize)]
pub struct Collection {
    pub objects: Vec<Object>,
    pub scripts: Vec<LinkScript>,
    pub compile: Vec<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkScript {
    pub abs_path: String,
    pub target: Target,
}
#[repr(transparent)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Object {
    pub abs_path: String,
    pub name: String,
    pub defined_symbols: Vec<Symbol>,
    pub undefined_symbols: Vec<Symbol>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Target {
    pub name: String,
    pub abs_path: String,
    pub dependencies: Vec<String>,
    // will changed later
    pub target_type: u8,
    pub linking_args: Vec<String>,
    pub ranlib_args: Vec<String>,
}

pub const EXEC: u8 = 0;
pub const SHARED: u8 = 1;
pub const STATIC: u8 = 2;