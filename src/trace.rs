use std::str::FromStr;
use structopt::*;

#[derive(Debug, PartialEq, StructOpt)]
pub enum TraceType {
    EBpf, STap
}

impl FromStr for TraceType {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ebpf" => Ok(TraceType::EBpf),
            "stap" => Ok(TraceType::STap),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
                                         "no such trace type"))
        }
    }
}

macro_rules! template {
    (STap) => {
r#"
probe process("{}").function("{}").call {{
    printf("probe: %s", ppfunc());
    print_usyms(ucallers(-1));
}}
"#
};
    (EBpf) => {
r#"
uprobe:{}:{} {{
    if (pid > 0) {{
        printf("probe: %s\n%s\n", probe, ustack(perf));
    }}
}}
"#
    };
}

pub type TraceTarget<'a> = Vec<(&'a str, &'a str, Vec<&'a str>)>;

pub fn generate_ebpf(target: &TraceTarget) -> String {
    target.iter()
        .map(|x : &(&str, &str, Vec<&str>)| {
            let mut temp = Vec::new();
            for i in &x.2 {
                temp.push(format!(template!(EBpf), x.1, i));
            }
            temp })
        .flatten()
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn generate_stap(target: &TraceTarget) -> String {
    target.iter()
        .map(|x : &(&str, &str, Vec<&str>)| {
            let mut temp = Vec::new();
            for i in &x.2 {
                temp.push(format!(template!(STap), x.1, i));
            }
            temp })
        .flatten()
        .collect::<Vec<_>>()
        .join("\n")
}



