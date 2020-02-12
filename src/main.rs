use std::path::PathBuf;
use structopt::StructOpt;
use log::*;
use rayon::prelude::*;
use std::process::exit;
use serde::export::fmt::{Debug, Display};
use crate::cmaker::{Collection, LinkScript, STATIC, EXEC, Target, Object};
use hashbrown::HashMap;
use trace::*;

mod cmaker;
mod trace;

#[derive(StructOpt, Debug)]
#[structopt(name = "trace-gen")]
enum Opt {
    #[structopt(about = "generate trace file")]
    Gen {
        #[structopt(short, long, help = "name of the elf")]
        name: String,
        #[structopt(short, long, possible_values = &["stap", "ebpf"], help = "the type of trace file")]
        trace_type: TraceType,
        #[structopt(short, long,
            help = "path to the input file", env = "TRACE_INPUT_PATH", default_value = "./cmake.log")]
        input: PathBuf,
        #[structopt(short, long, help = "path to the output file")]
        output: PathBuf
    },
    #[structopt(about = "check the dependency tree of a specific ELF")]
    Check {
        #[structopt(short, long, help = "name of the elf")]
        name: String,
        #[structopt(short, long,
            help = "path to the input file", env = "TRACE_INPUT_PATH", default_value = "./cmake.log")]
        input: PathBuf,
    },
    #[structopt(about = "list all available ELFs")]
    List {
        #[structopt(short, long,
            help = "path to the input file", env = "TRACE_INPUT_PATH", default_value = "./cmake.log")]
        input: PathBuf,
    }
}

impl Opt {
    fn get_input(&self) -> &PathBuf {
        use Opt::*;
        match self {
            List {input} => input,
            Check { input, .. } => input,
            Gen { input, .. } => input
        }
    }
    fn get_collection(&self) -> Collection {
        let input = self.get_input();
        let mut content = std::fs::read_to_string(input)
            .unwrap_or_else(|e| failed_fast(e.to_string()));
        let collection =
            simd_json::serde::from_str::<Collection>(content.as_mut_str())
                .unwrap_or_else(|e|failed_fast(e.to_string()));
        collection
    }
}

fn failed_fast<T : Display>(msg: T) -> ! {
    error!("{}", msg);
    exit(1)
}

fn transform_deps<'a, 'b>(target: &'b Target, map: &'a HashMap<String, Target>, parallel: bool) -> Vec<&'a Target> {
    if parallel {
        target.dependencies
            .par_iter()
            .map(|x| { x.split("/").last().unwrap() })
            .filter(|x| x.contains(".so") || !x.ends_with(".a"))
            .filter(|x| map.contains_key(*x))
            .map(|x| map.get(x).unwrap())
            .collect()
    } else {
        target.dependencies
            .iter()
            .map(|x| { x.split("/").last().unwrap() })
            .filter(|x| x.contains(".so") || !x.ends_with(".a"))
            .filter(|x| map.contains_key(*x))
            .map(|x| map.get(x).unwrap())
            .collect()
    }
}

fn collect_all_deps<'a>(deps: &mut Vec<&'a Target>, map: &'a HashMap<String, Target>) {
    let mut counter = 0;
    while deps.len() > counter {
        let next = deps.len();
        let new_deps = deps[counter..deps.len()]
            .par_iter()
            .map(|x| transform_deps(x, map, false))
            .flatten()
            .collect::<Vec<_>>();
        deps.extend(new_deps.into_iter());
        counter = next;
    }
}

fn main() {
    use Opt::*;
    pretty_env_logger::env_logger::builder()
        .filter_level(LevelFilter::Trace)
        .init();
    let opt : Opt = Opt::from_args();
    let collection = opt.get_collection();
    info!("successfuly loaded {:?}", opt.get_input());
    match opt {
        List { .. } => {
            let res : Vec<LinkScript> = collection.scripts.into_par_iter().filter(|x : &LinkScript| {
                x.target.target_type < STATIC
            }).collect();
            for i in res {
                if i.target.target_type == EXEC {
                    info!("[EXEC] {}: {}", i.target.name, i.target.abs_path);
                } else {
                    info!("[DYNL] {}: {}", i.target.name, i.target.abs_path);
                }
            }
        }
        Check {name, .. } => {
            let map : HashMap<String, Target> = collection.scripts.into_par_iter().map(|x| (x.target.name.clone(), x.target))
                .collect();
            let target = match map.get(name.as_str()) {
                None => failed_fast(format!("target does not exists: {}", name)),
                Some(t) => t
            };
            info!("[TARGET] {}: {}", target.name, target.abs_path);
            info!("[DEPNDT] dependencies: {:#?}",
                transform_deps(target, &map, true).par_iter().map(|x| &x.abs_path).collect::<Vec<_>>());
        }
        Gen {name, trace_type, output, .. } => {
            let map : HashMap<String, Target> = collection.scripts.into_par_iter().map(|x| (x.target.name.clone(), x.target))
                .collect();
            let obj : HashMap<String, Object> = collection.objects.into_par_iter().map(|x| { (x.abs_path.clone(), x) })
                .collect();
            let target = match map.get(name.as_str()) {
                None => failed_fast(format!("target does not exists: {}", name)),
                Some(t) => t
            };
            let mut dependencies = transform_deps(target, &map, true);
            collect_all_deps(&mut dependencies, &map);
            dependencies.push(target);
            let symbols : Vec<_> = dependencies.par_iter().map(|x : &&Target | {
                (x.name.as_str(), x.abs_path.as_str(),
                    x.dependencies.iter()
                        .filter(|x| { x.ends_with(".o") })
                        .map(|x| obj.get(x).unwrap())
                        .map(|x| &x.defined_symbols)
                        .flatten()
                        .map(|x| x.name.as_str() )
                        .collect::<Vec<_>>()
                )
            }).collect();
            let res = match trace_type {
                TraceType::STap =>  generate_stap(&symbols),
                TraceType::EBpf => generate_ebpf(&symbols)
            };
            std::fs::write(&output, res)
                .unwrap_or_else(|e| failed_fast(e));
            info!("successfully saved to {:?}", &output);
        }
    }
}
