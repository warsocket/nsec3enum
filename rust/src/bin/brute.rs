// use std::mem::transmute;
// use std::str::from_utf8;
// use std::str::from_utf8_unchecked;
// use std::cmp::max;
use std::io::{stdout, Write, BufWriter, Error, ErrorKind};
use std::fs::File;
use std::io::prelude::*;
use std::env;
use std::str;
use Extend;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Result;
use data_encoding::BASE32HEX_NOPAD;


#[derive(Serialize, Deserialize)]
struct Nsec3json {
    salt: String,
    iters: u16,
    domain: String,
    alg: u8,
    flags: u8,
    hashes: Vec<String>,
    count: usize,
    last: String
}

fn wire_prefix_fmt(input: &str) -> Vec<u8>{

    let mut domain:Vec<u8> = Vec::<u8>::new();
    for part in input.split("."){
        domain.push(part.len() as u8);
        for character in part.bytes(){
            domain.push(character as u8);
        }
    }
    
    domain
}

fn wire_fmt(input: &str) -> Vec<u8>{
    let mut domain = wire_prefix_fmt(input);
    domain.push(0);

    return domain
}



fn main() -> std::io::Result<()>{

    let ret = BASE32HEX_NOPAD.decode("00cc5c3k56vnqsjqidm83cjjhp41hss4".to_uppercase().as_bytes()).unwrap();
    let x:[u8;20] = (&ret[0..20]).try_into().unwrap();

    let map:HashMap::<[u8;20],&str>;



    // let string = str::from_utf8(&output).unwrap();
    println!("{:?}", ret.len());
    return Ok(());

    //parse argument 1
    let mut args_it = env::args();
    args_it.next();
    let json_file = args_it.next().ok_or(Error::new(ErrorKind::NotFound, "Json file not found"))?;

    let mut json_string = String::new();
    let mut file = File::open(json_file)?;
    file.read_to_string(&mut json_string)?;
    let obj:Nsec3json = serde_json::from_str(&json_string)?;
    // println!("{}", obj.count);

    //setup stuff
    let base_wire_domain = wire_fmt(&obj.domain);

    //now crack from stdin
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let mut wire_domain:Vec::<u8> = wire_prefix_fmt(&line.unwrap());
        wire_domain.extend(&base_wire_domain);

        // println!("{:?}", wire_domain);
    }


    Ok(())
}
// from_utf8_unchecked