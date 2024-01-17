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

use sha1::{Digest, Sha1};

use serde::{Deserialize, Serialize};
use serde_json::Result;
use data_encoding::{BASE32HEX_NOPAD, HEXLOWER_PERMISSIVE};


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
    let salt = HEXLOWER_PERMISSIVE.decode(&obj.salt.as_bytes()).unwrap();
    let iters = obj.iters;

    //setup hash table
    let mut map:HashMap::<[u8;20],String> = HashMap::new();

    for base32_hash in obj.hashes{
        // println!("{}", base32_hash);
        map.insert( (BASE32HEX_NOPAD.decode(base32_hash.to_uppercase().as_bytes()).unwrap())[0..20].try_into().unwrap(), base32_hash);
    }

    //now crack from stdin
    let stdin = std::io::stdin();
    for wraped_line in stdin.lock().lines() {
        let subdomain = wraped_line.unwrap();
        let mut wire_domain:Vec::<u8> = wire_prefix_fmt(&subdomain);
        wire_domain.extend(&base_wire_domain);

        let mut result = {
            let mut hasher = Sha1::new();
            hasher.update(wire_prefix_fmt(&subdomain));
            hasher.update(&base_wire_domain);
            hasher.update(&salt);
            hasher.finalize()
        };

        for _ in 0..iters{
            let mut hasher = Sha1::new();
            hasher.update(&result);
            hasher.update(&salt);
            result = hasher.finalize();
        }
        
        if let Some(encoded_hash) = map.get::<[u8; 20]>(&result.try_into().unwrap()) {
            println!("{}\t{}.{}", *encoded_hash, subdomain, obj.domain);
        }

    }


    Ok(())
}
// from_utf8_unchecked