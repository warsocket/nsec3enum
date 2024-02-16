use std::mem::transmute;
use std::str::from_utf8;
use std::str::from_utf8_unchecked;
use std::io::{stdout, Write, BufWriter, Error, ErrorKind};
use std::fs::File;
use std::io::prelude::*;
use std::env;


use sha1::{Digest, Sha1};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Result;
use data_encoding::{BASE32HEX_NOPAD, HEXLOWER_PERMISSIVE};

use std::thread;
use std::thread::JoinHandle;

// list(map(chr, range(97,123))) + list(map(str, range(10)))
type Alphabet = [u8;26+10+1];

fn mk_alphabet() -> Alphabet{

    let mut index = 0;
    let mut ret:Alphabet = [0;26+10+1]; //items and terminator 00 byte

    for i in 97u8..123u8{ // add a-z
        ret[index] = i;
        index += 1;        
    }

    for i in 48u8..58u8{ // add 0-9
        ret[index] = i;
        index += 1;        
    }

    ret[index] = 45; //add -

    return ret
}


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

fn crack(map:&HashMap::<[u8;20],String>, subdomain:&str, base_wire_domain:&[u8], salt:&Vec<u8>, iters:&u16){

    let mut wire_domain:Vec::<u8> = wire_prefix_fmt(&subdomain);
    wire_domain.extend(base_wire_domain);

    let mut result = {
        let mut hasher = Sha1::new();
        hasher.update(wire_prefix_fmt(&subdomain));
        hasher.update(&base_wire_domain);
        hasher.update(&salt);
        hasher.finalize()
    };

    for _ in 0..*iters{
        let mut hasher = Sha1::new();
        hasher.update(&result);
        hasher.update(&salt);
        result = hasher.finalize();
    }
    
    if let Some(encoded_hash) = map.get::<[u8; 20]>(&result.try_into().unwrap()) {
        println!("{}\t{}.todo", *encoded_hash, subdomain);
    }

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




    let alphabet:Alphabet = mk_alphabet();
    let alphabet_no_dash = &alphabet[0..36];
    // let mut out:[u8;65] = [10;65]; //max 63 chars + newline + leading _
    // out[0] = b'_';
    // let mut slice_size = 0;

    // let inner_alphabet = &alphabet; //string.as_str().as_bytes();


    // let mut stdout = BufWriter::with_capacity(0xFFFF, stdout());


    let iterate = move |string:&str| {

        let alphabet:Alphabet = mk_alphabet();
        let alphabet_no_dash = &alphabet[0..36];

        let mut out:[u8;65] = [10;65]; //max 63 chars + newline + leading _
        out[0] = b'_';        
        let mut slice_size = 0;

        // let inner_alphabet = &alphabet;
        let inner_alphabet = string.as_bytes();

        // 1
        slice_size = 1;

        for byte0 in inner_alphabet{
            out[1] = *byte0;

            // println!("{}", std::str::from_utf8(&out[1..slice_size+1]).unwrap());

            // stdout.write(&out[1..slice_size+2]);
            // stdout.write(&out[0..slice_size+2]);
            crack(&map, std::str::from_utf8(&out[1..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);
            crack(&map, std::str::from_utf8(&out[0..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);


            // crack(&map, std::str::from_utf8(&out[1..slice_size+2]).unwrap(), &base_wire_domain, &salt, iters);


    // crack(&map, std::str::from_utf8(
    //     ).unwrap(), &base_wire_domain, &salt, iters);


        }
        // return Ok(());
        // stdout.flush();

        // 2
        slice_size = 2;

        for byte1 in alphabet_no_dash{
            out[2] = *byte1;

            for byte0 in inner_alphabet{
                out[1] = *byte0;

                // stdout.write(&out[1..slice_size+2]);
                // stdout.write(&out[0..slice_size+2]);

            crack(&map, std::str::from_utf8(&out[1..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);
            crack(&map, std::str::from_utf8(&out[0..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);

            }
        }
        // stdout.flush();

        //3
        slice_size = 3;

        for byte2 in alphabet_no_dash{
            out[3] = *byte2;

            for byte1 in &alphabet{
                 out[2] = *byte1;

                for byte0 in inner_alphabet{
                    out[1] = *byte0;

                    // stdout.write(&out[1..slice_size+2]);
                    // stdout.write(&out[0..slice_size+2]);
                    crack(&map, std::str::from_utf8(&out[1..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);
                    crack(&map, std::str::from_utf8(&out[0..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);                

                }
            }
        }    
        // stdout.flush();

        //4
        slice_size = 4;

        for byte3 in alphabet_no_dash{
            out[4] = *byte3;

            for byte2 in &alphabet{
                out[3] = *byte2;

                for byte1 in &alphabet{
                    out[2] = *byte1;

                    for byte0 in inner_alphabet{
                        out[1] = *byte0;

                        // stdout.write(&out[1..slice_size+2]);
                        // stdout.write(&out[0..slice_size+2]);

                        crack(&map, std::str::from_utf8(&out[1..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);
                        crack(&map, std::str::from_utf8(&out[0..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);                    
                    }
                }
            }
        }

        // return Ok(());

        // stdout.flush();

        //5
        slice_size = 5;

        for byte4 in alphabet_no_dash{
            out[5] = *byte4; 

            for byte3 in &alphabet{
                out[4] = *byte3;

                for byte2 in &alphabet{
                    out[3] = *byte2;

                    for byte1 in &alphabet{
                        out[2] = *byte1;

                        for byte0 in inner_alphabet{
                            out[1] = *byte0;

                            // stdout.write(&out[1..slice_size+2]);
                            // stdout.write(&out[0..slice_size+2]);

                            crack(&map, std::str::from_utf8(&out[1..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);
                            // crack(&map, std::str::from_utf8(&out[0..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);

                        }
                    }
                }
            }
            // stdout.flush();  
        }

        //6
        slice_size = 6;

        for byte5 in alphabet_no_dash{
            out[6] = *byte5;

            for byte4 in alphabet_no_dash{
                out[5] = *byte4; 

                for byte3 in &alphabet{
                    out[4] = *byte3;

                    for byte2 in &alphabet{
                        out[3] = *byte2;

                        for byte1 in &alphabet{
                            out[2] = *byte1;

                            for byte0 in inner_alphabet{
                                out[1] = *byte0;

                                // stdout.write(&out[1..slice_size+2]);
                                // // stdout.write(&out[0..slice_size+2]);

                                crack(&map, std::str::from_utf8(&out[1..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);
                                // crack(&map, std::str::from_utf8(&out[0..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);

                            }
                        }
                    }
                }  
            }
            // stdout.flush();
        }
        return;

        // return Ok(());
        
        //7
        slice_size = 7;

        for byte6 in alphabet_no_dash{
            out[7] = *byte6;

            for byte5 in alphabet_no_dash{
                out[6] = *byte5;

                for byte4 in alphabet_no_dash{
                    out[5] = *byte4; 

                    for byte3 in &alphabet{
                        out[4] = *byte3;

                        for byte2 in &alphabet{
                            out[3] = *byte2;

                            for byte1 in &alphabet{
                                out[2] = *byte1;

                                for byte0 in inner_alphabet{
                                    out[1] = *byte0;

                                    // stdout.write(&out[1..slice_size+1]);
                                    // // stdout.write(&out[0..slice_size+1]);

                                    // crack(&map, std::str::from_utf8(&out[1..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);
                                    // // crack(&map, std::str::from_utf8(&out[0..slice_size+1]).unwrap(), &base_wire_domain, &salt, &iters);

                                }
                            }
                        }
                    }  
                }
                // stdout.flush();
            }
        }



    };
    let mut handles:Vec<JoinHandle<()>> = vec!();
    
    let alphabets = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];

    for alpha in alphabets{
        let it = iterate.clone();

        let handle = thread::spawn(
        move || {
            let inner_alphabet = alpha;
            it(inner_alphabet);
        }
        );
        handles.push(handle);

    }



    // handle.join().unwrap();

    for handle in handles{
        handle.join().unwrap();
    }

    Ok(())

}
