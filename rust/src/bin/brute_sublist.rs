use std::mem::transmute;
use std::str::from_utf8;
use std::str::from_utf8_unchecked;
use std::io::{stdout, Write, BufWriter};
use std::fs::File;
use std::io::prelude::*;
use std::env;

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

fn main(){

    let alphabet:Alphabet = mk_alphabet();
    let alphabet_no_dash = &alphabet[0..36];
    let mut out:[u8;65] = [10;65]; //max 63 chars + newline + leading _
    out[0] = b'_';
    let mut slice_size = 0;

    let mut args_it = env::args();
    args_it.next();


    let string = match args_it.next(){
        Some(x) => x,
        None => String::from_utf8(alphabet_no_dash.to_vec()).unwrap(),
    };

    let inner_alphabet = string.as_str().as_bytes();

    // let inner_alphabet = alphabet_no_dash;
    // println!("{}", inner_alphabet);
    // return;

    
    // return

    let mut stdout = BufWriter::with_capacity(0xFFFF, stdout());

    // 1
    slice_size = 1;

    for byte0 in inner_alphabet{
        out[1] = *byte0;

        stdout.write(&out[1..slice_size+2]);
        stdout.write(&out[0..slice_size+2]);
    }
    // stdout.flush();

    // 2
    slice_size = 2;

    for byte1 in alphabet_no_dash{
        out[2] = *byte1;

        for byte0 in inner_alphabet{
            out[1] = *byte0;

            stdout.write(&out[1..slice_size+2]);
            stdout.write(&out[0..slice_size+2]);
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

                stdout.write(&out[1..slice_size+2]);
                stdout.write(&out[0..slice_size+2]);
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

                    stdout.write(&out[1..slice_size+2]);
                    stdout.write(&out[0..slice_size+2]);
                }
            }
        }
    }
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

                        stdout.write(&out[1..slice_size+2]);
                        stdout.write(&out[0..slice_size+2]);
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

                            stdout.write(&out[1..slice_size+2]);
                            // stdout.write(&out[0..slice_size+2]);
                        }
                    }
                }
            }  
        }
        stdout.flush();
    }

    return
    
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

                                stdout.write(&out[1..slice_size+2]);
                                // stdout.write(&out[0..slice_size+2]);
                            }
                        }
                    }
                }  
            }
            stdout.flush();
        }
    }


}
