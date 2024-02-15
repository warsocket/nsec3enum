// Cartesian Combination tool //
// Combines all permutaions of n lists together


use std::{env};
use std::fs::File;
use std::fs::read_to_string;
use std::io::prelude::*;
use std::io::{stdin, stdout, Write, BufWriter};

type Single<'a> = Vec<&'a str>;

enum CharListPostProcesssingToken<'a>{ //Sorry but I got mad with the borrow checker below so this is how i fixed it.
    VecStr(&'a str), //put this VecString here
    FSBufferIndex(usize), // Put contentys of FS buffer here
    StdIn, // Put the std buffered stuff here
}
use CharListPostProcesssingToken::*;

fn main() {

    let args:Vec<String> = env::args().skip(1).collect();
    if args.len() < 1 {
        eprintln!("Cartesian Product Creator");
        eprintln!("Usage: {} [charset | ^ | ^filename ]", env::args().next().unwrap());

        eprintln!("\tWhere ^ (without filename) represents the stdin");
        eprintln!("\tWhere filename is a filename from a text-file from which to use all lines in generation");

        eprintln!("\tWhere charset is string of characters");
        eprintln!("\t\tWhere @ is substituted for abcdefghijklmnopqrstuvwxyz");
        eprintln!("\t\tWhere # is substituted for 0123456789");


        eprintln!("");
        eprintln!("Example:");
        eprintln!("\t{} ^subnames.txt '#' '#' '#'", env::args().next().unwrap());
        eprintln!("\t Generates all combinations of the names in subnames.txt with all possible 3 digit numbers as suffix (000-999), eg domain006");

        return;

    }

    //storage for file based input
    let mut stdin_buffer:Vec<String> = vec!();
    let mut fs_buffer:Vec<Vec<String>> = vec!();

    let mut full:Vec<Vec<&str>> = vec!();
    let mut full_tokens:Vec<CharListPostProcesssingToken> = vec!();

    //parse cli options to tokens
    for arg in args.iter(){

        if arg == ""{
            panic!("No empty command line argument allowed!");
        }else if arg == "^"{
            let stdin = std::io::stdin();
            stdin_buffer.extend(stdin.lines().map(|l| l.unwrap()).collect::<Vec<String>>());            
            full_tokens.push(StdIn);

        }else if arg.starts_with("^"){
            let mut file_err_msg = "File not found: ".to_owned();
            file_err_msg.push_str(&arg[1..]);

            let line_collection:Vec<String> = read_to_string(&arg[1..])
                .expect(&file_err_msg)
                .lines()
                .map(String::from)
                .collect();

            fs_buffer.push(line_collection);
            full_tokens.push(FSBufferIndex(fs_buffer.len()-1));

        }else{
            full_tokens.push(VecStr(&arg));
        }
        
    }

    //now make the full list of references from token list
    for token in full_tokens{
        full.push(
            match(token){
                VecStr(strr) => gen_sublist(strr),
                StdIn => {
                    // full.push( stdin_buffer.iter().map(String::as_str).collect() );
                    stdin_buffer.iter().map(String::as_str).collect()
                },
                FSBufferIndex(index) => {
                    fs_buffer[index].iter().map(String::as_str).collect()
                },
            }
        )
    }


    let fullref:Vec<&Vec<&str>> = full.iter().collect();
    cart(&fullref);

}


//^ (file) directives should been filtered out before 
fn gen_sublist(directive: &str) -> Vec<&str>{

    let mut vec: Vec<_> = vec!();

    for i in 0usize..directive.len(){
        let character = &directive[i..i+1];

        // println!("{}", character);

        let extended_string = match(character){
            "^" => panic!("^ ERROR: ^ character should have been sub stituted out already"),
            " " => vec!(""),
            "#" => vec!("0","1","2","3","4","5","6","7","8","9"),
            "@" => vec!("a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"),
            _ => vec!(character)
        };

        vec.extend(extended_string);
    }

    return vec;

}


fn cart(input: &[&Single]) {

    if (input.len() < 1){return};


    let mut stdout = BufWriter::with_capacity(0xFFFF, stdout());

    let buckets: Vec<_> = input.iter().map(|x| *x).collect(); //lists in their repective buckets
    let mut iterators: Vec<_> = buckets.iter().map(|x| x.iter()).collect(); //List wich containts the current iterators
    let mut current:Vec<_> = vec!();
    
    let length = buckets.len();

    let buildup = false;

    if buildup{
        for index in 0..buckets.len(){
            current.push( "" );
        }
    }else{
        for index in 0..buckets.len(){
            current.push( iterators[index].next().unwrap() ); //empty iterators are disallowed as a precondition
        }
    }


    let newline = ["\n"];
    loop{

        //emit single result
        let emit:Vec<&str> = current.iter().map(|s| *s).chain(newline.into_iter()).collect();
        // let emit:Vec<&str> = current.iter().map(|s| *s).collect();

        stdout.write(emit.join("").as_bytes());

        //increase one
        for index in 0..length{
            let ret = iterators[index].next();

            if let Some(next) = ret {
                current[index] = next;
                break; //we are done, no need to continue
            }else{
                iterators[index] = buckets[index].iter();
                current[index] = iterators[index].next().unwrap(); //empty iterators are disallowed as a precondition

                if index >= length-1 { return }// (totally done)
            }
        }


    }


}