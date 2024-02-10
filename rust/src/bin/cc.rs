// Cartesian Combination tool //
// Combines all permutaions of n lists together


use std::{env};
use std::fs::File;
use std::io::prelude::*;
use std::io::{stdin, stdout, Write, BufWriter};

type Single<'a> = Vec<&'a str>;

fn main() {

    let args:Vec<String> = env::args().skip(1).collect();
    if args.len() < 1 {return}

    //storage for file based input
    let mut stdin_buffer:Vec<String> = vec!();
    let mut use_stdin = false;

    let mut full:Vec<Vec<&str>> = vec!();

    for arg in args.iter(){

        if arg == ""{
            panic!("No empty command line argument allowed!")
        }else if arg == "^"{
            use_stdin = true
        }else if arg.starts_with("^"){
            todo!("still need to implement files other thatn stdin");
        }else{
            full.push( gen_sublist(&arg) );
        }
        
    }
    
    if use_stdin{
        let stdin = std::io::stdin();
        stdin_buffer.extend(stdin.lines().map(|l| l.unwrap()).collect::<Vec<String>>());
        full.push( stdin_buffer.iter().map(String::as_str).collect() );       
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
            "^" => panic!("^ ERROR: ^ character should have been subnstituted out already"),
            "#" => vec!("0","1","2","3","4","5","6","7","8","9"),
            "@" => vec!("a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"),
            _ => vec!(character)
        };

        vec.extend(extended_string);
    }

    return vec;

}


fn cart(input: &[&Single]) {

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