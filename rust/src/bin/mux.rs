use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter, Write};



fn main() -> std::io::Result<()> {

	let mut args_it = env::args();
	args_it.next();

	let args: Vec<String> = args_it.collect();
	let files:Vec<_> = args.into_iter().map(|x| File::options().read(false).write(true).open(x).unwrap()).collect();
	let mut writers:Vec<_> = files.into_iter().map(|x| BufWriter::with_capacity(0x10000, x)).collect();

	let num = writers.len();
	let mut index = 0;

    let stdin = std::io::stdin();

    // for wraped_line in stdin.lock().lines() {
    // 	let line = wraped_line.unwrap();
    // 	writers[index].write(line.as_bytes());
    // 	writers[index].write(&['\n' as u8]);
    // 	index = (index+1) % num;
    // }

    for line in stdin.lock().lines() {
    	let mut string = line?;
    	string.push_str("\n");
    	writers[index].write(string.as_bytes());
    	index = (index+1) % num;
    }

    // let reader = BufReader::new(stdin);
    // for line in reader.lines() {
    // 	let mut string = line?;
    // 	string.push_str("\n");
    // 	// string.push_str("\n");
    // 	writers[index].write(string.as_bytes());
    // 	// writers[index].write(&['\n' as u8]);
    // 	index = (index+1) % num;
    // }

    // for i in 0..2498205960u32{
    // 	let mut string = String::from("nopesx");
    // 	string.push_str("\n");
    // 	writers[index].write(string.as_bytes());
    // 	// writers[index].write(&['\n' as u8]);
    // 	index = (index+1) % num;    	
    // }



	Ok(())
}


// use std::fs::File;
// use std::io::{self, prelude::*, BufReader};

// fn main() -> io::Result<()> {
//     let file = File::open("foo.txt")?;
//     let reader = BufReader::new(file);

//     for line in reader.lines() {
//         println!("{}", line?);
//     }

//     Ok(())
// }
