use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufWriter, Write};

fn main() -> std::io::Result<()> {

	let mut args_it = env::args();
	args_it.next();

	let args: Vec<String> = args_it.collect();
	let files:Vec<_> = args.into_iter().map(|x| File::options().read(false).write(true).open(x).unwrap()).collect();
	let mut writers:Vec<_> = files.into_iter().map(|x| BufWriter::new(x)).collect();

	let num = writers.len();
	let mut index = 0;

    let stdin = std::io::stdin();
    for wraped_line in stdin.lock().lines() {
    	let line = wraped_line.unwrap();
    	// writeln!(&mut writers[index], "{}", line)?;
    	writers[index].write(line.as_bytes());
    	writers[index].write(&['\n' as u8]);
    	index = (index+1) % num;
    }
	// println!("{:?}", writers);

	Ok(())
}