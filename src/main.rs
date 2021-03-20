#![feature(min_const_generics)]
#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]

mod binary;
mod util;

#[allow(clippy::all)]
pub fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let file = std::fs::File::open(&args[1])?;
    let mmap = unsafe { memmap::Mmap::map(&file)? };
    let header = binary::header::Header::from_slice(&mmap)?;
    println!("Got header {:?}", header);
    Ok(())
}
