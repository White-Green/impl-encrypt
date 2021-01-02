use clap::{App, Arg, SubCommand};
use std::io::Read;


fn main() {
    let matches = App::new("des")
        .about("DES cipher")
        .subcommand(SubCommand::with_name("keygen")
            .about("generate new key by random"))
        .arg(Arg::new("decrypt")
            .short('d')
            .about("flag to decrypt"))
        .arg(Arg::new("key")
            .short('k')
            .about("Key for encrypt or decrypt")
            .takes_value(true))
        .arg(Arg::new("hex")
            .short('x')
            .about("flag to encrypt input as hex value(when decrypt this flag is ignored)"))
        .arg(Arg::new("input")
            .about("input value to encrypt or decrypt"))
        .get_matches();
    let input = matches.value_of("input").map(str::to_string).unwrap_or_else(|| {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).expect("failed to read standard input");
        s
    });
    if let Ok(key) = matches.value_of("key").unwrap().parse() {
        if matches.is_present("decrypt") {
            match decrypt(&input, key) {
                Ok(result) => println!("{}", result),
                Err(e) => eprintln!("error:{:?}", e),
            }
        } else {
            match encrypt(&input, key) {
                Ok(result) => println!("{}", result),
                Err(e) => eprintln!("error:{:?}", e),
            }
        }
    } else {
        eprintln!("argument 'key' should be number");
    }
}
