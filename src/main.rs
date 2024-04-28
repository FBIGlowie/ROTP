use image::io::Reader;
use storage::onboarding;
mod otp;
mod parse;
mod err;
mod storage;
use storage::{get_pass, DB};
mod types;
use types::*;


fn main() -> Result<(), anyhow::Error> {
    let mut otp_list:Vec<OTP> = vec![];
    let mut lol = Reader::open("/home/adi/code/ROTP/testing/canvas.png")?
    .with_guessed_format()?
    .decode()?;
let otp = OTP::parse_uri(&"otpauth://totp/grwrwghwRGHRGWRGW?secret=BASE32SECRET3232&issuer=grwrwghwRGHRGWRGW&algorithm=SHA1&digits=6&period=30".to_string()).unwrap();
println!("{:?}", otp);
    let uri = decode_qr(&mut lol)?;
    println!("{}", uri);
    let db =  DB::new(get_pass(&DB::get_name()?)?);
    Ok(())
}






