use toml::*;
use anyhow::{Ok, Result};
use crate::types::*;

pub fn deserialize(raw_string: String, list:Vec<OTP>) -> Result<()> {
let deserialized = raw_string.parse::<Table>()?;

Ok(())
}


#[cfg(test)]
mod tests {
    use crate::OTP;
    use super::deserialize;


    #[test]
    fn test() { // otpauth://totp/grwrwghwRGHRGWRGW?secret=BASE32SECRET3232&issuer=grwrwghwRGHRGWRGW&algorithm=SHA1&digits=6&period=30
        let list:Vec<OTP> = vec![];
        let otp = OTP::parse_uri(&"otpauth://totp/grwrwghwRGHRGWRGW?secret=BASE32SECRET3232&issuer=grwrwghwRGHRGWRGW&algorithm=SHA1&digits=6&period=30".to_string()).unwrap();
        println!("{:?}", otp);
    }
}