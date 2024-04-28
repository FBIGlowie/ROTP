use serde::Serialize;
use snafu::prelude::*;
use url::Url;
use bardecoder::default_builder;
use image::io::Reader;
use image::{DynamicImage, GenericImageView};
use anyhow::{Ok, Result};

#[derive(Debug, Snafu)]
enum OtpError {
    #[snafu(display("URI didn't contain a label: {err}"))]
    LabelNotProvided { err: String },
    #[snafu(display("HOTP URI didn't contain a counter: {err}"))]
    CounterNotProvided { err: String },
    #[snafu(display("URI didn't contain a secret: {err}"))]
    SecretNotProvided { err: String },
    #[snafu(display("URI didn't could not be verified to be a valid OTP uri: {err}"))]
    NotOtpLink { err: String },
    #[snafu(display("URI didn't contain a otp type: {err}"))]
    CannotIdentifyOtpType { err: String },
    #[snafu(display("QR code could not be parsed, try a simpler one with no images."))]
    CannotParseQR,
}
#[derive(Debug, Serialize)]
pub enum OTP {
    HOTP(HOTP),
    TOTP(TOTP)
}



    impl OTP{
        pub fn parse_uri(uri: &String) -> Result<(OTP)> {
            let url = Url::parse(uri).expect("Failed to parse URL");
        
            if uri.contains("otpauth://") {
                let mut path_segments = url.path_segments().expect("Failed to get path segments");
        
                // The label is the first path segment after "totp/"
                let label = path_segments.next().expect("Failed to get label");
        
                if uri.contains("totp") {
                    let mut totp = TOTP::new(&uri, &url, label.to_string(), "/wip".to_string()).unwrap();
                    return Ok(OTP::TOTP(totp))
                } else {
                    let mut hotp =
                        HOTP::new(&uri, &url, label.to_string(), "/wip".to_string()).unwrap();
                    return Ok(OTP::HOTP(hotp))
                    }
            } else {
                Err((OtpError::NotOtpLink{ err: "failed at parse_uri".to_string()}).into())
            }
        }
    }




#[derive(Debug, Serialize)]
enum Algo {
    SHA1,
    SHA256,
    SHA512,
}
#[derive(Debug, Serialize)]

struct HOTP {
    secret: String,
    label: String,
    issuer: String,
    algo: Algo,
    counter: u64,
    full_uri: String,
    img_path: String,
}

impl HOTP {
    fn new(
        uri: &String,
        url: &Url,
        label: String,
        img_path: String,
    ) -> Result<HOTP> {
        let uri = uri.clone();
        let url = url.clone();
        let mut algo;
        match url
            .query_pairs()
            .find(|(key, _)| key == "algorithm")
            .map(|(_, value)| value.to_string())
            .unwrap_or("SHA1".to_owned())
            .as_str()
        {
            "SHA1" => algo = Algo::SHA1,
            "SHA256" => algo = Algo::SHA256,
            "SHA512" => algo = Algo::SHA512,
            _ => algo = Algo::SHA1,
        }
        Ok(HOTP {
            secret: url
                .query_pairs()
                .find(|(key, _)| key == "secret")
                .map(|(_, value)| value.to_string())
                .unwrap(),
            label: label.clone(),
            issuer: url
                .query_pairs()
                .find(|(key, _)| key == "issuer")
                .map(|(_, value)| value.to_string())
                .unwrap_or(label),
            algo,
            counter: url
            .query_pairs()
            .find(|(key, _)| key == "counter")
            .map(|(_, value)| value.to_string())
            .unwrap().parse::<u64>().unwrap(),
            full_uri: uri,
            img_path,
        })
    }
}
#[derive(Debug, Serialize)]
struct TOTP {
    secret: String,
    label: String,
    issuer: String,
    algo: Algo,
    step: u32,
    full_uri: String,
    img_path: String,
}

impl TOTP {
    fn new(uri: &String, url: &Url, label: String, img_path: String) -> Result<TOTP> {
        let uri = uri.clone();
        let url = url.clone();
        let mut algo;
        match url
            .query_pairs()
            .find(|(key, _)| key == "algorithm")
            .map(|(_, value)| value.to_string())
            .unwrap_or("SHA1".to_owned())
            .as_str()
        {
            "SHA1" => algo = Algo::SHA1,
            "SHA256" => algo = Algo::SHA256,
            "SHA512" => algo = Algo::SHA512,
            _ => algo = Algo::SHA1,
        }
    
        let totp = TOTP {
            secret: url
                .query_pairs()
                .find(|(key, _)| key == "secret")
                .map(|(_, value)| value.to_string())
                .unwrap(),
            label: label.clone(),
            issuer: url
                .query_pairs()
                .find(|(key, _)| key == "issuer")
                .map(|(_, value)| value.to_string())
                .unwrap_or(label),
            algo,
            step: url
                .query_pairs()
                .find(|(key, _)| key == "period")
                .map(|(_, value)| value.to_string())
                .unwrap_or("30".to_string())
                .parse::<u32>()
                .unwrap_or(30),
            full_uri: uri,
            img_path,
        };
        Ok(totp)
    }
    
}

pub fn decode_qr(img: &mut DynamicImage) -> Result<String, anyhow::Error> {
    let decoder = bardecoder::default_decoder();

    let results = decoder.decode(&img.clone());
    if results.is_empty() {
        Err(OtpError::CannotParseQR.into())
    } else {
        Ok(results[0].as_ref().clone().unwrap().to_string())
    }
}


#[cfg(test)]
mod tests {
use super::OTP;


    #[test]
    fn test() {
        let list:Vec<OTP> = vec![];

    }
}