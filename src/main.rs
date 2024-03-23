use bardecoder::default_builder;
use std::thread;
use image::io::Reader;
use image::{DynamicImage, GenericImageView};
mod otp;
use anyhow::{Error, Ok, Result};
use std::path::Path;
mod err;
use snafu::prelude::*;
use url::Url;


#[derive(Debug, Snafu)]
enum OtpError {
    #[snafu(display("URI didn't contain a label: {err}"))]
    LabelNotProvided {err: String},
    #[snafu(display("HOTP URI didn't contain a counter: {err}"))]
    CounterNotProvided{err: String},
    #[snafu(display("URI didn't contain a secret: {err}"))]
    SecretNotProvided{err: String},
    #[snafu(display("URI didn't could not be verified to be a valid OTP uri: {err}"))]
    NotOtpLink{err: String},
    #[snafu(display("URI didn't contain a otp type: {err}"))]
    CannotIdentifyOtpType{err: String},
}



enum Algo {
    SHA1,
    SHA256,
    SHA512
}
struct HOTP {
    secret: String,
    label: String,
    issuer: String,
    algo: Algo,
    counter: u64,
    full_uri: String,
    img_path: String
}

struct TOTP {
    secret: String,
    label: String,
    issuer: String,
    algo: Algo,
    step: u32,
    full_uri: String,
    img_path: String
}


fn main() -> Result<(), anyhow::Error> {
    let mut lol = Reader::open("/home/adi/code/ROTP/src/Screenshot_20240323_110510.png")?.with_guessed_format()?.decode()?;


    let mut key = "BASE32SECRET3232";
    let uri = decode_qr(&mut lol).unwrap();
    parse_uri(&uri);
    Ok(())
}

fn decode_qr(img: &mut DynamicImage) -> Result<String, anyhow::Error> {
    let decoder = bardecoder::default_decoder();

    let results = decoder.decode(&img.clone());
    Ok(results[0].as_ref().clone().unwrap().to_string())
}

fn parse_uri(uri: &String) -> Result<()> {
    let url = Url::parse(uri).expect("Failed to parse URL");

    if uri.contains("otpauth://") {
        let mut path_segments = url.path_segments().expect("Failed to get path segments");

        // The label is the first path segment after "totp/"
            let label = path_segments.next().expect("Failed to get label");
    
        if uri.contains("totp") {
            let mut totp = parse_totp(&uri, &url, label.to_string(), "/lol".to_string()).unwrap();
            println!("{}", totp.secret)
        }
        else {
            let mut hotp = parse_hotp(&uri, &url, label.to_string(), "/lol".to_string(), 1000).unwrap();
            println!("{}", hotp.secret)
        }

    } else {
        panic!()
    }
    Ok(())
}

fn parse_hotp(uri: &String, url: &Url, label: String, img_path: String, counter: u64) -> Result<HOTP> {
    let uri = uri.clone();
    let url = url.clone();
    let mut algo;
    println!("{}", format!("{}", url.query_pairs().find(|(key, _)| key == "algorithm").map(|(_, value)| value.to_string()).unwrap_or("SHA1".to_owned()).as_str()));
    match url.query_pairs().find(|(key, _)| key == "algorithm").map(|(_, value)| value.to_string()).unwrap_or("SHA1".to_owned()).as_str() {
        _ => algo = Algo::SHA1,
        "SHA1" => algo = Algo::SHA1,
        "SHA256" => algo = Algo::SHA256,
        "SHA512" => algo = Algo::SHA512
    }
    Ok(HOTP {
        secret : url.query_pairs().find(|(key, _)| key == "secret").map(|(_, value)| value.to_string()).unwrap(),
        label: label.clone(),
        issuer: url.query_pairs().find(|(key, _)| key == "issuer").map(|(_, value)| value.to_string()).unwrap_or(label),
        algo,
        counter,
        full_uri: uri,
        img_path,
    })
}

fn parse_totp(uri: &String, url: &Url, label: String, img_path: String) -> Result<TOTP> {
    let uri = uri.clone();
    let url = url.clone();
    let mut algo;
    match url.query_pairs().find(|(key, _)| key == "algorithm").map(|(_, value)| value.to_string()).unwrap_or("SHA1".to_owned()).as_str() {
        _ => algo = Algo::SHA1,
        "SHA1" => algo = Algo::SHA1,
        "SHA256" => algo = Algo::SHA256,
        "SHA512" => algo = Algo::SHA512
    }

    let totp = TOTP {
        secret : url.query_pairs().find(|(key, _)| key == "secret").map(|(_, value)| value.to_string()).unwrap(),
        label: label.clone(),
        issuer: url.query_pairs().find(|(key, _)| key == "issuer").map(|(_, value)| value.to_string()).unwrap_or(label),
        algo,
        step: url.query_pairs().find(|(key, _)| key == "period").map(|(_, value)| value.to_string()).unwrap_or("30".to_string()).parse::<u32>().unwrap_or(30),
        full_uri: uri,
        img_path
    };
    Ok(totp)
}

