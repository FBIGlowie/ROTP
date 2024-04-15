use std::{fmt::format, fs::File, io::{Read, Write}};
use rpassword::*;
use anyhow::{Ok, Result};
use age::secrecy::Secret;
use tar::{Archive, Builder, Header};
use std::{env, path::Path};
use inquire::Text;

fn opentarball() -> Result<()> {
    let mut archive;
    let mut env_path = match env::var("ROTP_DB") { //check if the key exists
        std::result::Result::Ok(val) => Path::new(&val),
        Err(e) => onboarding().expect("Onboarding failed!!, quitting") //do onboarding if not
    };
    if env_path.exists() { //check if the actual file exists
        archive = Archive::new(File::open(env_path)?); 
    } else { //if not just infinetly promt the user to specify a correct one or let them do onboarding
        let mut choice = Text::new("Database does not exist, want to do onboarding or specify a new one? (y/n)").prompt()?;
        match choice.as_str() {
            "y" | "yes" | "Yes" | "Y" => onboarding(), //onboarding will quit after its done, to ensure I dont fuck up 
            "n" | "no" | "No" | "N" => {
                loop {
                    let new_path = Path::new(&Text::new("Please specify full path").prompt()?);
                    if new_path.exists() {
                        env_path = new_path;
                    } else {
                        continue;
                    }
                }
            },
            _ => {
            }
        }

    }

Ok()
}

pub fn get_pass(dir : &String) -> Result<(Secret<String>)> {
    let mut pass = rpassword::prompt_password(format!("Please enter password to unlock database located at {}: ", dir))?;
    Ok(Secret::new(pass))
}

fn encrypt(pass: Secret<String>, data: Vec<u8>) -> Result<(Vec<u8>)>{ //consumes the password
    let mut encrypted_data = vec![];
    let mut writer = age::Encryptor::with_user_passphrase(pass).wrap_output(&mut encrypted_data)?;
    let path = "archive.tar.gz";

    let tar_gz = File::open(path)?;
    let mut archive = Archive::new(tar_gz);
    writer.write_all(&data)?;
    writer.finish()?;

    Ok(encrypted_data)
}

fn decrypt(pass: &String) {

}
//make age encryptor


// make age decrypted
//make tar reader that outputs stream

fn onboarding() { // this function is done at which the app is first run
let mut default_path:&str = "~/.rotp/";
println!("Welsome to ROTP onboarding");
let db_name = Text::new("Please specify database name").prompt().unwrap();
let mut pass;
loop { //password vefiticvatio
let unverified_pass = rpassword::prompt_password(format!("Please type the database password")).unwrap();
if unverified_pass != rpassword::prompt_password(format!("Please verify the password")).unwrap() {
drop(unverified_pass); //drop the unverified one for extra secuity
continue;
} else {
    pass = Secret::new(unverified_pass);
    break;
}
}
let mut database_file = std::fs::File::create(format!("{}{}.rotp", default_path, db_name)).unwrap(); //create file for new tarball
let mut tarball_data = vec![];
let mut new_archive = Builder::new(tarball_data);
let secrets_header = &create_tar_header("secrets.toml", "[secrets]".as_bytes().len() as u64);
new_archive.append(secrets_header, "[secrets]".as_bytes()); //adding our secrets file, which is just contains toml table secrets

database_file.write_all(&encrypt(pass, tarball_data).unwrap()).unwrap(); // encrypt and write to file
database_file.flush();

//finally set the env var
env::set_var("ROTP_DB", format!("{}{}.rotp", default_path, db_name));
}

fn create_tar_header<S>(name: S, size: u64) -> Header{ //tar header for our secrets file
    let mut header = Header::new_gnu();
    header.set_path("secrets.toml").unwrap();
    header.set_size(size); // Set the file size to size param
    let now = std::time::SystemTime::now();
    header.set_mtime(now.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs());
    header.set_cksum();
    header
}