use age::secrecy::Secret;
use anyhow::{Ok, Result};
use glob::glob_with;
use glob::MatchOptions;
use inquire::Text;
use rpassword::*;
use snafu::prelude::*;
use std::io::BufReader;
use std::io::Cursor;
use std::{env, path::PathBuf};
use std::{
    env::VarError,
    fmt::format,
    fs::{DirBuilder, File},
    io::{Read, Write},
};
use tar::{Archive, Builder, Header};

#[derive(Debug, Snafu)]

enum StorageError {
    #[snafu(display("Database could not be found by ENV var or its location: {err}"))]
    DatabaseNotFound { err: String },
    #[snafu(display("ENV var does not contain valid database name (must end with .tar.rotp): {err}"))]
    BadDBName { err: String },
    #[snafu(display("Database is invalid: {err}"))]
    InvalidDB { err: String },
}

pub struct DB {
    path: PathBuf,
    archive_handle: Archive<Cursor<Vec<u8>>>,
    name: String,
    exists: bool,
}
impl DB {
    fn new(self, pass: Secret<String>) {
        DB {
            path: self.get_db().unwrap(),
            archive_handle: todo!(),
            name: todo!(),
            exists: todo!(),
        };
    }
    fn get_db(self) -> Result<PathBuf> {
        let mut env_path = match env::var("ROTP_DB") {
            //check if the the path exists by env var
            std::result::Result::Ok(val) => val,
            Err(e) => match e {
                //let it be none
                VarError::NotPresent => {
                    return Err(StorageError::DatabaseNotFound { err: e.to_string() }.into())
                }
                VarError::NotUnicode(e) => {
                    return Err(StorageError::DatabaseNotFound {
                        err: e.into_string().unwrap(),
                    }
                    .into())
                }
            }
        };

if env_path.contains(".tar.rotp"){
    if PathBuf::from(&env_path).exists() {
            //database found exists
            Ok(PathBuf::from(env_path))
        } else {
            Err(StorageError::DatabaseNotFound {
                err: "Does not exist in path specified by env".to_string(),
            }
            .into())
        }} else {
            Err(StorageError::BadDBName {err : format!("{}",env_path)}.into())
        }
    }

    fn opendb(mut self, pass: Secret<String>) -> Result<bool> { //as of now, this will only pass out the data from the secrets file, in the future there may be images inside too
        let mut encrypted_archive = File::open(self.path).unwrap(); //opens a file handle than opens a archine handle
        let mut decrypted_archive = DB::decrypt(pass, std::io::BufReader::new(encrypted_archive)).unwrap();
        //now we can get a tar handle
        let mut archive = Archive::new(std::io::Cursor::new(decrypted_archive));
        //confirm the secrets file exists
        let mut secrets_found = false;
        for entry in archive.entries()? {
            if entry.unwrap().path().unwrap().to_str().unwrap() == "secrets.toml" {
                secrets_found = true;
            }
        }
        if !secrets_found {
            return Err(StorageError::InvalidDB { err: "secrets.toml not found".to_string() }.into())
        }
        
       // Ok(archive)
       Ok((true))
    }
    fn encrypt(pass: Secret<String>, data: Vec<u8>) -> Result<(Vec<u8>)> {
        //consumes the password
        let mut encrypted_data = vec![];
        let mut writer = age::Encryptor::with_user_passphrase(pass).wrap_output(&mut encrypted_data)?;
        writer.write_all(&data)?;
        writer.finish()?;
    
        Ok(encrypted_data)
    }
    
    fn decrypt(pass: Secret<String>, data: std::io::BufReader<File>) -> Result<Vec<u8>> {
        let mut decrypted_data: Vec<u8> = vec![];
        let mut writer = match age::Decryptor::new(data)? {
            age::Decryptor::Passphrase(d) => d,
            _ => unreachable!(),
        };
        let mut decrypted = vec![];
        let mut reader = writer.decrypt(&pass, None)?;
        reader.read_to_end(&mut decrypted);
    
        Ok(decrypted)
    }
}

pub fn get_pass(dir: &String) -> Result<(Secret<String>)> {
    let mut pass = rpassword::prompt_password(format!(
        "Please enter password to unlock database located at {}: ",
        dir
    ))?;
    Ok(Secret::new(pass))
}



//make age encryptor

// make age decrypted
//make tar reader that outputs stream



fn create_tar_header<S: std::convert::AsRef<std::path::Path>>(name: S, size: u64) -> Header {
    //tar header for our secrets file
    let mut header = Header::new_gnu();
    header.set_path(name).unwrap();
    header.set_size(size); // Set the file size to size param
    let now = std::time::SystemTime::now();
    header.set_mtime(
        now.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    header.set_cksum();
    header
}
