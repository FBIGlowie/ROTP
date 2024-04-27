use age::secrecy::Secret;
use anyhow::{Ok, Result};
use inquire::{Text};
use rpassword::*;
use snafu::prelude::*;
use std::io::BufReader;
use std::io::Cursor;
use std::{env, path::PathBuf};
use std::{
    env::VarError,
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
}
impl DB {
    fn new(mut self, pass: Secret<String>) {

        DB {
            path: self.get_db().unwrap(),
            archive_handle: self.opendb(pass).unwrap(),
            name: self.get_name().unwrap(),
        };
    }

    fn get_db(&mut self) -> Result<PathBuf> {
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

    fn get_name(&self) -> Result<String> {
    match env::var("ROTP_DB") {
            //check if the the path exists by env var
            std::result::Result::Ok(val) => Ok(val),
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
        }
    }

    fn opendb(&self, pass: Secret<String>) -> Result<Archive<Cursor<Vec<u8>>>> { //as of now, this will only pass out the data from the secrets file, in the future there may be images inside too
        let mut encrypted_archive = File::open(&self.path).unwrap(); //opens a file handle than opens a archine handle
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
       Ok((archive))
    }
    fn encrypt(pass: Secret<String>, data: Vec<u8>) -> Result<(Vec<u8>)> {
        //consumes the password
        let mut encrypted_data = vec![];
        let mut writer = age::Encryptor::with_user_passphrase(pass).wrap_output(&mut encrypted_data)?;
        writer.write_all(&data)?;
        writer.finish()?;
    
        Ok(encrypted_data)
    }

    fn comprehend_secrets<T>(&mut self) -> Result<()>{
        let mut secret_buff: String = String::new();
        for entry in self.archive_handle.entries()? {
            if entry.as_ref().unwrap().path().unwrap().to_str().unwrap() == "secrets.toml" {
                entry?.read_to_string(&mut secret_buff)?;
            }
        }
        let secrets_decoded = secret_buff.parse::<toml::Table>()?;
        println!("{:?}", secrets_decoded);

        Ok(())
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



//onboarding just basicly gonna sit at like rotp init command, and will exit, basicly created a encrypted tar file with a secrets.toml and a [secrets] entry in there
pub fn onboarding() -> Result<(bool)>{
println!("Hello user, welcome to ROTP onboarding");
let mut archive = vec![];
let mut builder = Builder::new(archive);
let secrets_data = Cursor::new("[secrets]");
builder.append(&create_tar_header(std::path::Path::new("secrets.toml"), secrets_data.clone().into_inner().len() as u64), secrets_data);

// ask the user about the prefered db location
let path = loop {
    let path_prompter = PathBuf::from(Text::new("Please specify a empty path to put the db in ():".into()).prompt()?);
    if !path_prompter.exists() {
        if path_prompter.metadata()?.permissions().readonly() {
            println!("Path is readonly, specify one where you have write permissions"); continue;
        } else {break path_prompter;}
    } else {
        println!("Path already contains something, specify a empty one"); continue;
    }
};
println!("{:?}", path);
//building done at this point
//setting the env
Ok((true))
}

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



#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use age::secrecy::Secret;
    use super::{onboarding, DB};
    use tempfile::tempfile;
    #[test]
    fn test_encryption_decryption() {
        let mut data = tempfile().unwrap();
        let encrypted = DB::encrypt(Secret::new("test".to_string()), "shimmi shiimmi ya u lalala".as_bytes().to_vec()).unwrap();
        data.write_all(&encrypted);
        data.seek(SeekFrom::Start(0)).unwrap();
        let decrypted =  DB::decrypt(Secret::new("test".to_string()), std::io::BufReader::new(data)).unwrap();
        assert_eq!("shimmi shiimmi ya u lalala".as_bytes().to_vec(), decrypted);
    }
    #[test]
    fn test_onboarding() {
       // onboarding();
    }
}