use age::secrecy::Secret;
use anyhow::{Ok, Result};
use inquire::{Text};
use rpassword::*;
use snafu::prelude::*;
use std::io::Cursor;
use std::{env, path::PathBuf};
use std::{
    env::VarError,
    fs::File,
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
    pub fn new(pass: Secret<String>) {

        DB {
            path: DB::get_db().unwrap(),
            archive_handle: DB::opendb(pass).unwrap(),
            name: DB::get_name().unwrap(),
        };
    }

    fn get_db() -> Result<PathBuf> {
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

    pub fn get_name() -> Result<String> {
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

    fn opendb(pass: Secret<String>) -> Result<Archive<Cursor<Vec<u8>>>> { //as of now, this will only pass out the data from the secrets file, in the future there may be images inside too
        let mut encrypted_archive = File::open(DB::get_db()?.as_path()).unwrap(); //opens a file handle than opens a archine handle
        let mut decrypted_archive = DB::decrypt(pass, std::io::BufReader::new(encrypted_archive)).map_err(||);

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

    fn extract_secrets(&mut self) -> Result<(String)> {
        let mut secret_buff: String = String::new();
        for entry in self.archive_handle.entries()? {
            if entry.as_ref().unwrap().path().unwrap().to_str().unwrap() == "secrets.toml" {
                entry?.read_to_string(&mut secret_buff)?;
            }
        }

        Ok((secret_buff))
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
builder.append(&create_tar_header(std::path::Path::new("secrets.toml"), secrets_data.clone().into_inner().len() as u64), secrets_data)?;

let mut pass = loop {
    let pass_prompt = prompt_password(" !!! Please input the database password: ")?;
    let verification_prompt = prompt_password(" !!! Please verify the database password: ")?;
    if pass_prompt != verification_prompt {
        println!("Verification failed, try again"); 
        drop(pass_prompt);
        drop(verification_prompt);
        continue;
    } else {
        break Secret::new(pass_prompt);
    }
};

// ask the user about the prefered db location
let new_db_path = loop {
    let path_prompter = PathBuf::from(Text::new("Please specify an empty path to put the db in (\".tar.rotp\" will be appended to it):".into()).prompt()?);
    if !path_prompter.exists() {
        match std::fs::File::create(format!("{}.tar.rotp",&path_prompter.display())) {
            std::result::Result::Ok(_) => {
                // File created successfully, break the loop and return the path
                break path_prompter;
            },
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                println!("Permission denied for path: {:?}", path_prompter);
                // Handle the error, possibly by continuing the loop to prompt again
                continue;
            },
            Err(e) => {
                // Handle other kinds of errors
                println!("An error occurred: {:?}", e);
                // Continue the loop to prompt again
                continue;
            },
        }
    } else {
        println!("Path already contains something, specify an empty one");
        // Continue the loop to prompt again
        continue;
    }
};
println!("{}", new_db_path.display());

let mut new_db_file_handle = std::fs::File::create(format!("{}.tar.rotp",&new_db_path.display()))?;
new_db_file_handle.write(&DB::encrypt(pass, builder.into_inner()?)?)?;
new_db_file_handle.flush()?;
//building done at this point
//setting the env var 
let mut env_profile = std::fs::OpenOptions::new().append(true).open(format!("{}/.profile", std::env::var("HOME")?))?;
remove_older_profile_exports(&format!("{}/.profile", std::env::var("HOME")?))?;
env_profile.write_all(format!("\nexport ROTP_DB={}{}",&new_db_path.display(), ".tar.rotp").as_bytes())?;
//set the current session to the new update profile
println!("Done!!!");
println!("Please run this command immediatly \n source ~/.profile");
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
//this will remove the older export env var entries from the ~/.profile file
fn remove_older_profile_exports<P>(profile: &P) -> Result<()> 
where
    P: AsRef<std::path::Path>,
{
    let mut file = File::open(profile)?;
    // Open the file for reading
    let mut buffer = Vec::new();

    // Read the whole file into the buffer
    file.read_to_end(&mut buffer)?;

    // Convert the buffer into a string
    let content = String::from_utf8_lossy(&buffer);

    // Split the content into lines, filter out the target line, and join them back
    let modified_content = content.lines()
        .filter(|line| !line.contains("export ROTP_DB"))
        .collect::<Vec<&str>>()
        .join("\n");
    // Open the file for writing
        let mut file = File::create(profile)?;

        // Write the modified content back to the file
        file.write_all(modified_content.as_bytes())?;

    Ok(())
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