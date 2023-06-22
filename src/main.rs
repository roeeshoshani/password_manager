use base64::Engine;
use clap::{builder::TypedValueParser, Parser};
use sha2::{
    digest::{typenum::Unsigned, OutputSizeUser},
    Digest, Sha256, Sha256VarCore,
};

const PASSWORD_SALT: &[u8] = &[
    221, 112, 242, 134, 144, 232, 24, 0, 99, 18, 155, 97, 26, 150, 238, 78, 143, 160, 142, 176,
    176, 18, 130, 29, 142, 33, 19, 68, 174, 97, 225, 148, 50, 32, 59, 230, 20, 247, 36, 101, 183,
    110, 224, 172, 58, 76, 89, 203, 168, 42, 81, 98, 162, 9, 196, 6, 173, 61, 127, 111, 24, 65, 74,
    113, 107, 99, 119, 100, 251, 92, 208, 213, 230, 211, 193, 110, 0, 133, 50, 31, 206, 11, 166,
    71, 59, 224, 217, 213, 96, 12, 45, 207, 51, 128, 238, 188, 199, 92, 214, 244, 202, 35, 187,
    144, 247, 65, 91, 119, 226, 229, 215, 225, 85, 196, 44, 24, 71, 191, 212, 84, 61, 36, 136, 31,
    94, 250, 76, 241,
];

const USERNAME_SALT: &[u8] = &[
    28, 101, 153, 96, 197, 201, 7, 199, 110, 20, 140, 194, 222, 215, 209, 219, 52, 158, 236, 101,
    174, 43, 7, 72, 164, 145, 95, 3, 231, 206, 253, 202, 172, 143, 57, 238, 179, 135, 107, 198,
    229, 165, 7, 222, 102, 182, 252, 226, 156, 210, 62, 120, 234, 144, 18, 0, 88, 144, 15, 62, 164,
    128, 145, 147, 101, 219, 12, 104, 251, 11, 121, 21, 184, 118, 79, 191, 192, 239, 224, 89, 130,
    23, 167, 55, 221, 59, 73, 90, 76, 57, 96, 9, 184, 172, 209, 146, 233, 227, 153, 50, 250, 247,
    27, 231, 1, 130, 252, 103, 172, 126, 177, 38, 117, 126, 53, 69, 89, 243, 98, 238, 253, 128,
    152, 130, 17, 147, 157, 7,
];

const PASSWORD_LEN: usize = 32;
const USERNAME_LEN: usize = 8;

fn prompt_password(prompt: &str) -> Option<String> {
    match rpassword::prompt_password(prompt) {
        Ok(p) => Some(p),
        Err(e) => {
            println!("failed to read password: {}", e);
            None
        }
    }
}

fn gen_stringified_hash(site_domain: &str, master_password: &str, salt: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&site_domain);
    hasher.update(&master_password);
    hasher.update(salt);
    let hash = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hash)
}

fn main() {
    let cli = Cli::parse();
    let site_domain = cli.site_domain;

    let Some(master_password) = prompt_password("master password: ") else {return};
    let Some(master_password_reentered) = prompt_password("re-enter master password: ") else {return};
    if master_password != master_password_reentered {
        println!("the entered passwords do not match");
        return;
    }
    let password = gen_stringified_hash(&site_domain, &master_password, PASSWORD_SALT);
    let username = gen_stringified_hash(&site_domain, &master_password, USERNAME_SALT);

    println!("username: {}", &username[..USERNAME_LEN]);
    println!("password: {}", &password[..PASSWORD_LEN]);
}

#[derive(Parser, Debug)]
#[command(name = "Password Manager")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// the domain of the site on which the password is to be entered (e.g. "docs.rs").
    #[arg(value_parser = parse_domain_arg)]
    site_domain: String,
}

/// parses a domain command line argument
fn parse_domain_arg(domain: &str) -> Result<String, String> {
    let parts = domain.split('.');
    let parts_amount = parts.clone().count();
    if parts_amount <= 1 {
        return Err("domain must contain a '.' character".into());
    }
    for (i, part) in parts.enumerate() {
        if part.is_empty() {
            if i == 0 {
                return Err(
                    "domain must contain a non-empty string before the first '.' character".into(),
                );
            } else if i + 1 == parts_amount {
                return Err(
                    "domain must contain a non-empty string after the last '.' character".into(),
                );
            } else {
                return Err("domain must contain a non-empty string between '.' characters".into());
            }
        }
    }
    Ok(domain.into())
}
