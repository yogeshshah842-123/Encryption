use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use rayon::prelude::*;
use sha2::Sha256;
use walkdir::WalkDir;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8] = b"ENCRYPTED_OK";
const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;
const KEY_LEN: usize = 32;
const HMAC_LEN: usize = 32;
const ITERATIONS: u32 = 100_000;
const CHUNK_SIZE: usize = 64 * 1024 * 1024;

fn derive_keys(password: &str, salt: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut enc_key = [0u8; KEY_LEN];
    let mut mac_key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITERATIONS, &mut enc_key);
    let mut mac_salt = salt.to_vec();
    mac_salt.push(0x01);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &mac_salt, ITERATIONS, &mut mac_key);
    (enc_key, mac_key)
}

fn is_encrypted(input_path: &Path) -> bool {
    let mut f = match File::open(input_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut header = vec![0u8; SALT_LEN + IV_LEN + MAGIC.len()];
    if f.read_exact(&mut header).is_ok() {
        return &header[SALT_LEN + IV_LEN..] == MAGIC;
    }
    false
}

fn encrypt_single(input_path: &Path, password: &str) -> Result<String, String> {
    if is_encrypted(input_path) {
        return Ok("⚠️ Already encrypted".to_string());
    }

    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut iv);

    let (enc_key, mac_key) = derive_keys(password, &salt);

    let file_name = input_path.file_name().unwrap().to_string_lossy();
    let name_bytes = file_name.as_bytes();
    let name_len = (name_bytes.len() as u32).to_be_bytes();

    let enc_name = hex::encode(&iv[..8]);
    let output_path = input_path.with_file_name(&enc_name);

    if output_path.exists() {
        return Err("Output file already exists".to_string());
    }

    let mut mac = HmacSha256::new_from_slice(&mac_key).map_err(|e| e.to_string())?;

    {
        let out_file = OpenOptions::new()
            .write(true).create_new(true).open(&output_path)
            .map_err(|e: std::io::Error| e.to_string())?;
        let mut writer = BufWriter::new(out_file);

        writer.write_all(&salt).map_err(|e: std::io::Error| e.to_string())?;
        writer.write_all(&iv).map_err(|e: std::io::Error| e.to_string())?;
        writer.write_all(MAGIC).map_err(|e: std::io::Error| e.to_string())?;
        writer.write_all(&name_len).map_err(|e: std::io::Error| e.to_string())?;
        writer.write_all(name_bytes).map_err(|e: std::io::Error| e.to_string())?;

        mac.update(&salt);
        mac.update(&iv);
        mac.update(MAGIC);
        mac.update(&name_len);
        mac.update(name_bytes);

        let in_file = File::open(input_path).map_err(|e: std::io::Error| e.to_string())?;
        let mut reader = BufReader::new(in_file);
        let mut cipher = Ctr128BE::<Aes256>::new(&enc_key.into(), &iv.into());
        let mut buf = vec![0u8; CHUNK_SIZE];

        loop {
            let n = reader.read(&mut buf).map_err(|e: std::io::Error| e.to_string())?;
            if n == 0 { break; }
            let chunk = &mut buf[..n];
            cipher.apply_keystream(chunk);
            mac.update(chunk);
            writer.write_all(chunk).map_err(|e: std::io::Error| e.to_string())?;
        }

        let tag = mac.finalize().into_bytes();
        writer.write_all(&tag).map_err(|e: std::io::Error| e.to_string())?;
        writer.flush().map_err(|e: std::io::Error| e.to_string())?;
    }

    fs::remove_file(input_path).map_err(|e: std::io::Error| e.to_string())?;
    Ok(format!("✅ Encrypted: {}", file_name))
}

// output_dir = jahan decrypt hogi, delete_after = vault use ke liye false
fn decrypt_single(input_path: &Path, output_dir: &Path, password: &str, delete_original: bool) -> Result<String, String> {
    let file_size = fs::metadata(input_path)
        .map_err(|e: std::io::Error| e.to_string())?.len() as usize;
    let min_size = SALT_LEN + IV_LEN + MAGIC.len() + 4 + HMAC_LEN;

    if file_size < min_size {
        return Err("Not an encrypted file".to_string());
    }

    let mut f = File::open(input_path).map_err(|e: std::io::Error| e.to_string())?;
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    let mut magic = [0u8; 12];

    f.read_exact(&mut salt).map_err(|e: std::io::Error| e.to_string())?;
    f.read_exact(&mut iv).map_err(|e: std::io::Error| e.to_string())?;
    f.read_exact(&mut magic).map_err(|e: std::io::Error| e.to_string())?;

    if &magic != MAGIC {
        return Err("Not an encrypted file".to_string());
    }

    let mut name_len_bytes = [0u8; 4];
    f.read_exact(&mut name_len_bytes).map_err(|e: std::io::Error| e.to_string())?;
    let name_len = u32::from_be_bytes(name_len_bytes) as usize;

    let mut name_bytes = vec![0u8; name_len];
    f.read_exact(&mut name_bytes).map_err(|e: std::io::Error| e.to_string())?;
    let original_name = std::str::from_utf8(&name_bytes)
        .map_err(|e| e.to_string())?.to_string();

    let (enc_key, mac_key) = derive_keys(password, &salt);
    let header_size = SALT_LEN + IV_LEN + MAGIC.len() + 4 + name_len;
    let encrypted_size = file_size - header_size - HMAC_LEN;

    {
        let mut verify_mac = HmacSha256::new_from_slice(&mac_key).map_err(|e| e.to_string())?;
        let mut vf = File::open(input_path).map_err(|e: std::io::Error| e.to_string())?;
        let mut header_buf = vec![0u8; header_size];
        vf.read_exact(&mut header_buf).map_err(|e: std::io::Error| e.to_string())?;
        verify_mac.update(&header_buf);

        let mut enc_buf = vec![0u8; CHUNK_SIZE];
        let mut remaining = encrypted_size;
        while remaining > 0 {
            let to_read = remaining.min(CHUNK_SIZE);
            let buf = &mut enc_buf[..to_read];
            vf.read_exact(buf).map_err(|e: std::io::Error| e.to_string())?;
            verify_mac.update(buf);
            remaining -= to_read;
        }

        let mut stored_tag = [0u8; HMAC_LEN];
        vf.read_exact(&mut stored_tag).map_err(|e: std::io::Error| e.to_string())?;
        verify_mac.verify_slice(&stored_tag)
            .map_err(|_| "❌ Wrong password or corrupted file".to_string())?;
    }

    let output_path = output_dir.join(&original_name);

    if output_path.exists() {
        return Ok(output_path.to_string_lossy().to_string());
    }

    {
        let mut rf = File::open(input_path).map_err(|e: std::io::Error| e.to_string())?;
        rf.seek(SeekFrom::Start(header_size as u64))
            .map_err(|e: std::io::Error| e.to_string())?;

        let out_file = OpenOptions::new()
            .write(true).create_new(true).open(&output_path)
            .map_err(|e: std::io::Error| e.to_string())?;
        let mut writer = BufWriter::new(out_file);
        let mut cipher = Ctr128BE::<Aes256>::new(&enc_key.into(), &iv.into());
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut remaining = encrypted_size;

        while remaining > 0 {
            let to_read = remaining.min(CHUNK_SIZE);
            let chunk = &mut buf[..to_read];
            rf.read_exact(chunk).map_err(|e: std::io::Error| e.to_string())?;
            cipher.apply_keystream(chunk);
            writer.write_all(chunk).map_err(|e: std::io::Error| e.to_string())?;
            remaining -= to_read;
        }
        writer.flush().map_err(|e: std::io::Error| e.to_string())?;
    }

    if delete_original {
        fs::remove_file(input_path).map_err(|e: std::io::Error| e.to_string())?;
    }

    Ok(output_path.to_string_lossy().to_string())
}

fn collect_files(folder: &Path) -> Vec<PathBuf> {
    WalkDir::new(folder)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn process_folder(folder: &str, password: &str, encrypt: bool) -> String {
    let folder_path = Path::new(folder);
    if !folder_path.is_dir() {
        return "❌ Invalid folder path".to_string();
    }

    let files = collect_files(folder_path);
    if files.is_empty() {
        return "⚠️ No files found".to_string();
    }

    let results: Vec<String> = files.par_iter().map(|f| {
        if encrypt {
            match encrypt_single(f, password) {
                Ok(msg) => msg,
                Err(e) => format!("❌ {}: {}", f.file_name().unwrap().to_string_lossy(), e),
            }
        } else {
            match decrypt_single(f, folder_path, password, true) {
                Ok(_) => format!("✅ {}", f.file_name().unwrap().to_string_lossy()),
                Err(e) => format!("❌ {}: {}", f.file_name().unwrap().to_string_lossy(), e),
            }
        }
    }).collect();

    let errors = results.iter().filter(|r| r.starts_with("❌")).count();
    if errors == 0 {
        if encrypt { format!("✅ Encrypted {} file(s)", files.len()) }
        else { format!("✅ Decrypted {} file(s)", files.len()) }
    } else {
        format!("⚠️ Done with {} error(s):\n{}", errors, results.join("\n"))
    }
}

// JNI — folder encrypt
#[no_mangle]
pub extern "C" fn Java_com_sanvistudio_vaultx_MainActivity_00024Companion_encryptFolder(
    mut env: JNIEnv, _class: JClass, path: JString, password: JString,
) -> jstring {
    let folder: String = env.get_string(&path).unwrap().into();
    let pass: String = env.get_string(&password).unwrap().into();
    env.new_string(process_folder(&folder, &pass, true)).unwrap().into_raw()
}

// JNI — folder decrypt
#[no_mangle]
pub extern "C" fn Java_com_sanvistudio_vaultx_MainActivity_00024Companion_decryptFolder(
    mut env: JNIEnv, _class: JClass, path: JString, password: JString,
) -> jstring {
    let folder: String = env.get_string(&path).unwrap().into();
    let pass: String = env.get_string(&password).unwrap().into();
    env.new_string(process_folder(&folder, &pass, false)).unwrap().into_raw()
}

// JNI — single file encrypt
#[no_mangle]
pub extern "C" fn Java_com_sanvistudio_vaultx_MainActivity_00024Companion_encryptFile(
    mut env: JNIEnv, _class: JClass, path: JString, password: JString,
) -> jstring {
    let input: String = env.get_string(&path).unwrap().into();
    let pass: String = env.get_string(&password).unwrap().into();
    let result = encrypt_single(Path::new(&input), &pass)
        .unwrap_or_else(|e| format!("❌ {}", e));
    env.new_string(result).unwrap().into_raw()
}

// JNI — single file decrypt to temp (open ke liye, original safe)
#[no_mangle]
pub extern "C" fn Java_com_sanvistudio_vaultx_MainActivity_00024Companion_decryptFileToTemp(
    mut env: JNIEnv, _class: JClass, input_path: JString, output_dir: JString, password: JString,
) -> jstring {
    let input: String = env.get_string(&input_path).unwrap().into();
    let output: String = env.get_string(&output_dir).unwrap().into();
    let pass: String = env.get_string(&password).unwrap().into();
    let result = decrypt_single(Path::new(&input), Path::new(&output), &pass, false)
        .unwrap_or_else(|e| format!("❌ {}", e));
    env.new_string(result).unwrap().into_raw()
}

// JNI — single file decrypt aur save (export ke liye, original delete)
#[no_mangle]
pub extern "C" fn Java_com_sanvistudio_vaultx_MainActivity_00024Companion_decryptFileTo(
    mut env: JNIEnv, _class: JClass, input_path: JString, output_dir: JString, password: JString,
) -> jstring {
    let input: String = env.get_string(&input_path).unwrap().into();
    let output: String = env.get_string(&output_dir).unwrap().into();
    let pass: String = env.get_string(&password).unwrap().into();
    let result = decrypt_single(Path::new(&input), Path::new(&output), &pass, true)
        .unwrap_or_else(|e| format!("❌ {}", e));
    env.new_string(result).unwrap().into_raw()
}