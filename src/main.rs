use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream,NewAead},
    XChaCha20Poly1305,
};
use std::{
    fs::File,
    io::{Read, Write},
};

fn encrypt_large_file(
    source_file_path: &str,
    dist_file_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(source_file_path)?;
    let mut dist_file = File::create(dist_file_path)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|_| anyhow!("maybe key was incorrect"))?;
            dist_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("now this {} is bad", err))?;
            dist_file.write(&ciphertext)?;
            break;
        }
    }

    Ok(())
}

fn decrypt_large_file(
    encrypted_file_path: &str,
    dist: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut encrypted_file = File::open(encrypted_file_path)?;
    let mut dist_file = File::create(dist)?;

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
            break;
        }
    }

    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    let  large_file_key = b"mykeyjustlongenoughtobe32chars!?";
    let  large_file_nonce = b"mynoncejustnineteen";
    // OsRng.fill_bytes(&mut large_file_key);
    // OsRng.fill_bytes(&mut large_file_nonce);

    println!("Encrypting fume");
    encrypt_large_file(
        "fume.txt",
        "fume.encrypted",
        large_file_key,
        large_file_nonce,
    )?;

    decrypt_large_file(
        "fume.encrypted",
        "fume.txt.decrypted",
        large_file_key,
        large_file_nonce,
    )?;
    Ok(())

}