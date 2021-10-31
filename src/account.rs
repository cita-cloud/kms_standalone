use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::block_in_place;

use secrecy::ExposeSecret;
use secrecy::Secret;
use secrecy::SecretString;
use secrecy::SecretVec;

use lru::LruCache;
use sqlx::MySqlPool;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

use rand::Rng;

use efficient_sm2::KeyPair;

use crate::sm::{
    pk2address, sm2_gen_keypair, sm2_sign, sm3_hash, sm4_decrypt, sm4_encrypt, Address, PrivateKey,
    Signature,
};

const SALT_BYTES_LEN: usize = 16;
type Salt = [u8; SALT_BYTES_LEN];

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Master password mismatched")]
    MasterPasswordMismatched,
    #[error("Account with id `{0}` not found")]
    AccountNotFound(u64),
}

#[derive(Debug)]
struct EncryptedAccount {
    encrypted_privkey: Vec<u8>,
    salt: Vec<u8>,
}

#[derive(Debug)]
struct HashAndSalt {
    password_hash: Vec<u8>,
    salt: Vec<u8>,
}

// TODO and WARNING
// KeyPairs are not zeroized after drop. Doing so requires patching efficient_sm2
struct Account(KeyPair);

impl Account {
    pub fn generate() -> (Account, Address, Secret<PrivateKey>) {
        let (keypair, pk, sk) = sm2_gen_keypair();
        let addr = pk2address(&pk);
        (Account(keypair), addr, sk)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        sm2_sign(&self.0, msg)
    }

    pub fn from_encrypted(encrypted: &EncryptedAccount, master_password: &[u8]) -> Self {
        let sk = {
            let buf = SecretVec::new([master_password, &encrypted.salt].concat());
            let password_hash = Secret::new(sm3_hash(buf.expose_secret()));
            let sk: PrivateKey =
                sm4_decrypt(&encrypted.encrypted_privkey, password_hash.expose_secret())
                    .try_into()
                    .unwrap();
            Secret::new(sk)
        };
        let keypair =
            KeyPair::new(sk.expose_secret()).expect("construct keypair from private key failed");

        Account(keypair)
    }
}

pub struct AccountManager {
    nonce: AtomicU64,

    master_password: SecretString,

    pool: MySqlPool,
    cache: Mutex<LruCache<u64, Arc<Account>>>,
}

impl AccountManager {
    pub async fn new(
        db_url: &str,
        master_password: SecretString,
        max_cached_accounts: usize,
        db_max_connections: u32,
        db_conn_idle_timeout_millis: u64,
    ) -> Result<Self> {
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(db_max_connections)
            .idle_timeout(Duration::from_millis(db_conn_idle_timeout_millis))
            .connect(db_url)
            .await?;
        sqlx::migrate!().run(&pool).await?;

        let nonce: u64 = sqlx::query!("SELECT COUNT(*) as nonce FROM Accounts",)
            .fetch_one(&pool)
            .await
            .context("cannot fetch the number of accounts from database")?
            .nonce
            .try_into()
            .unwrap();

        let hash_and_salt = sqlx::query_as!(
            HashAndSalt,
            "SELECT password_hash, salt FROM MasterPassword"
        )
        .fetch_optional(&pool)
        .await
        .context("cannot fetch master password info from database")?;

        if let Some(HashAndSalt {
            password_hash,
            salt,
        }) = hash_and_salt
        {
            let salted_pw =
                Secret::new([master_password.expose_secret().as_bytes(), salt.as_slice()].concat());
            if password_hash != sm3_hash(salted_pw.expose_secret()) {
                bail!(Error::MasterPasswordMismatched);
            }
        } else {
            let salt: Salt = rand::thread_rng().gen();
            let salted_pw_hash = {
                let salted_pw = Secret::new(
                    [master_password.expose_secret().as_bytes(), salt.as_slice()].concat(),
                );
                sm3_hash(salted_pw.expose_secret())
            };
            sqlx::query!(
                "INSERT INTO MasterPassword (password_hash, salt) VALUES (?, ?)",
                salted_pw_hash.to_vec(),
                salt.to_vec()
            )
            .execute(&pool)
            .await
            .context("cannot store master password info into database")?;
        }
        Ok(Self {
            nonce: AtomicU64::new(nonce),
            master_password,
            pool,
            cache: Mutex::new(LruCache::new(max_cached_accounts)),
        })
    }

    pub async fn generate_account(&self, description: &str) -> Result<(u64, Address)> {
        let (account_id, account, encrypted_privkey, address, salt) = block_in_place(|| {
            let (account, address, sk) = Account::generate();
            // I think Ordering::AcqRel will do the job
            let account_id = self.nonce.fetch_add(1, Ordering::SeqCst);

            let salt: Salt = rand::thread_rng().gen();
            let encrypted_privkey = {
                let password_hash = {
                    let salted_pw = Secret::new(
                        [
                            self.master_password.expose_secret().as_bytes(),
                            salt.as_slice(),
                        ]
                        .concat(),
                    );
                    sm3_hash(salted_pw.expose_secret())
                };
                sm4_encrypt(sk.expose_secret(), &password_hash)
            };
            (account_id, account, encrypted_privkey, address, salt)
        });

        sqlx::query!(
            "INSERT INTO Accounts (id, encrypted_privkey, salt, account_description) VALUES (?, ?, ?, ?)",
            account_id,
            encrypted_privkey.to_vec(),
            salt.to_vec(),
            description,
        )
        .execute(&self.pool)
        .await
        .context("cannot store new account into database")?;

        self.cache.lock().await.put(account_id, Arc::new(account));

        Ok((account_id, address))
    }

    pub async fn sign_with(&self, account_id: u64, data: &[u8]) -> Result<Signature> {
        let account = self.cache.lock().await.get(&account_id).cloned();
        if let Some(account) = account {
            Ok(block_in_place(|| account.sign(data)))
        } else {
            let encrypted = sqlx::query_as!(
                EncryptedAccount,
                "SELECT encrypted_privkey, salt FROM Accounts WHERE id=?",
                account_id
            )
            .fetch_optional(&self.pool)
            .await
            .context("cannot fetch account from database")?;

            if let Some(encrypted) = encrypted {
                let (account, sig) = block_in_place(|| {
                    let account = Account::from_encrypted(
                        &encrypted,
                        self.master_password.expose_secret().as_bytes(),
                    );
                    let sig = account.sign(data);
                    (account, sig)
                });
                self.cache.lock().await.put(account_id, Arc::new(account));
                Ok(sig)
            } else {
                bail!(Error::AccountNotFound(account_id));
            }
        }
    }
}
