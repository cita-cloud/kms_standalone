use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use secrecy::Secret;
use secrecy::SecretString;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

use lru::LruCache;
use parking_lot::Mutex;
use sqlx::MySqlPool;

use tokio::task::block_in_place;

use efficient_sm2::KeyPair;

use rand::Rng;

use crate::sm::{
    pk2address, sm2_gen_keypair, sm2_sign, sm3_hash, sm4_decrypt, sm4_encrypt, Address, PrivateKey,
    Signature,
};

const SALT_BYTES_LEN: usize = 32;
type Salt = [u8; SALT_BYTES_LEN];

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Master password mismatched")]
    MasterPasswordMismatched,
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
            let buf = Secret::new([master_password, &encrypted.salt].concat());
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
    master_password: SecretString,

    pool: MySqlPool,
    cache: Mutex<LruCache<String, Arc<Account>>>,
}

impl AccountManager {
    pub async fn new(
        db_url: &str,
        master_password: SecretString,
        max_cached_accounts: usize,
        db_max_connections: u32,
        db_conn_timeout_millis: u64,
        db_conn_idle_timeout_millis: u64,
    ) -> Result<Self> {
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(db_max_connections)
            .connect_timeout(Duration::from_millis(db_conn_timeout_millis))
            .idle_timeout(Duration::from_millis(db_conn_idle_timeout_millis))
            .connect(db_url)
            .await
            .context("cannot connect to database")?;
        sqlx::migrate!()
            .run(&pool)
            .await
            .context("cannot run migration")?;

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
                Secret::new([master_password.expose_secret().as_bytes(), &salt[..]].concat());
            if password_hash != sm3_hash(salted_pw.expose_secret()) {
                bail!(Error::MasterPasswordMismatched);
            }
        } else {
            let salt: Salt = rand::thread_rng().gen();
            let salted_pw_hash = {
                let salted_pw =
                    Secret::new([master_password.expose_secret().as_bytes(), &salt[..]].concat());
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
            master_password,
            pool,
            cache: Mutex::new(LruCache::new(max_cached_accounts)),
        })
    }

    async fn generate_account(&self, account_id: &str) -> Result<Arc<Account>> {
        let (account, encrypted_privkey, salt) = block_in_place(|| {
            let (account, _address, sk) = Account::generate();

            let salt: Salt = rand::thread_rng().gen();
            let encrypted_privkey = {
                let password_hash = {
                    let salted_pw = Secret::new(
                        [self.master_password.expose_secret().as_bytes(), &salt[..]].concat(),
                    );
                    Secret::new(sm3_hash(salted_pw.expose_secret()))
                };
                sm4_encrypt(sk.expose_secret(), password_hash.expose_secret())
            };
            (Arc::new(account), encrypted_privkey, salt)
        });

        sqlx::query!(
            "INSERT INTO Accounts (id, encrypted_privkey, salt) VALUES (?, ?, ?)",
            account_id,
            encrypted_privkey.to_vec(),
            salt.to_vec(),
        )
        .execute(&self.pool)
        .await
        .context("cannot store new account into database")?;

        self.cache
            .lock()
            .put(account_id.into(), Arc::clone(&account));

        Ok(account)
    }

    pub async fn sign_with(&self, account_id: &str, msgs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        let account = self
            .fetch_or_create_account(account_id)
            .await
            .with_context(|| format!("cannot fetch or create account `{}`", account_id))?;

        let sigs: Vec<Vec<u8>> = block_in_place(|| {
            use rayon::prelude::*;
            msgs.into_par_iter()
                .map(|msg| account.sign(msg).into())
                .collect()
        });

        Ok(sigs)
    }

    async fn fetch_or_create_account(&self, account_id: &str) -> Result<Arc<Account>> {
        let account = self.cache.lock().get(account_id).cloned();
        match account {
            Some(account) => Ok(account),
            None => {
                let encrypted = sqlx::query_as!(
                    EncryptedAccount,
                    "SELECT encrypted_privkey, salt FROM Accounts WHERE id=?",
                    account_id
                )
                .fetch_optional(&self.pool)
                .await
                .context("cannot fetch account from database")?;

                if let Some(encrypted) = encrypted {
                    block_in_place(|| {
                        let account = {
                            let account = Account::from_encrypted(
                                &encrypted,
                                self.master_password.expose_secret().as_bytes(),
                            );
                            Arc::new(account)
                        };
                        self.cache
                            .lock()
                            .put(account_id.into(), Arc::clone(&account));
                        Ok(account)
                    })
                } else {
                    self.generate_account(account_id).await
                        .context("No account for the requested `account_id`, and fail to create a new account for it")
                }
            }
        }
    }
}
