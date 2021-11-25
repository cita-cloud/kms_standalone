use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use secrecy::Secret;
use secrecy::SecretVec;

use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;

use parking_lot::Mutex;
use sqlx::MySqlPool;

use tokio::sync::watch;
use tokio::task::block_in_place;

use efficient_sm2::KeyPair;

use rand::Rng;

use crate::sm::{
    addr_from_keypair, sm2_gen_keypair, sm2_sign, sm3_hash, sm4_decrypt, sm4_encrypt, Address,
    PrivateKey, Signature,
};

const SALT_BYTES_LEN: usize = 3;
type Salt = [u8; SALT_BYTES_LEN];

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
#[derive(Clone)]
struct Account(Arc<KeyPair>);

impl Account {
    pub fn generate() -> (Account, Secret<PrivateKey>) {
        let (keypair, sk) = sm2_gen_keypair();
        (Account(Arc::new(keypair)), sk)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        sm2_sign(&self.0, msg)
    }

    pub fn from_encrypted(encrypted: &EncryptedAccount, master_password: &[u8]) -> Result<Self> {
        let sk = {
            // let buf = Secret::new([master_password, &encrypted.salt].concat());
            // let password_hash = Secret::new(sm3_hash(buf.expose_secret()));
            let password = Secret::new([master_password, &encrypted.salt].concat());
            let sk = {
                let hex_sk = Secret::new(sm4_decrypt(
                    &encrypted.encrypted_privkey,
                    password.expose_secret(),
                ));
                let hex_sk = match hex_sk.expose_secret().as_slice() {
                    hex_sk @ [b'0', b'x', ..] => &hex_sk[2..],
                    hex_sk => hex_sk,
                };
                Secret::new(
                    hex::decode(hex_sk).context("invalid private key, must be a hex string")?,
                )
            };
            ensure!(
                sk.expose_secret().len() == std::mem::size_of::<PrivateKey>(),
                "invalid private key, must be 32 bytes array after hex::decode"
            );

            sk
        };
        let keypair =
            KeyPair::new(sk.expose_secret()).expect("construct keypair from private key failed");

        Ok(Account(Arc::new(keypair)))
    }

    pub fn get_address(&self) -> Address {
        addr_from_keypair(&self.0)
    }
}

enum AccountSlot {
    Cached(Account),
    Waiting(watch::Receiver<Option<Account>>),
}

pub struct AccountManager {
    master_password: SecretVec<u8>,

    pool: MySqlPool,
    cache: Mutex<HashMap<String, AccountSlot>>,
}

impl AccountManager {
    pub async fn new(
        db_url: &str,
        master_password: SecretVec<u8>,
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
            let salted_pw = Secret::new([master_password.expose_secret(), &salt[..]].concat());
            ensure!(
                password_hash == sm3_hash(salted_pw.expose_secret()),
                "Master password mismatched"
            );
        } else {
            let salt: Salt = rand::thread_rng().gen();
            let salted_pw_hash = {
                let salted_pw = Secret::new([master_password.expose_secret(), &salt[..]].concat());
                sm3_hash(salted_pw.expose_secret())
            };
            sqlx::query!(
                "INSERT INTO MasterPassword (password_hash, salt) VALUES (?, ?)",
                &salted_pw_hash[..],
                &salt[..]
            )
            .execute(&pool)
            .await
            .context("cannot store master password info into database")?;
        }
        Ok(Self {
            master_password,
            pool,
            cache: Mutex::new(HashMap::new()),
        })
    }

    #[allow(unused)]
    async fn generate_account(&self, account_id: &str) -> Result<Account> {
        let (account, encrypted_privkey, salt) = block_in_place(|| {
            let (account, sk) = Account::generate();

            let salt: Salt = rand::thread_rng().gen();
            let encrypted_privkey = {
                let password =
                    Secret::new([self.master_password.expose_secret(), &salt[..]].concat());
                sm4_encrypt(sk.expose_secret(), password.expose_secret())
            };
            (account, encrypted_privkey, salt)
        });

        self.insert_account(account_id, &encrypted_privkey, &salt)
            .await?;

        Ok(account)
    }

    pub async fn insert_account(
        &self,
        account_id: &str,
        encrypted_privkey: &[u8],
        salt: &[u8],
    ) -> Result<()> {
        ensure!(salt.len() == 3, "salt must be 3 bytes");

        let account = {
            let encrypted = EncryptedAccount {
                encrypted_privkey: encrypted_privkey.to_vec(),
                salt: salt.to_vec(),
            };

            Account::from_encrypted(&encrypted, self.master_password.expose_secret())
                .with_context(|| format!("cannot insert account `{}`", account_id))?
        };

        sqlx::query!(
            "INSERT INTO Accounts (id, encrypted_privkey, salt) VALUES (?, ?, ?)",
            account_id,
            encrypted_privkey,
            salt,
        )
        .execute(&self.pool)
        .await
        .context("cannot store new account into database")?;

        self.cache
            .lock()
            .insert(account_id.into(), AccountSlot::Cached(account));

        Ok(())
    }

    pub async fn sign_with(&self, account_id: &str, msgs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        let account = self
            .fetch_account(account_id)
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

    pub async fn get_account_address(&self, account_id: &str) -> Result<Address> {
        let account = self
            .fetch_account(account_id)
            .await
            .with_context(|| format!("cannot fetch or create account `{}`", account_id))?;

        Ok(account.get_address())
    }

    async fn fetch_account(&self, account_id: &str) -> Result<Account> {
        // Work around `!Send` across await
        enum Either {
            Waiter(watch::Receiver<Option<Account>>),
            Worker(watch::Sender<Option<Account>>),
        }
        let either = {
            let mut guard = self.cache.lock();
            match guard.entry(account_id.into()) {
                Entry::Occupied(e) => match e.get() {
                    AccountSlot::Cached(account) => return Ok(account.clone()),
                    AccountSlot::Waiting(waiter) => {
                        let waiter = waiter.clone();
                        Either::Waiter(waiter)
                    }
                },
                Entry::Vacant(e) => {
                    let (tx, rx) = watch::channel(None);
                    e.insert(AccountSlot::Waiting(rx));
                    Either::Worker(tx)
                }
            }
        };

        let tx = match either {
            Either::Waiter(mut rx) => {
                ensure!(
                    rx.changed().await.is_ok(),
                    "waiting another worker for acquiring account, but that worker seems to fail"
                );
                return Ok(rx
                    .borrow()
                    .clone()
                    .expect("worker never releases a None value"));
            }
            Either::Worker(tx) => tx,
        };

        let encrypted = sqlx::query_as!(
            EncryptedAccount,
            "SELECT encrypted_privkey, salt FROM Accounts WHERE id=?",
            account_id
        )
        .fetch_one(&self.pool)
        .await
        .context("cannot fetch account from database")?;

        let account = block_in_place(|| {
            let account = Account::from_encrypted(&encrypted, self.master_password.expose_secret())
                .with_context(|| format!("cannot fetch account `{}`", account_id))
                .expect("corrupted account data");
            self.cache
                .lock()
                .insert(account_id.into(), AccountSlot::Cached(account.clone()));

            account
        });

        let _ = tx.send(Some(account.clone()));

        Ok(account)
    }
}
