use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::task::block_in_place;

use secrecy::ExposeSecret;
use secrecy::Secret;
use secrecy::SecretVec;

use sqlx::Database;
use sqlx::MySqlPool;
use lru::LruCache;

use rand::Rng;

use crate::sm::{
    Address, PublicKey, PrivateKey, Signature,
    pk2address,
    sm2_gen_keypair, sm2_sign,
    sm3_hash,
    sm4_encrypt, sm4_decrypt
};


const SALT_BYTES_LEN: usize = 16;
type Salt = [u8; SALT_BYTES_LEN];


#[derive(Debug)]
struct EncryptedAccount {
    id: u64,
    pubkey: Vec<u8>,
    encrypted_privkey: Vec<u8>,
    salt: Vec<u8>,
}

#[derive(Debug)]
struct HashAndSalt {
    password_hash: Vec<u8>,
    salt: Vec<u8>,
}

struct Account {
    pk: PublicKey,
    sk: Secret<PrivateKey>,
}

impl Account {
    pub fn generate() -> Self {
        let (pk, sk) = sm2_gen_keypair();
        Self { pk, sk }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        sm2_sign(&self.pk, &self.sk.expose_secret(), msg)
    }

    pub fn from_encrypted(encrypted: &EncryptedAccount, master_password: &[u8]) -> Self {
        let pk = encrypted.pubkey.as_slice().try_into().expect("invalid public key length");
        let sk = {
            let buf = SecretVec::new([master_password, &encrypted.salt].concat());
            let password_hash = Secret::new(sm3_hash(buf.expose_secret()));
            let sk = sm4_decrypt(&encrypted.encrypted_privkey, password_hash.expose_secret(),).try_into().unwrap();
            Secret::new(sk)
        };
        Account {
            pk,
            sk,
        }
    }

    pub fn expose_privkey(&self) -> &PrivateKey {
        self.sk.expose_secret()
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.pk
    }
}

pub struct AccountManager {
    nonce: AtomicU64,

    master_password: SecretVec<u8>,

    pool: MySqlPool,
    cache: Mutex<LruCache<u64, Account>>,
}

impl AccountManager
{
    pub async fn new(db_uri: &str, master_password: SecretVec<u8>) -> Self {
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .connect(db_uri)
            .await
            .unwrap();
        sqlx::migrate!().run(&pool).await.unwrap();

        let hash_and_salt = sqlx::query_as!(
            HashAndSalt,
            "SELECT password_hash, salt FROM MasterPassword"
        )
        .fetch_optional(&pool)
        .await
        .unwrap();

        if let Some(HashAndSalt{ password_hash, salt }) = hash_and_salt {
            let salted_pw = Secret::new([master_password.expose_secret(), salt.as_slice()].concat());
            if password_hash != sm3_hash(salted_pw.expose_secret()) {
                panic!("wrong password");
            }
        } else {
            let salt: Salt = rand::thread_rng().gen();
            let salted_pw_hash = {
                let salted_pw = Secret::new([master_password.expose_secret(), salt.as_slice()].concat());
                sm3_hash(salted_pw.expose_secret())
            };
            sqlx::query!(
                "INSERT INTO MasterPassword (password_hash, salt) VALUES (?, ?)",
                salted_pw_hash.to_vec(),
                salt.to_vec()
            )
            .execute(&pool)
            .await
            .unwrap();
        }
        Self {
            nonce: AtomicU64::new(1),
            master_password,
            pool,
            cache: Mutex::new(LruCache::new(1024))
        }
    }

    pub async fn generate_account(&self, description: &str) -> (u64, Address) {
        // TODO: maybe block_in_place
        let account = Account::generate();
        let address = pk2address(account.pubkey());
        // I think Ordering::Release will do the job
        let account_id = self.nonce.fetch_add(1, Ordering::SeqCst);

        let salt: Salt = rand::thread_rng().gen();
        let encrypted_privkey = {
            let password_hash = {
                let salted_pw = Secret::new([self.master_password.expose_secret(), salt.as_slice()].concat());
                sm3_hash(salted_pw.expose_secret())
            };
            sm4_encrypt(account.expose_privkey(), &password_hash)
        };

        sqlx::query!(
            "INSERT INTO Accounts (id, pubkey, encrypted_privkey, salt, account_description) VALUES (?, ?, ?, ?, ?)",
            account_id,
            account.pubkey().to_vec(),
            encrypted_privkey.to_vec(),
            salt.to_vec(),
            description,
        )
        .execute(&self.pool)
        .await
        .unwrap();

        self.cache.lock().await.put(account_id, account);

        (account_id, address)
    }

    pub async fn sign_with(&self, account_id: u64, data: &[u8]) -> Option<Signature> {
        let mut guard = self.cache.lock().await;
        if let Some(account) = guard.get(&account_id) {
            // TODO: block_in_place
            Some(account.sign(data))
        } else {
            drop(guard);

            let encrypted = sqlx::query_as!(
                EncryptedAccount,
                "SELECT id, pubkey, encrypted_privkey, salt FROM Accounts WHERE id=?", account_id
            )
            .fetch_optional(&self.pool)
            .await
            .unwrap();

            if let Some(encrypted) = encrypted {
                let account = Account::from_encrypted(&encrypted, &self.master_password.expose_secret());
                let sig = account.sign(data);
                self.cache.lock().await.put(account_id, account);
                Some(sig)
            } else {
                None
            }
        }
    }
}
