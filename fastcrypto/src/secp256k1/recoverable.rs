// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [ECDSA signature scheme](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) over the [secp256k1 curve](http://www.secg.org/sec2-v2.pdf).
//!
//! Messages can be signed and the public key can be recovered from the signature:
//! # Example
//! ```rust
//! # use fastcrypto::secp256k1::recoverable::*;
//! # use fastcrypto::traits::{KeyPair, Signer, VerifyingKey};
//! # use fastcrypto::traits::{RecoverableSignature, RecoverableSigner};
//! use rand::thread_rng;
//! let kp = Secp256k1RecoverableKeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign(message);
//! assert_eq!(&signature.recover(message).unwrap(), kp.public());
//! ```

use crate::hash::HashFunction;
use crate::secp256k1::{DefaultHash, PublicKey, Secp256k1Signature, SecretKey};
use crate::serde_helpers::BytesRepresentation;
use crate::traits::{
    AllowedRng, Authenticator, KeyPair, RecoverableSignature, RecoverableSigner, Signer,
    SigningKey, VerifyRecoverable, VerifyingKey,
};
use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    generate_bytes_representation, impl_base64_display_fmt,
    serialize_deserialize_with_to_from_bytes,
    traits::{EncodeDecodeBase64, ToFromBytes},
};
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use once_cell::sync::{Lazy, OnceCell};
pub use rust_secp256k1::ecdsa::Signature as Secp256k1Sig;
use rust_secp256k1::{
    constants,
    ecdsa::{RecoverableSignature as ExternalRecoverableSignature, RecoveryId},
    All, Message, Secp256k1,
};
use std::fmt::{self, Debug};
use std::str::FromStr;
use zeroize::Zeroize;

pub static SECP256K1: Lazy<Secp256k1<All>> = Lazy::new(rust_secp256k1::Secp256k1::new);

/// Length of a compact signature followed by one extra byte for recovery id, used to recover the public key from a signature.
pub const SECP256K1_RECOVERABLE_SIGNATURE_LENGTH: usize = constants::COMPACT_SIGNATURE_SIZE + 1;

/// The length of a public key in bytes.
pub const SECP256K1_RECOVERABLE_PUBLIC_KEY_LENGTH: usize = constants::PUBLIC_KEY_SIZE;

/// The length of a private key in bytes.
pub const SECP256K1_RECOVERABLE_PRIVATE_KEY_LENGTH: usize = constants::SECRET_KEY_SIZE;

/// The key pair bytes length is the same as the private key length. This enforces deserialization to always derive the public key from the private key.
pub const SECP256K1_RECOVERABLE_KEYPAIR_LENGTH: usize = constants::SECRET_KEY_SIZE;

/// Secp256k1 public/private key pair.
#[derive(Debug, PartialEq, Eq)]
pub struct Secp256k1RecoverableKeyPair {
    pub public: Secp256k1RecoverablePublicKey,
    pub secret: Secp256k1RecoverablePrivateKey,
}

/// Secp256k1 public key.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256k1RecoverablePublicKey {
    pub pubkey: PublicKey,
    pub bytes: OnceCell<[u8; SECP256K1_RECOVERABLE_PUBLIC_KEY_LENGTH]>,
}

/// Secp256k1 private key.
#[readonly::make]
#[derive(SilentDebug, SilentDisplay)]
pub struct Secp256k1RecoverablePrivateKey {
    pub privkey: SecretKey,
    pub bytes: OnceCell<zeroize::Zeroizing<[u8; SECP256K1_RECOVERABLE_PRIVATE_KEY_LENGTH]>>,
}

/// Secp256k1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256k1RecoverableSignature {
    pub sig: ExternalRecoverableSignature,
    pub bytes: OnceCell<[u8; SECP256K1_RECOVERABLE_SIGNATURE_LENGTH]>,
}

// Recoverable public key implementation

impl std::hash::Hash for Secp256k1RecoverablePublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialOrd for Secp256k1RecoverablePublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.pubkey.partial_cmp(&other.pubkey)
    }
}

impl Ord for Secp256k1RecoverablePublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.pubkey.cmp(&other.pubkey)
    }
}

impl PartialEq for Secp256k1RecoverablePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
    }
}

impl Eq for Secp256k1RecoverablePublicKey {}

impl VerifyingKey for Secp256k1RecoverablePublicKey {
    type PrivKey = Secp256k1RecoverablePrivateKey;
    type Sig = Secp256k1RecoverableSignature;
    const LENGTH: usize = constants::PUBLIC_KEY_SIZE;

    /// Verify a recoverable signature by recovering the public key and compare it to self.
    fn verify(
        &self,
        msg: &[u8],
        signature: &Secp256k1RecoverableSignature,
    ) -> Result<(), FastCryptoError> {
        // Sha256 is used by default as digest
        self.verify_recoverable_with_hash::<DefaultHash>(msg, signature)
            .map_err(|_| FastCryptoError::InvalidSignature)
    }
}

impl Secp256k1RecoverablePublicKey {
    /// Verify a recoverable signature by recovering the public key and compare it to self.
    /// The recovery is using the given hash function.
    ///
    /// Note: This is currently only used for Secp256r1 and Secp256k1 where the hash function must have 32 byte output.
    pub fn verify_recoverable_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
        signature: &Secp256k1RecoverableSignature,
    ) -> Result<(), FastCryptoError> {
        match signature.recover_with_hash::<H>(msg)? == *self {
            true => Ok(()),
            false => Err(FastCryptoError::InvalidSignature),
        }
    }
}

impl AsRef<[u8]> for Secp256k1RecoverablePublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init::<_>(|| self.pubkey.serialize())
    }
}

impl ToFromBytes for Secp256k1RecoverablePublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match PublicKey::from_slice(bytes) {
            Ok(pubkey) => Ok(Secp256k1RecoverablePublicKey {
                pubkey,
                bytes: OnceCell::new(),
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl_base64_display_fmt!(Secp256k1RecoverablePublicKey);

serialize_deserialize_with_to_from_bytes!(
    Secp256k1RecoverablePublicKey,
    SECP256K1_RECOVERABLE_PUBLIC_KEY_LENGTH
);
generate_bytes_representation!(
    Secp256k1RecoverablePublicKey,
    SECP256K1_RECOVERABLE_PUBLIC_KEY_LENGTH,
    Secp256k1RecoverablePublicKeyAsBytes
);

impl<'a> From<&'a Secp256k1RecoverablePrivateKey> for Secp256k1RecoverablePublicKey {
    fn from(secret: &'a Secp256k1RecoverablePrivateKey) -> Self {
        Secp256k1RecoverablePublicKey {
            pubkey: secret.privkey.public_key(&SECP256K1),
            bytes: OnceCell::new(),
        }
    }
}

// Recoverable private key implementation

impl SigningKey for Secp256k1RecoverablePrivateKey {
    type PubKey = Secp256k1RecoverablePublicKey;
    type Sig = Secp256k1RecoverableSignature;
    const LENGTH: usize = constants::SECRET_KEY_SIZE;
}

impl ToFromBytes for Secp256k1RecoverablePrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match SecretKey::from_slice(bytes) {
            Ok(privkey) => Ok(Secp256k1RecoverablePrivateKey {
                privkey,
                bytes: OnceCell::new(),
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl PartialEq for Secp256k1RecoverablePrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.privkey == other.privkey
    }
}

impl Eq for Secp256k1RecoverablePrivateKey {}

serialize_deserialize_with_to_from_bytes!(
    Secp256k1RecoverablePrivateKey,
    SECP256K1_RECOVERABLE_PRIVATE_KEY_LENGTH
);

impl AsRef<[u8]> for Secp256k1RecoverablePrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_init::<_>(|| zeroize::Zeroizing::new(self.privkey.secret_bytes()))
            .as_ref()
    }
}

impl zeroize::Zeroize for Secp256k1RecoverablePrivateKey {
    fn zeroize(&mut self) {
        // Unwrap is safe here because we are using a constant and it has been tested
        // (see fastcrypto/src/tests/secp256k1_tests::test_sk_zeroization_on_drop)
        self.privkey = SecretKey::from_slice(&constants::ONE).unwrap();
        self.bytes.take().zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for Secp256k1RecoverablePrivateKey {}

impl Drop for Secp256k1RecoverablePrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Recoverable sig implementation

serialize_deserialize_with_to_from_bytes!(
    Secp256k1RecoverableSignature,
    SECP256K1_RECOVERABLE_SIGNATURE_LENGTH
);
generate_bytes_representation!(
    Secp256k1RecoverableSignature,
    SECP256K1_RECOVERABLE_SIGNATURE_LENGTH,
    Secp256k1RecoverableSignatureAsBytes
);

impl ToFromBytes for Secp256k1RecoverableSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != SECP256K1_RECOVERABLE_SIGNATURE_LENGTH {
            return Err(FastCryptoError::InputLengthWrong(
                SECP256K1_RECOVERABLE_SIGNATURE_LENGTH,
            ));
        }
        RecoveryId::from_i32(bytes[SECP256K1_RECOVERABLE_SIGNATURE_LENGTH - 1] as i32)
            .and_then(|rec_id| {
                ExternalRecoverableSignature::from_compact(
                    &bytes[..(SECP256K1_RECOVERABLE_SIGNATURE_LENGTH - 1)],
                    rec_id,
                )
                .map(|sig| Secp256k1RecoverableSignature {
                    sig,
                    bytes: OnceCell::new(),
                })
            })
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl Authenticator for Secp256k1RecoverableSignature {
    type PubKey = Secp256k1RecoverablePublicKey;
    type PrivKey = Secp256k1RecoverablePrivateKey;
    const LENGTH: usize = SECP256K1_RECOVERABLE_SIGNATURE_LENGTH;
}

impl AsRef<[u8]> for Secp256k1RecoverableSignature {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init::<_>(|| {
            let mut bytes = [0u8; SECP256K1_RECOVERABLE_SIGNATURE_LENGTH];
            let (recovery_id, sig) = self.sig.serialize_compact();
            bytes[..(SECP256K1_RECOVERABLE_SIGNATURE_LENGTH - 1)].copy_from_slice(&sig);
            bytes[(SECP256K1_RECOVERABLE_SIGNATURE_LENGTH - 1)] = recovery_id.to_i32() as u8;
            bytes
        })
    }
}

impl std::hash::Hash for Secp256k1RecoverableSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for Secp256k1RecoverableSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for Secp256k1RecoverableSignature {}

impl_base64_display_fmt!(Secp256k1RecoverableSignature);

impl Secp256k1RecoverableSignature {
    /// Convert a non-recoverable signature into a recoverable signature.
    pub fn try_from_nonrecoverable(
        signature: &Secp256k1Signature,
        pk: &Secp256k1RecoverablePublicKey,
        message: &[u8],
    ) -> Result<Self, FastCryptoError> {
        // Secp256k1Signature::as_bytes is guaranteed to return SECP256K1_SIGNATURE_LENGTH = SECP256K1_RECOVERABLE_SIGNATURE_SIZE - 1 bytes.
        let mut recoverable_signature_bytes = [0u8; SECP256K1_RECOVERABLE_SIGNATURE_LENGTH];
        recoverable_signature_bytes[0..SECP256K1_RECOVERABLE_SIGNATURE_LENGTH - 1]
            .copy_from_slice(signature.as_ref());

        for recovery_id in 0..4 {
            recoverable_signature_bytes[SECP256K1_RECOVERABLE_SIGNATURE_LENGTH - 1] = recovery_id;
            let recoverable_signature = <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(
                &recoverable_signature_bytes,
            )?;
            if pk
                .verify_recoverable(message, &recoverable_signature)
                .is_ok()
            {
                return Ok(recoverable_signature);
            }
        }
        Err(FastCryptoError::InvalidInput)
    }
}

impl RecoverableSignature for Secp256k1RecoverableSignature {
    type PubKey = Secp256k1RecoverablePublicKey;
    type Signer = Secp256k1RecoverableKeyPair;
    type DefaultHash = DefaultHash;

    /// Recover public key from signature using the given hash function to hash the message.
    fn recover_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
    ) -> Result<Secp256k1RecoverablePublicKey, FastCryptoError> {
        match Message::from_slice(&H::digest(msg).digest) {
            Ok(message) => match self.sig.recover(&message) {
                Ok(pubkey) => {
                    Secp256k1RecoverablePublicKey::from_bytes(pubkey.serialize().as_slice())
                }
                Err(_) => Err(FastCryptoError::GeneralOpaqueError),
            },
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl RecoverableSigner for Secp256k1RecoverableKeyPair {
    type PubKey = Secp256k1RecoverablePublicKey;
    type Sig = Secp256k1RecoverableSignature;

    /// Create a new recoverable signature over the given message. The hash function `H` is used to hash the message.
    fn sign_recoverable_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
    ) -> Secp256k1RecoverableSignature {
        let secp = Secp256k1::signing_only();
        let message = Message::from_slice(H::digest(msg).as_ref()).unwrap();

        // Creates a 65-bytes sigature of shape [r, s, v] where v can be 0 or 1.
        // Pseudo-random deterministic nonce generation is used according to RFC6979.
        Secp256k1RecoverableSignature {
            sig: secp.sign_ecdsa_recoverable(&message, &self.secret.privkey),
            bytes: OnceCell::new(),
        }
    }
}

impl VerifyRecoverable for Secp256k1RecoverablePublicKey {
    type Sig = Secp256k1RecoverableSignature;
}

// Recoverable key pair implementation

/// The bytes form of the keypair always only contain the private key bytes
impl ToFromBytes for Secp256k1RecoverableKeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Secp256k1RecoverablePrivateKey::from_bytes(bytes).map(|secret| secret.into())
    }
}

serialize_deserialize_with_to_from_bytes!(
    Secp256k1RecoverableKeyPair,
    SECP256K1_RECOVERABLE_KEYPAIR_LENGTH
);

impl AsRef<[u8]> for Secp256k1RecoverableKeyPair {
    fn as_ref(&self) -> &[u8] {
        self.secret.as_ref()
    }
}

impl KeyPair for Secp256k1RecoverableKeyPair {
    type PubKey = Secp256k1RecoverablePublicKey;
    type PrivKey = Secp256k1RecoverablePrivateKey;
    type Sig = Secp256k1RecoverableSignature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.public
    }

    fn private(self) -> Self::PrivKey {
        Secp256k1RecoverablePrivateKey::from_bytes(self.secret.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        Secp256k1RecoverableKeyPair {
            public: self.public.clone(),
            secret: Secp256k1RecoverablePrivateKey::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let (privkey, pubkey) = SECP256K1.generate_keypair(rng);

        Secp256k1RecoverableKeyPair {
            public: Secp256k1RecoverablePublicKey {
                pubkey,
                bytes: OnceCell::new(),
            },
            secret: Secp256k1RecoverablePrivateKey {
                privkey,
                bytes: OnceCell::new(),
            },
        }
    }
}

impl FromStr for Secp256k1RecoverableKeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

impl Secp256k1RecoverableKeyPair {
    /// Create a new recoverable signature over the given message. The hash function `H` is used to hash the message.
    fn sign_recoverable_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
    ) -> Secp256k1RecoverableSignature {
        let secp = Secp256k1::signing_only();
        let message = Message::from_slice(H::digest(msg).as_ref()).unwrap();

        // Creates a 65-bytes sigature of shape [r, s, v] where v can be 0 or 1.
        // Pseudo-random deterministic nonce generation is used according to RFC6979.
        Secp256k1RecoverableSignature {
            sig: secp.sign_ecdsa_recoverable(&message, &self.secret.privkey),
            bytes: OnceCell::new(),
        }
    }
}

impl Signer<Secp256k1RecoverableSignature> for Secp256k1RecoverableKeyPair {
    fn sign(&self, msg: &[u8]) -> Secp256k1RecoverableSignature {
        // Sha256 is used by default
        self.sign_recoverable_with_hash::<DefaultHash>(msg)
    }
}

impl From<Secp256k1RecoverablePrivateKey> for Secp256k1RecoverableKeyPair {
    fn from(secret: Secp256k1RecoverablePrivateKey) -> Self {
        let public = Secp256k1RecoverablePublicKey::from(&secret);
        Secp256k1RecoverableKeyPair { public, secret }
    }
}
