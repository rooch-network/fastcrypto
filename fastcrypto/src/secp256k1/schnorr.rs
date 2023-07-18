// Copyright (c) 2022, Rooch Network.
// SPDX-License-Identifier: Apache-2.0

//! TODO Multiple Schnorr signatures MuSig2 [https://github.com/jonasnick/bips/blob/90133b00affd7d10389fbde42ada68ff08563e1e/bip-musig2.mediawiki].
//! This module contains an implementation of the [Schnorr signature scheme](https://en.wikipedia.org/wiki/Schnorr_signature) over the [secp256k1 curve](http://www.secg.org/sec2-v2.pdf).
//!
//! Messages can be signed and the private key can be recovered from the signed messages using the same secret nounce:
//! # Example
//! ```rust
//! # use fastcrypto::secp256k1::schnorr::*;
//! # use fastcrypto::traits::{KeyPair, Signer, VerifyingKey};
//! use rust_secp256k1::{Message, Secp256k1};
//! use rand::*;
//! let mut rng = thread_rng();
//! let kp = SchnorrKeyPair::generate(&mut rng);
//! let message: [u8; 32] = random();
//! let signature: SchnorrSignature = kp.sign(&message);
//! assert!(kp.public().verify(&message, &signature).is_ok());
//! ```
use crate::hash::{HashFunction, Sha256};
use crate::serde_helpers::BytesRepresentation;
use crate::traits::{Signer, SigningKey};
use crate::{
    encoding::Base64,
    error::FastCryptoError,
    impl_base64_display_fmt,
    traits::{AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, ToFromBytes, VerifyingKey},
};
use crate::{
    encoding::Encoding, generate_bytes_representation, serialize_deserialize_with_to_from_bytes,
};
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use once_cell::sync::{Lazy, OnceCell};
use rust_secp256k1::Message;
use rust_secp256k1::{
    constants, schnorr::Signature, All, KeyPair as Secp256k1KeyPair, Secp256k1, SecretKey,
    XOnlyPublicKey,
};
use std::{
    fmt::{self, Debug},
    str::FromStr,
};
use zeroize::Zeroize;

pub static SECP256K1: Lazy<Secp256k1<All>> = Lazy::new(rust_secp256k1::Secp256k1::new);

/// The length of a public key in bytes.
pub const SCHNORR_PUBLIC_KEY_LENGTH: usize = constants::SCHNORR_PUBLIC_KEY_SIZE;

/// The length of a private key in bytes.
pub const SCHNORR_PRIVATE_KEY_LENGTH: usize = constants::SECRET_KEY_SIZE;

/// The length of a signature in bytes.
pub const SCHNORR_SIGNATURE_LENGTH: usize = constants::SCHNORR_SIGNATURE_SIZE;

/// The key pair bytes length is the same as the private key length. This enforces deserialization to always derive the public key from the private key.
pub const SCHNORR_KEYPAIR_LENGTH: usize = constants::SECRET_KEY_SIZE;

/// Default hash function used for signing and verifying messages unless another hash function is
/// specified using the `with_hash` functions.
pub type DefaultHash = Sha256;

/// Schnorr public key.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct SchnorrPublicKey {
    pub pubkey: XOnlyPublicKey,
    pub bytes: OnceCell<[u8; SCHNORR_PUBLIC_KEY_LENGTH]>,
}

/// Schnorr private key.
#[readonly::make]
#[derive(SilentDebug, SilentDisplay)]
pub struct SchnorrPrivateKey {
    pub privkey: SecretKey,
    pub bytes: OnceCell<zeroize::Zeroizing<[u8; SCHNORR_PRIVATE_KEY_LENGTH]>>,
}

/// Schnorr key pair.
#[derive(Debug, PartialEq, Eq)]
pub struct SchnorrKeyPair {
    pub public: SchnorrPublicKey,
    pub secret: SchnorrPrivateKey,
}

/// Schnorr signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct SchnorrSignature {
    pub sig: Signature,
    pub bytes: OnceCell<[u8; SCHNORR_SIGNATURE_LENGTH]>,
}

//
// Implementation of [SchnorrPrivateKey].
//

impl SigningKey for SchnorrPrivateKey {
    type PubKey = SchnorrPublicKey;
    type Sig = SchnorrSignature;
    const LENGTH: usize = SCHNORR_PRIVATE_KEY_LENGTH;
}

impl ToFromBytes for SchnorrPrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match SecretKey::from_slice(bytes) {
            Ok(privkey) => Ok(SchnorrPrivateKey {
                privkey,
                bytes: OnceCell::new(),
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl PartialEq for SchnorrPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.privkey == other.privkey
    }
}

impl Eq for SchnorrPrivateKey {}

serialize_deserialize_with_to_from_bytes!(SchnorrPrivateKey, SCHNORR_PRIVATE_KEY_LENGTH);

impl AsRef<[u8]> for SchnorrPrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_init::<_>(|| zeroize::Zeroizing::new(self.privkey.secret_bytes()))
            .as_ref()
    }
}

impl zeroize::Zeroize for SchnorrPrivateKey {
    fn zeroize(&mut self) {
        // Unwrap is safe here because we are using a constant and it has been tested
        // (see fastcrypto/src/tests/secp256k1_tests::test_sk_zeroization_on_drop)
        self.privkey = SecretKey::from_slice(&constants::ONE).unwrap();
        self.bytes.take().zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for SchnorrPrivateKey {}

impl Drop for SchnorrPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

//
// Implementation of [SchnorrKeyPair].
//

impl From<SchnorrPrivateKey> for SchnorrKeyPair {
    fn from(secret: SchnorrPrivateKey) -> Self {
        let public = SchnorrPublicKey::from(&secret);
        SchnorrKeyPair { public, secret }
    }
}

impl ToFromBytes for SchnorrKeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        SchnorrPrivateKey::from_bytes(bytes).map(|secret| secret.into())
    }
}

impl AsRef<[u8]> for SchnorrKeyPair {
    fn as_ref(&self) -> &[u8] {
        self.secret.as_ref()
    }
}

serialize_deserialize_with_to_from_bytes!(SchnorrKeyPair, SCHNORR_KEYPAIR_LENGTH);

impl KeyPair for SchnorrKeyPair {
    type PubKey = SchnorrPublicKey;
    type PrivKey = SchnorrPrivateKey;
    type Sig = SchnorrSignature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.public
    }

    fn private(self) -> Self::PrivKey {
        SchnorrPrivateKey::from_bytes(self.secret.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        SchnorrKeyPair {
            public: self.public.clone(),
            secret: SchnorrPrivateKey::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let (privkey, pubkey) = SECP256K1.generate_keypair(rng);
        SchnorrKeyPair {
            public: SchnorrPublicKey {
                pubkey: pubkey.x_only_public_key().0,
                bytes: OnceCell::new(),
            },
            secret: SchnorrPrivateKey {
                privkey,
                bytes: OnceCell::new(),
            },
        }
    }
}

impl FromStr for SchnorrKeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

impl SchnorrKeyPair {
    /// Create a new signature using the given hash function to hash the message.
    pub fn sign_with_hash<H: HashFunction<32>>(&self, msg: &[u8]) -> SchnorrSignature {
        let message = Message::from_slice(H::digest(msg).as_ref()).unwrap();
        let keypair = Secp256k1KeyPair::from_secret_key(&SECP256K1, &self.secret.privkey);

        SchnorrSignature {
            sig: Secp256k1::signing_only().sign_schnorr(&message, &keypair),
            bytes: OnceCell::new(),
        }
    }
}

impl Signer<SchnorrSignature> for SchnorrKeyPair {
    fn sign(&self, msg: &[u8]) -> SchnorrSignature {
        self.sign_with_hash::<DefaultHash>(msg)
    }
}

//
// Implementation Authenticator of [SchnorrSignature].
//

serialize_deserialize_with_to_from_bytes!(SchnorrSignature, SCHNORR_SIGNATURE_LENGTH);
generate_bytes_representation!(
    SchnorrSignature,
    SCHNORR_SIGNATURE_LENGTH,
    SchnorrSignatureAsBytes
);

impl_base64_display_fmt!(SchnorrSignature);

impl PartialEq for SchnorrSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for SchnorrSignature {}

impl Authenticator for SchnorrSignature {
    type PubKey = SchnorrPublicKey;
    type PrivKey = SchnorrPrivateKey;
    const LENGTH: usize = SCHNORR_SIGNATURE_LENGTH;
}

impl ToFromBytes for SchnorrSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != SCHNORR_SIGNATURE_LENGTH {
            return Err(FastCryptoError::InputLengthWrong(SCHNORR_SIGNATURE_LENGTH));
        }
        Signature::from_slice(bytes)
            .map(|sig| SchnorrSignature {
                sig,
                bytes: OnceCell::new(),
            })
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl AsRef<[u8]> for SchnorrSignature {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init::<_>(|| *self.sig.as_ref())
    }
}

impl std::hash::Hash for SchnorrSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl From<&Signature> for SchnorrSignature {
    fn from(schnorr_signature: &Signature) -> Self {
        SchnorrSignature {
            sig: *schnorr_signature,
            bytes: OnceCell::new(),
        }
    }
}

//
// Implementation VerifyingKey of [SchnorrPublicKey].
//

impl<'a> From<&'a SchnorrPrivateKey> for SchnorrPublicKey {
    fn from(secret: &'a SchnorrPrivateKey) -> Self {
        SchnorrPublicKey {
            pubkey: secret.privkey.x_only_public_key(&SECP256K1).0,
            bytes: OnceCell::new(),
        }
    }
}

impl ToFromBytes for SchnorrPublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match XOnlyPublicKey::from_slice(bytes) {
            Ok(pubkey) => Ok(SchnorrPublicKey {
                pubkey,
                bytes: OnceCell::new(),
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl std::hash::Hash for SchnorrPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialOrd for SchnorrPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.pubkey.partial_cmp(&other.pubkey)
    }
}

impl Ord for SchnorrPublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.pubkey.cmp(&other.pubkey)
    }
}

impl PartialEq for SchnorrPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
    }
}

impl Eq for SchnorrPublicKey {}

impl AsRef<[u8]> for SchnorrPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init::<_>(|| self.pubkey.serialize())
    }
}

impl_base64_display_fmt!(SchnorrPublicKey);

serialize_deserialize_with_to_from_bytes!(SchnorrPublicKey, SCHNORR_PUBLIC_KEY_LENGTH);
generate_bytes_representation!(
    SchnorrPublicKey,
    SCHNORR_PUBLIC_KEY_LENGTH,
    SchnorrPublicKeyAsBytes
);
impl VerifyingKey for SchnorrPublicKey {
    type PrivKey = SchnorrPrivateKey;
    type Sig = SchnorrSignature;
    const LENGTH: usize = SCHNORR_PUBLIC_KEY_LENGTH;

    fn verify(&self, msg: &[u8], signature: &SchnorrSignature) -> Result<(), FastCryptoError> {
        self.verify_with_hash::<DefaultHash>(msg, signature)
            .map_err(|_| FastCryptoError::InvalidSignature)
    }
}

impl SchnorrPublicKey {
    /// Verify the signature using the given hash function to hash the message.
    pub fn verify_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
        signature: &SchnorrSignature,
    ) -> Result<(), FastCryptoError> {
        // This fails if the output of the hash function is not 32 bytes, but that is ensured by the def of H.
        let hashed_message = Message::from_slice(H::digest(msg).as_ref()).unwrap();
        signature
            .sig
            .verify(&hashed_message, &self.pubkey)
            .map_err(|_| FastCryptoError::InvalidSignature)
    }
}
