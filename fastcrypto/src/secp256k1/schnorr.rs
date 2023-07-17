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
//! # use fastcrypto::secp256k1::Secp256k1KeyPair;
//! # use rust_secp256k1::Message;
//! use rand::thread_rng;
//! let kp = Secp256k1KeyPair::generate(&mut thread_rng());
//! let message: Message = Message::from_slice(b"Hello, world!").unwrap();
//! let signature = kp.sign_schnorr(&message);
//! let pubkey = kp.x_only_public_key(&Secp256k1::new()).0;
//! assert!(signature.verify(self, &message, &pubkey).is_ok());
//! ```
use crate::serde_helpers::{to_custom_error, BytesRepresentation};
use crate::traits::{InsecureDefault, Signer, SigningKey};
use crate::{
    encoding::Base64,
    error::FastCryptoError,
    impl_base64_display_fmt,
    traits::{AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, ToFromBytes, VerifyingKey},
};
use crate::{
    encoding::Encoding, generate_bytes_representation, serialize_deserialize_with_to_from_bytes,
};
use base64ct::Encoding as _;
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use once_cell::sync::OnceCell;
use rust_secp256k1::Message;
use rust_secp256k1::{
    constants::{KEY_PAIR_SIZE, SCHNORR_PUBLIC_KEY_SIZE, SCHNORR_SIGNATURE_SIZE, SECRET_KEY_SIZE},
    schnorr::Signature,
    KeyPair as Secp256k1KeyPair, Secp256k1, SecretKey, XOnlyPublicKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{Bytes as SerdeBytes, DeserializeAs, SerializeAs};
use std::borrow::Borrow;
use std::{
    fmt::{self, Debug},
    str::FromStr,
};

/// Schnorr public key.
#[derive(Clone, PartialEq, Eq)]
pub struct SchnorrPublicKey {
    pub pubkey: XOnlyPublicKey,
    // TODO Replace serialize() to AsRef<[u8]> - Helps implementing AsRef<[u8]>.
    pub bytes: OnceCell<[u8; SCHNORR_PUBLIC_KEY_SIZE]>,
}

/// Schnorr private key.
#[derive(SilentDebug, SilentDisplay)]
pub struct SchnorrPrivateKey(pub SecretKey);

/// Schnorr key pair.
#[derive(Debug, PartialEq, Eq)]
pub struct SchnorrKeyPair {
    public: SchnorrPublicKey,
    private: SchnorrPrivateKey,
}

/// Schnorr signature.
#[derive(Debug, Clone)]
pub struct SchnorrSignature {
    pub sig: Signature,
    // Helps implementing AsRef<[u8]>.
    pub bytes: OnceCell<[u8; SCHNORR_SIGNATURE_SIZE]>,
}

//
// Implementation of [SchnorrPrivateKey].
//

impl PartialEq for SchnorrPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for SchnorrPrivateKey {}

// implement AsRef for SchnorrPrivateKey
impl AsRef<[u8]> for SchnorrPrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl SigningKey for SchnorrPrivateKey {
    type PubKey = SchnorrPublicKey;
    type Sig = SchnorrSignature;
    const LENGTH: usize = SECRET_KEY_SIZE;
}

impl ToFromBytes for SchnorrPrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        SecretKey::from_slice(bytes)
            .map(SchnorrPrivateKey)
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

serialize_deserialize_with_to_from_bytes!(SchnorrPrivateKey, SECRET_KEY_SIZE);

//
// Implementation of [SchnorrKeyPair].
//

impl From<SchnorrPrivateKey> for SchnorrKeyPair {
    fn from(private: SchnorrPrivateKey) -> Self {
        let public = SchnorrPublicKey::from(&private);
        SchnorrKeyPair { public, private }
    }
}

impl ToFromBytes for SchnorrKeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        SchnorrPrivateKey::from_bytes(bytes).map(|private| private.into())
    }
}

impl AsRef<[u8]> for SchnorrKeyPair {
    fn as_ref(&self) -> &[u8] {
        self.private.as_ref()
    }
}

serialize_deserialize_with_to_from_bytes!(SchnorrKeyPair, KEY_PAIR_SIZE);

impl KeyPair for SchnorrKeyPair {
    type PubKey = SchnorrPublicKey;
    type PrivKey = SchnorrPrivateKey;
    type Sig = SchnorrSignature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.public
    }

    fn private(self) -> Self::PrivKey {
        SchnorrPrivateKey::from_bytes(self.private.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        Self {
            public: SchnorrPublicKey::from_bytes(self.public.as_ref()).unwrap(),
            private: SchnorrPrivateKey::from_bytes(self.private.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let kp = SecretKey::new(rng);
        SchnorrKeyPair {
            public: SchnorrPublicKey {
                pubkey: kp.x_only_public_key(&Secp256k1::new()).0,
                bytes: OnceCell::new(),
            },
            private: SchnorrPrivateKey(kp),
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

impl From<SecretKey> for SchnorrKeyPair {
    fn from(kp: SecretKey) -> Self {
        SchnorrKeyPair {
            public: SchnorrPublicKey {
                pubkey: kp.x_only_public_key(&Secp256k1::new()).0,
                bytes: OnceCell::new(),
            },
            private: SchnorrPrivateKey(kp),
        }
    }
}

impl Signer<SchnorrSignature> for SchnorrKeyPair {
    fn sign(&self, msg: &[u8]) -> SchnorrSignature {
        let keypair = Secp256k1KeyPair::from_secret_key(&Secp256k1::new(), &self.private.0);
        SchnorrSignature {
            sig: keypair.sign_schnorr(Message::from_slice(msg).unwrap()),
            bytes: OnceCell::new(),
        }
    }
}

//
// Implementation Authenticator of [SchnorrSignature].
//

serialize_deserialize_with_to_from_bytes!(SchnorrSignature, SCHNORR_SIGNATURE_SIZE);
generate_bytes_representation!(
    SchnorrSignature,
    SCHNORR_SIGNATURE_SIZE,
    SchnorrSignatureAsBytes
);

impl PartialEq for SchnorrSignature {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for SchnorrSignature {}

impl Authenticator for SchnorrSignature {
    type PubKey = SchnorrPublicKey;
    type PrivKey = SchnorrPrivateKey;
    const LENGTH: usize = SCHNORR_SIGNATURE_SIZE;
}

impl ToFromBytes for SchnorrSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
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

impl_base64_display_fmt!(SchnorrSignature);

impl Default for SchnorrSignature {
    fn default() -> Self {
        SchnorrSignature::from_bytes(&[1u8; SCHNORR_SIGNATURE_SIZE]).unwrap()
    }
}

//
// Implementation VerifyingKey of [SchnorrPublicKey].
//

impl<'a> From<&'a SchnorrPrivateKey> for SchnorrPublicKey {
    fn from(private: &'a SchnorrPrivateKey) -> Self {
        SchnorrPublicKey {
            pubkey: private.0.x_only_public_key(&Secp256k1::new()).0,
            bytes: OnceCell::new(),
        }
    }
}

impl ToFromBytes for SchnorrPublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        XOnlyPublicKey::from_slice(bytes)
            .map(|public| SchnorrPublicKey {
                pubkey: public,
                bytes: OnceCell::new(),
            })
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl InsecureDefault for SchnorrPublicKey {
    fn insecure_default() -> Self {
        SchnorrPublicKey::from_bytes(&[0u8; 32]).unwrap()
    }
}

impl Debug for SchnorrPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64::encode(self.as_bytes().as_ref()))
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for SchnorrPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state)
    }
}

impl PartialOrd for SchnorrPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_bytes().partial_cmp(other.as_bytes())
    }
}

impl Ord for SchnorrPublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl AsRef<[u8]> for SchnorrPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init::<_>(|| self.pubkey.serialize())
    }
}

impl_base64_display_fmt!(SchnorrPublicKey);

impl Default for SchnorrPublicKey {
    fn default() -> Self {
        SchnorrPublicKey::from_bytes(&[1u8; SCHNORR_PUBLIC_KEY_SIZE]).unwrap()
    }
}

serialize_deserialize_with_to_from_bytes!(SchnorrPublicKey, SCHNORR_PUBLIC_KEY_SIZE);
generate_bytes_representation!(
    SchnorrPublicKey,
    SCHNORR_PUBLIC_KEY_SIZE,
    SchnorrPublicKeyAsBytes
);
impl VerifyingKey for SchnorrPublicKey {
    type PrivKey = SchnorrPrivateKey;
    type Sig = SchnorrSignature;
    const LENGTH: usize = SCHNORR_PUBLIC_KEY_SIZE;

    fn verify(&self, msg: &[u8], signature: &SchnorrSignature) -> Result<(), FastCryptoError> {
        Secp256k1::verify_schnorr(
            &Secp256k1::new(),
            &signature.sig,
            &Message::from_slice(msg).unwrap(),
            &self.pubkey,
        )
        .map_err(|_| FastCryptoError::InvalidSignature)
    }

    #[cfg(any(test, feature = "experimental"))]
    fn verify_batch_empty_fail(
        _msg: &[u8],
        _pks: &[Self],
        _sigs: &[Self::Sig],
    ) -> Result<(), eyre::Report> {
        todo!()
    }

    #[cfg(any(test, feature = "experimental"))]
    fn verify_batch_empty_fail_different_msg<'a, M>(
        _msgs: &[M],
        _pks: &[Self],
        _sigs: &[Self::Sig],
    ) -> Result<(), eyre::Report>
    where
        M: Borrow<[u8]> + 'a,
    {
        todo!()
    }
}

//
// Serde for a signature
//

pub struct SingleSignature;

impl SerializeAs<Signature> for SingleSignature {
    fn serialize_as<S>(source: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // Serialise to Base64 encoded String
            Base64::encode(source.as_ref()).serialize(serializer)
        } else {
            // Serialise to Bytes
            SerdeBytes::serialize_as(&source.as_ref(), serializer)
        }
    }
}

impl<'de> DeserializeAs<'de, Signature> for SingleSignature {
    fn deserialize_as<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            base64ct::Base64::decode_vec(&s).map_err(to_custom_error::<'de, D, _>)?
        } else {
            SerdeBytes::deserialize_as(deserializer)?
        };
        Signature::from_slice(bytes.as_slice()).map_err(to_custom_error::<'de, D, _>)
    }
}
