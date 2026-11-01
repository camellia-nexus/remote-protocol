//! Maintained, wire-compatible cryptographic primitives used by Remote.
//!
//! The public wrappers keep serialized key and ciphertext layouts explicit so
//! protocol consumers do not depend on a particular implementation crate.

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum CryptoError {
    #[error("cryptographic authentication failed")]
    Authentication,
    #[error("cryptographic encryption failed")]
    Encryption,
}

pub mod secretbox {
    use super::CryptoError;
    use crypto_secretbox::aead::rand_core::{OsRng, RngCore};
    use crypto_secretbox::{
        aead::{Aead, KeyInit},
        XSalsa20Poly1305,
    };
    use zeroize::{Zeroize, ZeroizeOnDrop};

    pub const KEYBYTES: usize = 32;
    pub const NONCEBYTES: usize = 24;
    pub const MACBYTES: usize = 16;

    #[derive(Clone, Zeroize, ZeroizeOnDrop)]
    pub struct Key(pub [u8; KEYBYTES]);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Nonce(pub [u8; NONCEBYTES]);

    pub fn gen_key() -> Key {
        let mut bytes = [0u8; KEYBYTES];
        OsRng.fill_bytes(&mut bytes);
        Key(bytes)
    }

    pub fn gen_nonce() -> Nonce {
        let mut bytes = [0u8; NONCEBYTES];
        OsRng.fill_bytes(&mut bytes);
        Nonce(bytes)
    }

    pub fn seal(message: &[u8], nonce: &Nonce, key: &Key) -> Result<Vec<u8>, CryptoError> {
        let cipher = XSalsa20Poly1305::new((&key.0).into());
        cipher
            .encrypt((&nonce.0).into(), message)
            .map_err(|_| CryptoError::Encryption)
    }

    pub fn open(ciphertext: &[u8], nonce: &Nonce, key: &Key) -> Result<Vec<u8>, CryptoError> {
        let cipher = XSalsa20Poly1305::new((&key.0).into());
        cipher
            .decrypt((&nonce.0).into(), ciphertext)
            .map_err(|_| CryptoError::Authentication)
    }
}

pub mod box_ {
    use super::CryptoError;
    use crypto_box::aead::rand_core::{OsRng, RngCore};
    use crypto_box::{
        aead::Aead, PublicKey as RustCryptoPublicKey, SalsaBox, SecretKey as RustCryptoSecretKey,
    };
    use zeroize::{Zeroize, ZeroizeOnDrop};

    pub const PUBLICKEYBYTES: usize = 32;
    pub const SECRETKEYBYTES: usize = 32;
    pub const NONCEBYTES: usize = 24;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct PublicKey(pub [u8; PUBLICKEYBYTES]);

    impl PublicKey {
        pub fn from_slice(bytes: &[u8]) -> Option<Self> {
            bytes.try_into().ok().map(Self)
        }
    }

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Clone, Zeroize, ZeroizeOnDrop)]
    pub struct SecretKey(pub [u8; SECRETKEYBYTES]);

    impl SecretKey {
        pub fn from_slice(bytes: &[u8]) -> Option<Self> {
            bytes.try_into().ok().map(Self)
        }
    }

    impl AsRef<[u8]> for SecretKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Nonce(pub [u8; NONCEBYTES]);

    pub fn gen_keypair() -> (PublicKey, SecretKey) {
        let mut secret = [0u8; SECRETKEYBYTES];
        OsRng.fill_bytes(&mut secret);
        let private = RustCryptoSecretKey::from(secret);
        let public = private.public_key();
        (PublicKey(*public.as_bytes()), SecretKey(secret))
    }

    pub fn seal(
        message: &[u8],
        nonce: &Nonce,
        recipient: &PublicKey,
        sender: &SecretKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let recipient = RustCryptoPublicKey::from(recipient.0);
        let sender = RustCryptoSecretKey::from(sender.0);
        SalsaBox::new(&recipient, &sender)
            .encrypt((&nonce.0).into(), message)
            .map_err(|_| CryptoError::Encryption)
    }

    pub fn open(
        ciphertext: &[u8],
        nonce: &Nonce,
        sender: &PublicKey,
        recipient: &SecretKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let sender = RustCryptoPublicKey::from(sender.0);
        let recipient = RustCryptoSecretKey::from(recipient.0);
        SalsaBox::new(&sender, &recipient)
            .decrypt((&nonce.0).into(), ciphertext)
            .map_err(|_| CryptoError::Authentication)
    }
}

pub mod sign {
    use super::CryptoError;
    use crypto_box::aead::rand_core::{OsRng, RngCore};
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    pub const PUBLICKEYBYTES: usize = 32;
    pub const SECRETKEYBYTES: usize = 64;
    pub const SEEDBYTES: usize = 32;
    pub const SIGNATUREBYTES: usize = 64;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct PublicKey(pub [u8; PUBLICKEYBYTES]);

    impl PublicKey {
        pub fn from_slice(bytes: &[u8]) -> Option<Self> {
            let bytes: [u8; PUBLICKEYBYTES] = bytes.try_into().ok()?;
            VerifyingKey::from_bytes(&bytes).ok()?;
            Some(Self(bytes))
        }
    }

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Clone, Zeroize, ZeroizeOnDrop)]
    pub struct SecretKey(pub [u8; SECRETKEYBYTES]);

    impl SecretKey {
        pub fn from_slice(bytes: &[u8]) -> Option<Self> {
            let bytes: [u8; SECRETKEYBYTES] = bytes.try_into().ok()?;
            SigningKey::from_keypair_bytes(&bytes).ok()?;
            Some(Self(bytes))
        }

        pub fn public_key(&self) -> PublicKey {
            let mut seed = [0u8; SEEDBYTES];
            seed.copy_from_slice(&self.0[..SEEDBYTES]);
            let signing_key = SigningKey::from_bytes(&seed);
            PublicKey(signing_key.verifying_key().to_bytes())
        }
    }

    impl AsRef<[u8]> for SecretKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Clone, Zeroize, ZeroizeOnDrop)]
    pub struct Seed(pub [u8; SEEDBYTES]);

    impl Seed {
        pub fn from_slice(bytes: &[u8]) -> Option<Self> {
            bytes.try_into().ok().map(Self)
        }
    }

    pub fn gen_keypair() -> (PublicKey, SecretKey) {
        let mut seed = [0u8; SEEDBYTES];
        OsRng.fill_bytes(&mut seed);
        keypair_from_seed(&Seed(seed))
    }

    pub fn keypair_from_seed(seed: &Seed) -> (PublicKey, SecretKey) {
        let signing_key = SigningKey::from_bytes(&seed.0);
        (
            PublicKey(signing_key.verifying_key().to_bytes()),
            SecretKey(signing_key.to_keypair_bytes()),
        )
    }

    pub fn sign(message: &[u8], key: &SecretKey) -> Vec<u8> {
        let mut seed = [0u8; SEEDBYTES];
        seed.copy_from_slice(&key.0[..SEEDBYTES]);
        let signing_key = SigningKey::from_bytes(&seed);
        let signature: Signature = signing_key.sign(message);
        let mut signed = Vec::with_capacity(SIGNATUREBYTES + message.len());
        signed.extend_from_slice(&signature.to_bytes());
        signed.extend_from_slice(message);
        signed
    }

    pub fn verify(signed: &[u8], key: &PublicKey) -> Result<Vec<u8>, CryptoError> {
        if signed.len() < SIGNATUREBYTES {
            return Err(CryptoError::Authentication);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&key.0).map_err(|_| CryptoError::Authentication)?;
        let signature = Signature::from_slice(&signed[..SIGNATUREBYTES])
            .map_err(|_| CryptoError::Authentication)?;
        let message = &signed[SIGNATUREBYTES..];
        verifying_key
            .verify_strict(message, &signature)
            .map_err(|_| CryptoError::Authentication)?;
        Ok(message.to_vec())
    }

    pub fn sign_detached(message: &[u8], key: &SecretKey) -> [u8; SIGNATUREBYTES] {
        let mut seed = [0u8; SEEDBYTES];
        seed.copy_from_slice(&key.0[..SEEDBYTES]);
        let signing_key = SigningKey::from_bytes(&seed);
        let signature: Signature = signing_key.sign(message);
        signature.to_bytes()
    }

    pub fn verify_detached(
        signature: &[u8],
        message: &[u8],
        key: &PublicKey,
    ) -> Result<(), CryptoError> {
        if signature.len() != SIGNATUREBYTES {
            return Err(CryptoError::Authentication);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&key.0).map_err(|_| CryptoError::Authentication)?;
        let signature =
            Signature::from_slice(signature).map_err(|_| CryptoError::Authentication)?;
        verifying_key
            .verify_strict(message, &signature)
            .map_err(|_| CryptoError::Authentication)?;
        Ok(())
    }
}

#[inline]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    left.len() == right.len() && bool::from(left.ct_eq(right))
}

#[cfg(test)]
mod tests {
    use super::{box_, constant_time_eq, secretbox, sign};
    use hex_literal::hex;

    #[test]
    fn secretbox_matches_the_nacl_reference_vector() {
        let key = secretbox::Key(hex!(
            "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
        ));
        let nonce = secretbox::Nonce(hex!("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"));
        let plaintext = hex!(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a"
            "1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057"
            "e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040"
            "e082f937763848645e0705"
        );
        let expected = hex!(
            "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4"
            "476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
            "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de"
            "56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5"
        );
        let encrypted = secretbox::seal(&plaintext, &nonce, &key).unwrap();
        assert_eq!(encrypted, expected);
        assert_eq!(
            secretbox::open(&encrypted, &nonce, &key),
            Ok(plaintext.to_vec())
        );
    }

    #[test]
    fn box_keys_and_ciphertext_use_the_nacl_layout() {
        let alice_secret = box_::SecretKey(hex!(
            "68f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d4c"
        ));
        let alice_public = box_::PublicKey(hex!(
            "ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d"
        ));
        let bob_secret = box_::SecretKey(hex!(
            "b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b"
        ));
        let bob_public = box_::PublicKey(hex!(
            "e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754"
        ));
        let nonce = box_::Nonce(hex!("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"));
        let encrypted =
            box_::seal(b"current-protocol", &nonce, &bob_public, &alice_secret).unwrap();
        assert_eq!(
            box_::open(&encrypted, &nonce, &alice_public, &bob_secret),
            Ok(b"current-protocol".to_vec())
        );
    }

    #[test]
    fn ed25519_matches_rfc8032_empty_message_vector() {
        let seed = sign::Seed(hex!(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ));
        let (public, secret) = sign::keypair_from_seed(&seed);
        assert_eq!(
            public.0,
            hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        assert_eq!(
            sign::sign(b"", &secret),
            hex!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        );
        assert_eq!(
            sign::verify(&sign::sign(b"message", &secret), &public),
            Ok(b"message".to_vec())
        );
    }

    #[test]
    fn constant_time_equality_rejects_length_and_content_changes() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"diff"));
        assert!(!constant_time_eq(b"same", b"same-longer"));
    }

    #[test]
    fn ed25519_detached_signatures_verify_authenticity() {
        let (public, secret) = sign::gen_keypair();
        let message = b"camellia-trusted-device-proof-test";
        let signature = sign::sign_detached(message, &secret);
        assert_eq!(signature.len(), 64);
        assert!(sign::verify_detached(&signature, message, &public).is_ok());

        // Tampered message
        let tampered_msg = b"camellia-trusted-device-proof-t3st";
        assert!(sign::verify_detached(&signature, tampered_msg, &public).is_err());

        // Tampered signature
        let mut tampered_sig = signature;
        tampered_sig[0] ^= 0x01;
        assert!(sign::verify_detached(&tampered_sig, message, &public).is_err());

        // Wrong key
        let (other_public, _) = sign::gen_keypair();
        assert!(sign::verify_detached(&signature, message, &other_public).is_err());
    }
}
