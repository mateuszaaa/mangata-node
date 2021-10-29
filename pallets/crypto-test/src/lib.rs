// Copyright (C) 2020 Mangata team

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_std::prelude::*;

use secp256k1::{SecretKey, PublicKey, Error as SecpError, util::FULL_PUBLIC_KEY_SIZE};
use hkdf::Hkdf;
use sha2::Sha256;

use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use aes_gcm::{Aes256Gcm};

/// Type alias for `[u8; 32]`, which is a 256-bit key
pub type AesKey = [u8; 32];
/// AES IV/nonce length
pub const AES_IV_LENGTH: usize = 12;
/// AES tag length
pub const AES_TAG_LENGTH: usize = 16;
/// AES IV + tag length
pub const AES_IV_PLUS_TAG_LENGTH: usize = AES_IV_LENGTH + AES_TAG_LENGTH;
/// Empty bytes array
pub const EMPTY_BYTES: [u8; 0] = [];

pub(crate) const LOG_TARGET: &'static str = "crypto-test";

// syntactic sugar for logging.
#[macro_export]
macro_rules! log {
	($level:tt, $patter:expr $(, $values:expr)* $(,)?) => {
		frame_support::debug::$level!(
			target: crate::LOG_TARGET,
			$patter $(, $values)*
		)
	};
}


pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {

    use super::*;

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(PhantomData<T>);

    #[pallet::hooks]
	impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {}

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
    }

    #[pallet::error]
    /// Errors
    pub enum Error<T> {
        EncryptionFailed,
        DecryptionFailed,
        CheckFailed,
        SecretKeyParseFailed,
        EncapsulationFailed,
        DecapsulationFailed
    }


    #[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config>
    {
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {

        #[pallet::weight(1_000_000)]
        pub fn test_crypto(
            origin: OriginFor<T>,
        ) -> DispatchResultWithPostInfo {

            let sender = ensure_signed(origin)?;

            let msg: &[u8] = b"hello!!";

            let secret_key_seed_1: [u8; 32] = *b"00010001010101110001000101010111";
            let secret_key_seed_2: [u8; 32] = *b"00010001010101110001000101011111";

            let secret_key_1: SecretKey = SecretKey::parse(&secret_key_seed_1).map_err(|_| Error::<T>::SecretKeyParseFailed)?;
            let secret_key_2: SecretKey = SecretKey::parse(&secret_key_seed_2).map_err(|_| Error::<T>::SecretKeyParseFailed)?;

            let public_key_1: PublicKey = PublicKey::from_secret_key(&secret_key_1);
            let public_key_2: PublicKey = PublicKey::from_secret_key(&secret_key_2);

            let aes_key = Pallet::<T>::encapsulate(&secret_key_1, &public_key_2).map_err(|_| Error::<T>::EncapsulationFailed)?;

            let aes_key = GenericArray::from_slice(&aes_key);

            let aead = Aes256Gcm::new(aes_key);

            let iv = [0u8; AES_IV_LENGTH];

            let nonce = GenericArray::from_slice(&iv[..]);

            let mut out = Vec::with_capacity(msg.len());
            out.extend(msg);

            let tag = aead.encrypt_in_place_detached(nonce, &EMPTY_BYTES, &mut out).map_err(|_| Error::<T>::EncryptionFailed)?;

            let mut output = Vec::with_capacity(AES_IV_PLUS_TAG_LENGTH + msg.len());
            output.extend(&iv);
            output.extend(tag);
            output.extend(out);

            ensure!(!(msg.clone()[..] == output.clone()[AES_IV_PLUS_TAG_LENGTH..]), Error::<T>::EncryptionFailed);

            log!(
                info,
                "tag length: {:?}",
                tag.len()
            );

            let encrypted_msg = output.clone();

            let aes_key = Pallet::<T>::decapsulate(&public_key_1, &secret_key_2).map_err(|_| Error::<T>::DecapsulationFailed)?;

            let aes_key = GenericArray::from_slice(&aes_key);

            let aead = Aes256Gcm::new(aes_key);

            let iv_from_encrypted = GenericArray::from_slice(&encrypted_msg[..AES_IV_LENGTH]);
            let tag_from_encrypted = GenericArray::from_slice(&encrypted_msg[AES_IV_LENGTH..AES_IV_PLUS_TAG_LENGTH]);

            let mut decrypted_out = Vec::with_capacity(encrypted_msg.len() - AES_IV_PLUS_TAG_LENGTH);
            decrypted_out.extend(&encrypted_msg[AES_IV_PLUS_TAG_LENGTH..]);

            let _ = aead.decrypt_in_place_detached(iv_from_encrypted, &EMPTY_BYTES, &mut decrypted_out, tag_from_encrypted).map_err(|_| Error::<T>::DecryptionFailed)?;
            
            log!(
                info,
                "msg: {:?}",
                msg
            );

            log!(
                info,
                "decrypted_out: {:?}",
                decrypted_out
            );

            ensure!(msg.clone()[..] == decrypted_out.clone()[..], Error::<T>::CheckFailed);

            Ok(().into())
        }

    }
}

impl<T: Config> Pallet<T> {
    /// Calculate a shared AES key of our secret key and peer's public key by hkdf
    pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> Result<AesKey, SecpError> {
        let mut shared_point = peer_pk.clone();
        shared_point.tweak_mul_assign(&sk)?;

        let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);
        master.extend(PublicKey::from_secret_key(&sk).serialize().iter());
        master.extend(shared_point.serialize().iter());

        Self::hkdf_sha256(master.as_slice())
    }

    /// Calculate a shared AES key of our public key and peer's secret key by hkdf
    pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> Result<AesKey, SecpError> {
        let mut shared_point = pk.clone();
        shared_point.tweak_mul_assign(&peer_sk)?;

        let mut master = Vec::with_capacity(FULL_PUBLIC_KEY_SIZE * 2);
        master.extend(pk.serialize().iter());
        master.extend(shared_point.serialize().iter());

        Self::hkdf_sha256(master.as_slice())
    }

    // private below
    fn hkdf_sha256(master: &[u8]) -> Result<AesKey, SecpError> {
        let h = Hkdf::<Sha256>::new(None, master);
        let mut out = [0u8; 32];
        h.expand(&EMPTY_BYTES, &mut out)
            .map_err(|_| SecpError::InvalidInputLength)?;
        Ok(out)
    }

}