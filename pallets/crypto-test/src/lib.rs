// Copyright (C) 2020 Mangata team

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_std::prelude::*;

use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use aes_gcm::{Aes256Gcm};

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
        CheckFailed
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

            let key: &[u8] = b"00010001010101110001000101010111";

            let key = GenericArray::from_slice(key);

            let aead = Aes256Gcm::new(key);

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

            let aead = Aes256Gcm::new(key);

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