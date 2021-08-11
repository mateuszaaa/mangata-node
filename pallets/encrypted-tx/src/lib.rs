#![cfg_attr(not(feature = "std"), no_std)]
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
};
use frame_system::{self as system, ensure_root, ensure_signed};
use mangata_traits::{TxWrapper, EncryptedTX, ExecuteEncryptedExtrinsic, RawTx};

use codec::{Encode, Decode};
use sp_std::prelude::*;
use sp_std::convert::TryInto;
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::traits::Hash;
use sp_core::H256;
use frame_system::RawEvent;


pub trait Trait: system::Trait {
    type Event: From<Event> + Into<<Self as system::Trait>::Event>;
    type Executor: ExecuteEncryptedExtrinsic<Self>;
}


decl_storage! {
    trait Store for Module<T: Trait> as XykStorage {
        Transactions get(fn txs): map hasher(blake2_128_concat) T::AccountId => TxWrapper;
    }
}

decl_event!(
    pub enum Event {
        /// Asset info stored. [assetId, info]
        ExtrinsicDecoded(EncryptedTX),
    }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        /// Target application not found.
        AppNotFound,
        DeserializationError,
        /// Updated AppId is the same as current
        DifferentAppIdRequired
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

        type Error = Error<T>;

        fn deposit_event() = default;
        //
        #[weight = 10_000]
        pub fn submit_transaction (
            origin,
            tx: EncryptedTX,
            key: RawTx
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            let mut wraped_tx : TxWrapper = tx.into();
            // XOR payload with key
            wraped_tx.bytes.iter_mut().zip(key.iter()).for_each(|(x,y)| *x=*x^y);

            Transactions::<T>::insert( sender, wraped_tx);

            Ok(())
        }

        #[weight = 10_000]
        pub fn submit_raw_transaction (
            origin,
            tx: RawTx,
            signature: H256,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            Transactions::<T>::insert( sender, TxWrapper{bytes: tx, signature});

            Ok(())
        }

        #[weight = 10_000]
        pub fn decrypt_transaction (
            origin,
            key: RawTx
        ) -> DispatchResult {
            let sender = ensure_signed(origin.clone())?;

            let mut wrapped_tx = Transactions::<T>::get(
                sender.clone()
            );

            // dectypt !
            wrapped_tx.bytes.iter_mut().zip(key.iter()).for_each(|(x,y)| *x=*x^y);

            ensure!(
                BlakeTwo256::hash(&wrapped_tx.bytes[..]) == wrapped_tx.signature,
                Error::<T>::DeserializationError,
            );

            match EncryptedTX::decode(& mut &wrapped_tx.bytes[..]){
                Ok(tx) => {
                    Self::deposit_event(Event::ExtrinsicDecoded(
                            tx.clone()
                    ));
                    // <T as Trait>::Executor::execute(sender, tx);
                },
                Err(_) => {
                }
            };


            Ok(())
        }


    }
}

impl<T: Trait> Module<T> {
}
