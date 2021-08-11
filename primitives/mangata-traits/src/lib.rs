#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::convert::TryInto;
use sp_core::H256;
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::traits::Hash;
use codec::{Encode, Decode};
use mangata_primitives::{TokenId, Balance};
#[derive(Eq,Default, Debug, PartialEq, Encode, Decode, Clone)]
pub struct EncryptedTX{
    pub input_id: TokenId,
    pub output_id: TokenId,
    pub input_amount: Balance,
    pub output_amount: Balance,
}

pub type RawTx = [u8; sp_std::mem::size_of::<EncryptedTX>()];

#[derive(Debug, PartialEq, Encode, Decode, Clone)]
pub struct TxWrapper{
    pub bytes: RawTx,
    pub signature: H256,
}

impl Default for TxWrapper{
    fn default() -> Self {
        TxWrapper{
            bytes: [0u8; sp_std::mem::size_of::<EncryptedTX>()],
            signature: H256::repeat_byte(0),
        }
    }
}

impl From<EncryptedTX> for TxWrapper{
    fn from(tx: EncryptedTX) -> Self {
        let bytes: RawTx = tx.encode().try_into().unwrap();
        
        Self{
            // we know that it always suceed because there as there is  test for that
            bytes: bytes,
            signature: BlakeTwo256::hash(&bytes[..])
        }
    }
}

pub trait ExecuteEncryptedExtrinsic<T: frame_system::Trait>{
    fn execute(sender: T::AccountId, tx: EncryptedTX);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn verify_encoding() {
        let t = EncryptedTX{
            input_id: u32::max_value(),
            output_id: u32::max_value(),
            input_amount: u128::max_value(),
            output_amount: u128::max_value(),
        };

        assert_eq!(sp_std::mem::size_of::<EncryptedTX>(), t.encode().len());
        assert_eq!(sp_std::mem::size_of_val(&t), t.encode().len());
	}
}
