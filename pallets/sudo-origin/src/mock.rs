// This file is part of Substrate.

// Copyright (C) 2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Test utilities

use super::*;
use crate as sudo_origin;
use frame_support::traits::Filter;
use frame_support::{
    decl_storage, impl_outer_dispatch, impl_outer_event, impl_outer_origin, parameter_types,
    weights::Weight,
};
use frame_system::ensure_signed;
use frame_system::EnsureRoot;
use sp_core::H256;
use sp_io;
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
    Perbill,
};
use frame_support::{construct_runtime};

// Logger module to track execution.
pub mod logger {
    use super::*;
    use frame_system::ensure_root;

    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
    }

    decl_storage! {
        trait Store for Module<T: Config> as Logger {
            AccountLog get(fn account_log): Vec<T::AccountId>;
            I32Log get(fn i32_log): Vec<i32>;
        }
    }

    decl_event! {
        pub enum Event<T> where AccountId = <T as frame_system::Config>::AccountId {
            AppendI32(i32, Weight),
            AppendI32AndAccount(AccountId, i32, Weight),
        }
    }

    decl_module! {
        pub struct Module<T: Config> for enum Call where origin: <T as frame_system::Config>::Origin {
            fn deposit_event() = default;

            #[weight = *weight]
            fn privileged_i32_log(origin, i: i32, weight: Weight){
                // Ensure that the `origin` is `Root`.
                ensure_root(origin)?;
                <I32Log>::append(i);
                Self::deposit_event(RawEvent::AppendI32(i, weight));
            }

            #[weight = *weight]
            fn non_privileged_log(origin, i: i32, weight: Weight){
                // Ensure that the `origin` is some signed account.
                let sender = ensure_signed(origin)?;
                <I32Log>::append(i);
                <AccountLog<T>>::append(sender.clone());
                Self::deposit_event(RawEvent::AppendI32AndAccount(sender, i, weight));
            }
        }
    }
}

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Module, Call, Storage, Config, Event<T>},
		Logger: logger::{Module, Storage, Call, Event<T>},
        SudoOrigin: sudo_origin::{Module, Call, Event},
	}
);

// New types for dispatchable functions.
pub type SudoOriginCall = sudo_origin::Call<Test>;
pub type LoggerCall = logger::Call<Test>;

parameter_types! {
    pub const BlockHashCount: u64 = 250;
}

pub struct BlockEverything;
impl Filter<Call> for BlockEverything {
    fn filter(_: &Call) -> bool {
        false
    }
}

impl frame_system::Config for Test {
    type BaseCallFilter = BlockEverything;
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = Event;
    type BlockHashCount = BlockHashCount;
    type DbWeight = ();
    type Version = ();
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
	type PalletInfo = PalletInfo;
	type BlockWeights = ();
	type BlockLength = ();
	type SS58Prefix = ();
}

// Implement the logger module's `Config` on the Test runtime.
impl logger::Config for Test {
    type Event = Event;
}

// Implement the sudo module's `Config` on the Test runtime.
impl Config for Test {
    type Event = Event;
    type Call = Call;
    type SudoOrigin = EnsureRoot<Self::AccountId>;
}

// Build test environment by setting the root `key` for the Genesis.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();
    t.into()
}
