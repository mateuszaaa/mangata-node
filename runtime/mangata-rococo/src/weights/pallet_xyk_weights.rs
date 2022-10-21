// This file is part of Mangata.

// Copyright (C) 2020-2022 Mangata Foundation.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Autogenerated weights for pallet_xyk
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2022-09-16, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("dev"), DB CACHE: 1024

// Executed Command:
// /home/ubuntu/mangata-node/scripts/..//target/release/mangata-node
// benchmark
// pallet
// --chain
// dev
// --execution
// wasm
// --wasm-execution
// compiled
// --pallet
// pallet_xyk
// --extrinsic
// *
// --steps
// 50
// --repeat
// 20
// --output
// ./benchmarks/pallet_xyk_weights.rs
// --template
// ./templates/module-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(clippy::unnecessary_cast)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_xyk.
pub trait WeightInfo {
	fn create_pool() -> Weight;
	fn sell_asset() -> Weight;
	fn buy_asset() -> Weight;
	fn mint_liquidity() -> Weight;
	fn mint_liquidity_using_vesting_native_tokens() -> Weight;
	fn burn_liquidity() -> Weight;
	fn promote_pool() -> Weight;
	fn claim_rewards_v2() -> Weight;
	fn claim_rewards_all_v2() -> Weight;
	fn activate_liquidity_v2() -> Weight;
	fn deactivate_liquidity_v2() -> Weight;
	fn rewards_migrate_v1_to_v2() -> Weight;
}

/// Weights for pallet_xyk using the Mangata node and recommended hardware.
pub struct ModuleWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_xyk::WeightInfo for ModuleWeight<T> {
	// Storage: Bootstrap ActivePair (r:1 w:0)
	// Storage: Xyk Pools (r:2 w:1)
	// Storage: Tokens Accounts (r:5 w:5)
	// Storage: System Account (r:1 w:1)
	// Storage: Tokens NextCurrencyId (r:1 w:1)
	// Storage: Tokens TotalIssuance (r:1 w:1)
	// Storage: AssetRegistry Metadata (r:1 w:1)
	// Storage: Xyk LiquidityAssets (r:0 w:1)
	// Storage: Xyk LiquidityPools (r:0 w:1)
	fn create_pool() -> Weight {
		(143_430_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(12 as Weight))
			.saturating_add(T::DbWeight::get().writes(12 as Weight))
	}
	// Storage: Xyk Pools (r:3 w:1)
	// Storage: Tokens Accounts (r:6 w:6)
	// Storage: System Account (r:2 w:2)
	fn sell_asset() -> Weight {
		(151_597_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(11 as Weight))
			.saturating_add(T::DbWeight::get().writes(9 as Weight))
	}
	// Storage: Xyk Pools (r:4 w:1)
	// Storage: Tokens Accounts (r:6 w:6)
	// Storage: System Account (r:2 w:2)
	fn buy_asset() -> Weight {
		(158_939_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(12 as Weight))
			.saturating_add(T::DbWeight::get().writes(9 as Weight))
	}
	// Storage: Xyk LiquidityAssets (r:1 w:0)
	// Storage: Xyk Pools (r:1 w:1)
	// Storage: Tokens TotalIssuance (r:1 w:1)
	// Storage: Tokens Accounts (r:5 w:5)
	// Storage: Tokens NextCurrencyId (r:1 w:0)
	// Storage: Issuance PromotedPoolsRewards (r:1 w:0)
	// Storage: Xyk LiquidityMiningUser (r:1 w:1)
	// Storage: Xyk LiquidityMiningActiveUser (r:1 w:1)
	// Storage: Xyk LiquidityMiningPool (r:1 w:1)
	// Storage: Xyk LiquidityMiningActivePool (r:1 w:1)
	// Storage: MultiPurposeLiquidity ReserveStatus (r:1 w:1)
	fn mint_liquidity() -> Weight {
		(169_416_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(15 as Weight))
			.saturating_add(T::DbWeight::get().writes(12 as Weight))
	}
	// Storage: Xyk LiquidityAssets (r:1 w:0)
	// Storage: Issuance PromotedPoolsRewards (r:1 w:0)
	// Storage: Vesting Vesting (r:2 w:2)
	// Storage: Tokens Locks (r:2 w:2)
	// Storage: Tokens Accounts (r:5 w:5)
	// Storage: Xyk Pools (r:1 w:1)
	// Storage: Tokens TotalIssuance (r:1 w:1)
	// Storage: Tokens NextCurrencyId (r:1 w:0)
	fn mint_liquidity_using_vesting_native_tokens() -> Weight {
		(198_407_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(14 as Weight))
			.saturating_add(T::DbWeight::get().writes(11 as Weight))
	}
	// Storage: Xyk LiquidityAssets (r:1 w:2)
	// Storage: Issuance PromotedPoolsRewards (r:1 w:1)
	// Storage: MultiPurposeLiquidity ReserveStatus (r:1 w:1)
	// Storage: Xyk Pools (r:1 w:2)
	// Storage: Tokens Accounts (r:5 w:5)
	// Storage: Xyk LiquidityMiningActiveUser (r:1 w:1)
	// Storage: Xyk LiquidityMiningUser (r:1 w:1)
	// Storage: Xyk LiquidityMiningPool (r:1 w:1)
	// Storage: Xyk LiquidityMiningActivePool (r:1 w:1)
	// Storage: Xyk LiquidityMiningUserToBeClaimed (r:1 w:1)
	// Storage: Xyk LiquidityMiningUserClaimed (r:1 w:1)
	// Storage: Tokens TotalIssuance (r:1 w:1)
	// Storage: Xyk LiquidityPools (r:0 w:1)
	fn burn_liquidity() -> Weight {
		(175_567_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(16 as Weight))
			.saturating_add(T::DbWeight::get().writes(19 as Weight))
	}
	// Storage: Issuance PromotedPoolsRewards (r:1 w:0)
	// Storage: Xyk LiquidityMiningUser (r:1 w:0)
	// Storage: Xyk LiquidityMiningPool (r:1 w:0)
	// Storage: Xyk LiquidityMiningActiveUser (r:1 w:0)
	// Storage: Xyk LiquidityMiningActivePool (r:1 w:0)
	// Storage: Xyk LiquidityMiningUserToBeClaimed (r:1 w:1)
	// Storage: Xyk LiquidityMiningUserClaimed (r:1 w:1)
	// Storage: Tokens Accounts (r:2 w:2)
	// Storage: Issuance PromotedPoolsRewards (r:1 w:1)
	fn promote_pool() -> Weight {
		(21_528_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(1 as Weight))
			.saturating_add(T::DbWeight::get().writes(1 as Weight))
	}

	// Storage: Issuance PromotedPoolsRewards (r:1 w:0)
	// Storage: Xyk LiquidityMiningUser (r:1 w:0)
	// Storage: Xyk LiquidityMiningPool (r:1 w:0)
	// Storage: Xyk LiquidityMiningActiveUser (r:1 w:0)
	// Storage: Xyk LiquidityMiningActivePool (r:1 w:0)
	// Storage: Xyk LiquidityMiningUserToBeClaimed (r:1 w:1)
	// Storage: Xyk LiquidityMiningUserClaimed (r:1 w:1)
	// Storage: Tokens Accounts (r:2 w:2)
	fn claim_rewards_v2() -> Weight {
		(86_814_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(9 as Weight))
			.saturating_add(T::DbWeight::get().writes(4 as Weight))
	}

	fn claim_rewards_all_v2() -> Weight {
		(86_814_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(9 as Weight))
			.saturating_add(T::DbWeight::get().writes(4 as Weight))
	}
	fn activate_liquidity_v2() -> Weight {
		(70_204_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(6 as Weight))
			.saturating_add(RocksDbWeight::get().writes(5 as Weight))
	}
	// Storage: Issuance PromotedPoolsRewards (r:1 w:1)
	// Storage: Xyk LiquidityMiningActiveUser (r:1 w:1)
	// Storage: Xyk LiquidityMiningUser (r:1 w:1)
	// Storage: Xyk LiquidityMiningPool (r:1 w:1)
	// Storage: Xyk LiquidityMiningActivePool (r:1 w:1)
	// Storage: Xyk LiquidityMiningUserToBeClaimed (r:1 w:1)
	// Storage: Xyk LiquidityMiningUserClaimed (r:1 w:1)
	// Storage: Tokens Accounts (r:1 w:1)
	fn deactivate_liquidity_v2() -> Weight {
		(84_598_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(8 as Weight))
			.saturating_add(T::DbWeight::get().writes(8 as Weight))
	}
//TODO retest
fn rewards_migrate_v1_to_v2() -> Weight {
	(133_607_000 as Weight)
		.saturating_add(RocksDbWeight::get().reads(7 as Weight))
		.saturating_add(RocksDbWeight::get().writes(7 as Weight))
}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	fn create_pool() -> Weight {
		(143_430_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(12 as Weight))
			.saturating_add(RocksDbWeight::get().writes(12 as Weight))
	}
	fn sell_asset() -> Weight {
		(151_597_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(11 as Weight))
			.saturating_add(RocksDbWeight::get().writes(9 as Weight))
	}
	fn buy_asset() -> Weight {
		(158_939_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(12 as Weight))
			.saturating_add(RocksDbWeight::get().writes(9 as Weight))
	}
	fn mint_liquidity() -> Weight {
		(169_416_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(15 as Weight))
			.saturating_add(RocksDbWeight::get().writes(12 as Weight))
	}
	fn mint_liquidity_using_vesting_native_tokens() -> Weight {
		(198_407_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(14 as Weight))
			.saturating_add(RocksDbWeight::get().writes(11 as Weight))
	}
	fn burn_liquidity() -> Weight {
		(175_567_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(16 as Weight))
			.saturating_add(RocksDbWeight::get().writes(19 as Weight))
	}
	fn promote_pool() -> Weight {
		(21_528_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(1 as Weight))
			.saturating_add(RocksDbWeight::get().writes(1 as Weight))
	}
	fn claim_rewards_v2() -> Weight {
		(156_724_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(8 as Weight))
			.saturating_add(RocksDbWeight::get().writes(6 as Weight))
	}
	fn claim_rewards_all_v2() -> Weight {
		(86_814_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(9 as Weight))
			.saturating_add(RocksDbWeight::get().writes(4 as Weight))
	}
	fn activate_liquidity_v2() -> Weight {
		(70_204_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(6 as Weight))
			.saturating_add(RocksDbWeight::get().writes(5 as Weight))
	}
	fn deactivate_liquidity_v2() -> Weight {
		(84_598_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(8 as Weight))
			.saturating_add(RocksDbWeight::get().writes(8 as Weight))
	}
	//TODO retest
	fn rewards_migrate_v1_to_v2() -> Weight {
		(133_607_000 as Weight)
			.saturating_add(RocksDbWeight::get().reads(7 as Weight))
			.saturating_add(RocksDbWeight::get().writes(7 as Weight))
	}
}
