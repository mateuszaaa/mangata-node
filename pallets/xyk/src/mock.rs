// Copyright (C) 2020 Mangata team

use super::*;

use sp_core::H256;

use sp_runtime::{
	testing::Header,
	traits::{AccountIdConversion, BlakeTwo256, IdentityLookup},
};

use crate as xyk;
use frame_support::{
	construct_runtime, parameter_types,
	traits::{
		tokens::currency::MultiTokenCurrency, ConstU128, ConstU32, Contains, Everything, Nothing,
	},
	PalletId,
};

use frame_system as system;
use mangata_types::{assets::CustomMetadata, Amount, Balance, TokenId};
use orml_tokens::{MultiTokenCurrencyAdapter, MultiTokenCurrencyExtended};
use orml_traits::{asset_registry::AssetMetadata, parameter_type_with_key};
use pallet_issuance::PoolPromoteApi;
use sp_runtime::{Perbill, Percent};
use std::{collections::HashMap, sync::Mutex};

pub const NATIVE_CURRENCY_ID: u32 = 0;

pub(crate) type AccountId = u128;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Pallet, Call, Storage, Config, Event<T>},
		Tokens: orml_tokens::{Pallet, Storage, Call, Event<T>, Config<T>},
		XykStorage: xyk::{Pallet, Call, Storage, Event<T>, Config<T>},
		Vesting: pallet_vesting_mangata::{Pallet, Call, Storage, Event<T>},
		Issuance: pallet_issuance::{Pallet, Event<T>, Storage},
	}
);

lazy_static::lazy_static! {
	static ref PROMOTED_POOLS: Mutex<HashMap<TokenId, U256>> = {
		let m = HashMap::new();
		Mutex::new(m)
	};
}

pub struct MockPromotedPoolApi;
pub struct MockActivedPoolQueryApi;

#[cfg(test)]
#[cfg(not(feature = "runtime-benchmarks"))]
impl MockPromotedPoolApi {
	pub fn instance() -> &'static Mutex<HashMap<TokenId, U256>> {
		&PROMOTED_POOLS
	}
}

impl pallet_issuance::ComputeIssuance for MockPromotedPoolApi {
	fn compute_issuance(_n: u32) {
		todo!()
	}
}

impl MockActivedPoolQueryApi {
	pub fn instance() -> &'static Mutex<HashMap<TokenId, U256>> {
		&PROMOTED_POOLS
	}
}

impl ActivedPoolQueryApi for MockActivedPoolQueryApi {
	fn get_pool_activate_amount(_liquidity_token_id: TokenId) -> Option<u128> {
		Some(1 as u128)
	}
}

impl PoolPromoteApi for MockPromotedPoolApi {
	fn promote_pool(liquidity_token_id: TokenId) -> bool {
		let mut pools = PROMOTED_POOLS.lock().unwrap();
		if pools.contains_key(&liquidity_token_id) {
			false
		} else {
			pools.insert(liquidity_token_id, 0_u128.into());
			true
		}
	}

	fn unpromote_pool(liquidity_token_id: TokenId) -> bool {
		let mut pools = PROMOTED_POOLS.lock().unwrap();
		if pools.contains_key(&liquidity_token_id) {
			false
		} else {
			pools.insert(liquidity_token_id, 0_u128.into());
			true
		}
	}

	fn get_pool_rewards(liquidity_token_id: TokenId) -> Option<Balance> {
		let pools = PROMOTED_POOLS.lock().unwrap();
		pools.get(&liquidity_token_id).map(|x| (*x).try_into().unwrap())
	}

	fn claim_pool_rewards(liquidity_token_id: TokenId, amount: Balance) -> bool {
		let mut pools = PROMOTED_POOLS.lock().unwrap();
		let rewards: Balance =
			pools.get(&liquidity_token_id).map(|x| (*x).try_into().unwrap()).unwrap();
		let new_rewards = U256::from(rewards - amount);
		pools.insert(liquidity_token_id, new_rewards);
		true
	}

	fn get_pool_rewards_v2(liquidity_token_id: TokenId) -> Option<sp_core::U256> {
		let pools = PROMOTED_POOLS.lock().unwrap();
		pools.get(&liquidity_token_id).map(|x| *x)
	}

	fn len() -> usize {
		PROMOTED_POOLS.lock().unwrap().len()
	}

	fn len_v2() -> usize {
		PROMOTED_POOLS.lock().unwrap().len()
	}
}

parameter_types! {
	pub const BlockHashCount: u64 = 250;
}
impl system::Config for Test {
	type BaseCallFilter = Everything;
	type Origin = Origin;
	type Call = Call;
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
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
	type OnSetCode = ();
	type MaxConsumers = ConstU32<16>;
}

parameter_type_with_key! {
	pub ExistentialDeposits: |currency_id: TokenId| -> Balance {
		match currency_id {
			_ => 0,
		}
	};
}

pub struct DustRemovalWhitelist;
impl Contains<AccountId> for DustRemovalWhitelist {
	fn contains(a: &AccountId) -> bool {
		*a == TreasuryAccount::get()
	}
}

parameter_types! {
	pub TreasuryAccount: AccountId = TreasuryPalletId::get().into_account_truncating();
	pub const MaxLocks: u32 = 50;
}

impl orml_tokens::Config for Test {
	type Event = Event;
	type Balance = Balance;
	type Amount = Amount;
	type CurrencyId = TokenId;
	type WeightInfo = ();
	type ExistentialDeposits = ExistentialDeposits;
	type OnDust = ();
	type MaxLocks = MaxLocks;
	type DustRemovalWhitelist = DustRemovalWhitelist;
}

parameter_types! {
	pub const NativeCurrencyId: u32 = NATIVE_CURRENCY_ID;
	pub const TreasuryPalletId: PalletId = PalletId(*b"py/trsry");
	pub const BnbTreasurySubAccDerive: [u8; 4] = *b"bnbt";
}

parameter_types! {
	pub const MinVestedTransfer: Balance = 0;
}

impl pallet_vesting_mangata::Config for Test {
	type Event = Event;
	type Tokens = MultiTokenCurrencyAdapter<Test>;
	type BlockNumberToBalance = sp_runtime::traits::ConvertInto;
	type MinVestedTransfer = MinVestedTransfer;
	type WeightInfo = pallet_vesting_mangata::weights::SubstrateWeight<Test>;
	// `VestingInfo` encode length is 36bytes. 28 schedules gets encoded as 1009 bytes, which is the
	// highest number of schedules that encodes less than 2^10.
	const MAX_VESTING_SCHEDULES: u32 = 28;
}

parameter_types! {
	pub LiquidityMiningIssuanceVault: AccountId = LiquidityMiningIssuanceVaultId::get().into_account_truncating();
	pub const StakingIssuanceVaultId: PalletId = PalletId(*b"py/stkiv");
	pub StakingIssuanceVault: AccountId = StakingIssuanceVaultId::get().into_account_truncating();
	pub const MgaTokenId: TokenId = 0u32;


	pub const TotalCrowdloanAllocation: Balance = 200_000_000;
	pub const IssuanceCap: Balance = 100_000__000_000__000_000;
	pub const LinearIssuanceBlocks: u32 = 22_222u32;
	pub const LiquidityMiningSplit: Perbill = Perbill::from_parts(555555556);
	pub const StakingSplit: Perbill = Perbill::from_parts(444444444);
	pub const ImmediateTGEReleasePercent: Percent = Percent::from_percent(20);
	pub const TGEReleasePeriod: u32 = 100u32; // 2 years
	pub const TGEReleaseBegin: u32 = 10u32; // Two weeks into chain start
	pub const BlocksPerRound: u32 = 5u32;
	pub const HistoryLimit: u32 = 10u32;
}

#[cfg(not(feature = "runtime-benchmarks"))]
impl pallet_issuance::Config for Test {
	type Event = Event;
	type NativeCurrencyId = MgaTokenId;
	type Tokens = orml_tokens::MultiTokenCurrencyAdapter<Test>;
	type BlocksPerRound = BlocksPerRound;
	type HistoryLimit = HistoryLimit;
	type LiquidityMiningIssuanceVault = LiquidityMiningIssuanceVault;
	type StakingIssuanceVault = StakingIssuanceVault;
	type TotalCrowdloanAllocation = TotalCrowdloanAllocation;
	type IssuanceCap = IssuanceCap;
	type LinearIssuanceBlocks = LinearIssuanceBlocks;
	type LiquidityMiningSplit = LiquidityMiningSplit;
	type StakingSplit = StakingSplit;
	type ImmediateTGEReleasePercent = ImmediateTGEReleasePercent;
	type TGEReleasePeriod = TGEReleasePeriod;
	type TGEReleaseBegin = TGEReleaseBegin;
	type VestingProvider = Vesting;
	type WeightInfo = ();
	type ActivedPoolQueryApiType = MockActivedPoolQueryApi;
}

#[cfg(feature = "runtime-benchmarks")]
impl pallet_issuance::Config for Test {
	type Event = Event;
	type NativeCurrencyId = MgaTokenId;
	type Tokens = orml_tokens::MultiTokenCurrencyAdapter<Test>;
	type BlocksPerRound = BlocksPerRound;
	type HistoryLimit = HistoryLimit;
	type LiquidityMiningIssuanceVault = LiquidityMiningIssuanceVault;
	type StakingIssuanceVault = StakingIssuanceVault;
	type TotalCrowdloanAllocation = TotalCrowdloanAllocation;
	type IssuanceCap = IssuanceCap;
	type LinearIssuanceBlocks = LinearIssuanceBlocks;
	type LiquidityMiningSplit = LiquidityMiningSplit;
	type StakingSplit = StakingSplit;
	type ImmediateTGEReleasePercent = ImmediateTGEReleasePercent;
	type TGEReleasePeriod = TGEReleasePeriod;
	type TGEReleaseBegin = TGEReleaseBegin;
	type VestingProvider = Vesting;
	type WeightInfo = ();
	type ActivedPoolQueryApiType = XykStorage;
}

impl XykBenchmarkingConfig for Test {}

parameter_types! {
	pub const LiquidityMiningIssuanceVaultId: PalletId = PalletId(*b"py/lqmiv");
	pub FakeLiquidityMiningIssuanceVault: AccountId = LiquidityMiningIssuanceVaultId::get().into_account_truncating();
}

pub struct DummyBlacklistedPool;

impl Contains<(TokenId, TokenId)> for DummyBlacklistedPool {
	fn contains(pair: &(TokenId, TokenId)) -> bool {
		pair == &(1_u32, 9_u32) || pair == &(9_u32, 1_u32)
	}
}

pub struct RewardsMigrateAccountProvider<T: frame_system::Config>(PhantomData<T>);

impl<T: frame_system::Config> Get<T::AccountId> for RewardsMigrateAccountProvider<T> {
	fn get() -> T::AccountId {
		let account32: sp_runtime::AccountId32 =
			hex_literal::hex!["0e33df23356eb2e9e3baf0e8a5faae15bc70a6a5cce88f651a9faf6e8e937324"]
				.into();
		let mut init_account32 = sp_runtime::AccountId32::as_ref(&account32);
		let init_account = T::AccountId::decode(&mut init_account32).unwrap();
		init_account
	}
}

pub struct MockAssetRegister;

lazy_static::lazy_static! {
	static ref ASSET_REGISTER: Mutex<HashMap<TokenId, AssetMetadata<Balance, CustomMetadata>>> = {
		let m = HashMap::new();
		Mutex::new(m)
	};
}

#[cfg(test)]
impl MockAssetRegister {
	pub fn instance() -> &'static Mutex<HashMap<TokenId, AssetMetadata<Balance, CustomMetadata>>> {
		&ASSET_REGISTER
	}
}

impl AssetMetadataMutationTrait for MockAssetRegister {
	fn set_asset_info(
		asset: TokenId,
		name: Vec<u8>,
		symbol: Vec<u8>,
		decimals: u32,
	) -> DispatchResult {
		let meta = AssetMetadata {
			name,
			symbol,
			decimals,
			location: None,
			additional: Default::default(),
			existential_deposit: 0,
		};
		let mut register = ASSET_REGISTER.lock().unwrap();
		register.insert(asset, meta);
		Ok(())
	}
}

#[cfg(not(feature = "runtime-benchmarks"))]
impl Config for Test {
	type Event = Event;
	type ActivationReservesProvider = TokensActivationPassthrough<Test>;
	type Currency = MultiTokenCurrencyAdapter<Test>;
	type NativeCurrencyId = NativeCurrencyId;
	type TreasuryPalletId = TreasuryPalletId;
	type BnbTreasurySubAccDerive = BnbTreasurySubAccDerive;
	type LiquidityMiningIssuanceVault = FakeLiquidityMiningIssuanceVault;
	type PoolPromoteApi = MockPromotedPoolApi;
	type PoolFeePercentage = ConstU128<20>;
	type TreasuryFeePercentage = ConstU128<5>;
	type BuyAndBurnFeePercentage = ConstU128<5>;
	type RewardsDistributionPeriod = ConstU32<10>;
	type WeightInfo = ();
	type VestingProvider = Vesting;
	type DisallowedPools = DummyBlacklistedPool;
	type DisabledTokens = Nothing;
	type RewardsMigrateAccount = RewardsMigrateAccountProvider<Self>;
	type AssetMetadataMutation = MockAssetRegister;
}

#[cfg(feature = "runtime-benchmarks")]
impl Config for Test {
	type Event = Event;
	type ActivationReservesProvider = TokensActivationPassthrough<Test>;
	type Currency = MultiTokenCurrencyAdapter<Test>;
	type NativeCurrencyId = NativeCurrencyId;
	type TreasuryPalletId = TreasuryPalletId;
	type BnbTreasurySubAccDerive = BnbTreasurySubAccDerive;
	type LiquidityMiningIssuanceVault = FakeLiquidityMiningIssuanceVault;
	type PoolPromoteApi = Issuance;
	type PoolFeePercentage = ConstU128<20>;
	type TreasuryFeePercentage = ConstU128<5>;
	type BuyAndBurnFeePercentage = ConstU128<5>;
	type RewardsDistributionPeriod = ConstU32<1200>;
	type WeightInfo = ();
	type VestingProvider = Vesting;
	type DisallowedPools = Nothing;
	type DisabledTokens = Nothing;
	type RewardsMigrateAccount = RewardsMigrateAccountProvider<Self>;
	type AssetMetadataMutation = MockAssetRegister;
}

pub struct TokensActivationPassthrough<T: Config>(PhantomData<T>);

impl<T: Config> ActivationReservesProviderTrait for TokensActivationPassthrough<T>
where
	AccountId: From<<T as frame_system::Config>::AccountId>,
{
	type AccountId = T::AccountId;

	fn get_max_instant_unreserve_amount(
		token_id: TokenId,
		account_id: &Self::AccountId,
	) -> Balance {
		let account_id: u128 = (account_id.clone()).into();
		let token_id: u32 = token_id.into();
		XykStorage::get_rewards_info(account_id, token_id).activated_amount
	}

	fn can_activate(
		token_id: TokenId,
		account_id: &Self::AccountId,
		amount: Balance,
		_use_balance_from: Option<ActivateKind>,
	) -> bool {
		<T as pallet::Config>::Currency::can_reserve(token_id.into(), account_id, amount.into())
	}

	fn activate(
		token_id: TokenId,
		account_id: &Self::AccountId,
		amount: Balance,
		_use_balance_from: Option<ActivateKind>,
	) -> DispatchResult {
		<T as pallet::Config>::Currency::reserve(token_id.into(), account_id, amount.into())
	}

	fn deactivate(token_id: TokenId, account_id: &Self::AccountId, amount: Balance) -> Balance {
		<T as pallet::Config>::Currency::unreserve(token_id.into(), account_id, amount.into())
			.into()
	}
}

impl<T: Config> Pallet<T> {
	pub fn balance(id: TokenId, who: T::AccountId) -> Balance {
		<T as Config>::Currency::free_balance(id.into(), &who).into()
	}
	pub fn reserved(id: TokenId, who: T::AccountId) -> Balance {
		<T as Config>::Currency::reserved_balance(id.into(), &who).into()
	}
	pub fn total_supply(id: TokenId) -> Balance {
		<T as Config>::Currency::total_issuance(id.into()).into()
	}
	pub fn transfer(
		currency_id: TokenId,
		source: T::AccountId,
		dest: T::AccountId,
		value: Balance,
	) -> DispatchResult {
		<T as Config>::Currency::transfer(
			currency_id.into(),
			&source,
			&dest,
			value.into(),
			ExistenceRequirement::KeepAlive,
		)
		.into()
	}
	pub fn create_new_token(who: &T::AccountId, amount: Balance) -> TokenId {
		<T as Config>::Currency::create(who, amount.into())
			.expect("Token creation failed")
			.into()
	}
}

// This function basically just builds a genesis storage key/value store according to
// our desired mockup.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut ext: sp_io::TestExternalities =
		system::GenesisConfig::default().build_storage::<Test>().unwrap().into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}
