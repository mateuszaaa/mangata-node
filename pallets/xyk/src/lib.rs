#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{DispatchError, DispatchResult},
    ensure,
    sp_runtime::ModuleId,
    weights::Pays,
    StorageMap,
};
use frame_system::ensure_signed;
use sp_core::U256;
// TODO documentation!
use codec::FullCodec;
use frame_support::sp_runtime::traits::AccountIdConversion;
use frame_support::traits::{ExistenceRequirement, Get, WithdrawReasons};
use frame_support::Parameter;
use mangata_primitives::{Balance, TokenId};
use orml_tokens::{MultiTokenCurrency, MultiTokenCurrencyExtended};
use sp_runtime::traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize, Member};
use sp_runtime::traits::{SaturatedConversion, Zero};
use sp_std::fmt::Debug;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub trait Trait: frame_system::Trait {
    type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
    type Currency: MultiTokenCurrencyExtended<Self::AccountId>;
    type NativeCurrencyId: Get<TokenId>;
}

const PALLET_ID: ModuleId = ModuleId(*b"79b14c96");

decl_error! {
    /// Errors
    pub enum Error for Module<T: Trait> {
        VaultAlreadySet,
        PoolAlreadyExists,
        NotEnoughAssets,
        NoSuchPool,
        NoSuchLiquidityAsset,
        NotEnoughReserve,
        ZeroAmount,
        InsufficientInputAmount,
        InsufficientOutputAmount,
        SameAsset,
        AssetAlreadyExists,
        AssetDoesNotExists,
        DivisionByZero,
        NotMangataLiquidityAsset,
    }
}

decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as frame_system::Trait>::AccountId,
    {
        //TODO add trading events
        PoolCreated(AccountId, TokenId, Balance, TokenId, Balance),
        AssetsSwapped(AccountId, TokenId, Balance, TokenId, Balance),
        LiquidityMinted(
            AccountId,
            TokenId,
            Balance,
            TokenId,
            Balance,
            TokenId,
            Balance,
        ),
        LiquidityBurned(
            AccountId,
            TokenId,
            Balance,
            TokenId,
            Balance,
            TokenId,
            Balance,
        ),
    }
);

// XYK exchange pallet storage.
decl_storage! {
    trait Store for Module<T: Trait> as XykStorage {

        Pools get(fn asset_pool): map hasher(opaque_blake2_256) (TokenId, TokenId) => Balance;

        LiquidityAssets get(fn liquidity_asset): map hasher(opaque_blake2_256) (TokenId, TokenId) => TokenId;
        LiquidityPools get(fn liquidity_pool): map hasher(opaque_blake2_256) TokenId => (TokenId, TokenId);

        Nonce get (fn nonce): u32;

    }
    add_extra_genesis {
        config(created_pools_for_staking): Vec<(T::AccountId, TokenId, Balance, TokenId, Balance, TokenId)>;

        build(|config: &GenesisConfig<T>| {
            config.created_pools_for_staking.iter().for_each(|(account_id, native_token_id, native_token_amount, pooled_token_id, pooled_token_amount, liquidity_token_id)| {
                let created_liquidity_token_id: TokenId = T::Currency::get_next_currency_id().into();
                assert!(created_liquidity_token_id == *liquidity_token_id, "Assets not initialized in the expected sequence");
                assert!(<Module<T>>::create_pool( T::Origin::from(Some(account_id.clone()).into()), *native_token_id, *native_token_amount, *pooled_token_id, *pooled_token_amount).is_ok(), "Pool creation failed");

            })
        })
    }
}

// XYK extrinsics.
decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

        fn deposit_event() = default;

        #[weight = 10_000]
        pub fn create_pool(
            origin,
            first_asset_id: TokenId,
            first_asset_amount: Balance,
            second_asset_id: TokenId,
            second_asset_amount: Balance
        ) -> DispatchResult {

            let sender = ensure_signed(origin)?;

            <Self as XykFunctionsTrait<T::AccountId>>::create_pool(sender, first_asset_id.into(), first_asset_amount.into(), second_asset_id.into(), second_asset_amount.into())

        }

        // you will sell your sold_asset_amount of sold_asset_id to get some amount of bought_asset_id
        #[weight = (10_000, Pays::No)]
        pub fn sell_asset (
            origin,
            sold_asset_id: TokenId,
            bought_asset_id: TokenId,
            sold_asset_amount: Balance,
            min_amount_out: Balance,
        ) -> DispatchResult {

            let sender = ensure_signed(origin)?;
            <Self as XykFunctionsTrait<T::AccountId>>::sell_asset(sender, sold_asset_id.into(), bought_asset_id.into(), sold_asset_amount.into(), min_amount_out.into())

        }

        #[weight = (10_000, Pays::No)]
        pub fn buy_asset (
            origin,
            sold_asset_id: TokenId,
            bought_asset_id: TokenId,
            bought_asset_amount: Balance,
            max_amount_in: Balance,
        ) -> DispatchResult {

            let sender = ensure_signed(origin)?;

            <Self as XykFunctionsTrait<T::AccountId>>::buy_asset(sender, sold_asset_id.into(), bought_asset_id.into(), bought_asset_amount.into(), max_amount_in.into())

        }

        #[weight = 10_000]
        pub fn mint_liquidity (
            origin,
            first_asset_id: TokenId,
            second_asset_id: TokenId,
            first_asset_amount: Balance,
        ) -> DispatchResult {

            let sender = ensure_signed(origin)?;

            <Self as XykFunctionsTrait<T::AccountId>>::mint_liquidity(sender, first_asset_id.into(), second_asset_id.into(), first_asset_amount.into())

        }

        #[weight = 10_000]
        pub fn burn_liquidity (
            origin,
            first_asset_id: TokenId,
            second_asset_id: TokenId,
            liquidity_asset_amount: Balance,
        ) -> DispatchResult {

            let sender = ensure_signed(origin)?;

            <Self as XykFunctionsTrait<T::AccountId>>::burn_liquidity(sender, first_asset_id.into(), second_asset_id.into(), liquidity_asset_amount.into())

        }
    }
}

impl<T: Trait> Module<T> {
    pub fn calculate_sell_price(
        input_reserve: Balance,
        output_reserve: Balance,
        sell_amount: Balance,
    ) -> Result<Balance, DispatchError> {
        let input_reserve_saturated: U256 = input_reserve.saturated_into::<u128>().into();
        let output_reserve_saturated: U256 = output_reserve.saturated_into::<u128>().into();
        let sell_amount_saturated: U256 = sell_amount.saturated_into::<u128>().into();

        let input_amount_with_fee: U256 = sell_amount_saturated * 997;
        let numerator: U256 = input_amount_with_fee * output_reserve_saturated;
        let denominator: U256 = input_reserve_saturated * 1000 + input_amount_with_fee;
        let result = numerator
            .checked_div(denominator)
            .ok_or_else(|| DispatchError::from(Error::<T>::DivisionByZero))?;
        Ok(result.saturated_into::<u128>().saturated_into::<Balance>())
    }

    pub fn calculate_buy_price(
        input_reserve: Balance,
        output_reserve: Balance,
        buy_amount: Balance,
    ) -> Balance {
        let input_reserve_saturated: U256 = input_reserve.saturated_into::<u128>().into();
        let output_reserve_saturated: U256 = output_reserve.saturated_into::<u128>().into();
        let buy_amount_saturated: U256 = buy_amount.saturated_into::<u128>().into();

        let numerator: U256 = input_reserve_saturated * buy_amount_saturated * 1000;
        let denominator: U256 = (output_reserve_saturated - buy_amount_saturated) * 997;
        let result: U256 = numerator / denominator + 1;

        result.saturated_into::<u128>().saturated_into::<Balance>()
    }

    pub fn get_liquidity_asset(first_asset_id: TokenId, second_asset_id: TokenId) -> TokenId {
        if LiquidityAssets::contains_key((first_asset_id, second_asset_id)) {
            LiquidityAssets::get((first_asset_id, second_asset_id))
        } else {
            LiquidityAssets::get((second_asset_id, first_asset_id))
        }
    }

    pub fn get_burn_amount(
        first_asset_id: TokenId,
        second_asset_id: TokenId,
        liquidity_asset_amount: Balance,
    ) -> (Balance, Balance) {
        let liquidity_asset_id = Self::get_liquidity_asset(first_asset_id, second_asset_id);
        let first_asset_reserve_u256: U256 = Pools::get((first_asset_id, second_asset_id))
            .saturated_into::<u128>()
            .into();
        let second_asset_reserve_u256: U256 = Pools::get((second_asset_id, first_asset_id))
            .saturated_into::<u128>()
            .into();
        let total_liquidity_assets_u256: U256 =
            T::Currency::total_issuance(liquidity_asset_id.into())
                .saturated_into::<u128>()
                .into();
        let liquidity_asset_amount_u256: U256 =
            liquidity_asset_amount.saturated_into::<u128>().into();

        let first_asset_amount_u256 =
            first_asset_reserve_u256 * liquidity_asset_amount_u256 / total_liquidity_assets_u256;
        let second_asset_amount_u256 =
            second_asset_reserve_u256 * liquidity_asset_amount_u256 / total_liquidity_assets_u256;
        let second_asset_amount = second_asset_amount_u256
            .saturated_into::<u128>()
            .saturated_into::<Balance>();
        let first_asset_amount = first_asset_amount_u256
            .saturated_into::<u128>()
            .saturated_into::<Balance>();

        (first_asset_amount, second_asset_amount)
    }

    fn account_id() -> T::AccountId {
        PALLET_ID.into_account()
    }
}

pub trait XykFunctionsTrait<AccountId> {
    type Balance: AtLeast32BitUnsigned
        + FullCodec
        + Copy
        + MaybeSerializeDeserialize
        + Debug
        + Default
        + From<Balance>
        + Into<Balance>;

    type CurrencyId: Parameter
        + Member
        + Copy
        + MaybeSerializeDeserialize
        + Ord
        + Default
        + AtLeast32BitUnsigned
        + FullCodec
        + From<TokenId>
        + Into<TokenId>;

    fn create_pool(
        sender: AccountId,
        first_asset_id: Self::CurrencyId,
        first_asset_amount: Self::Balance,
        second_asset_id: Self::CurrencyId,
        second_asset_amount: Self::Balance,
    ) -> DispatchResult;

    fn sell_asset(
        sender: AccountId,
        sold_asset_id: Self::CurrencyId,
        bought_asset_id: Self::CurrencyId,
        sold_asset_amount: Self::Balance,
        min_amount_out: Self::Balance,
    ) -> DispatchResult;

    fn buy_asset(
        sender: AccountId,
        sold_asset_id: Self::CurrencyId,
        bought_asset_id: Self::CurrencyId,
        bought_asset_amount: Self::Balance,
        max_amount_in: Self::Balance,
    ) -> DispatchResult;

    fn mint_liquidity(
        sender: AccountId,
        first_asset_id: Self::CurrencyId,
        second_asset_id: Self::CurrencyId,
        first_asset_amount: Self::Balance,
    ) -> DispatchResult;

    fn burn_liquidity(
        sender: AccountId,
        first_asset_id: Self::CurrencyId,
        second_asset_id: Self::CurrencyId,
        liquidity_asset_amount: Self::Balance,
    ) -> DispatchResult;

    fn get_tokens_required_for_minting(
        liquidity_asset_id: Self::CurrencyId,
        liquidity_token_amount: Self::Balance,
    ) -> (
        Self::CurrencyId,
        Self::Balance,
        Self::CurrencyId,
        Self::Balance,
    );
}

impl<T: Trait> XykFunctionsTrait<T::AccountId> for Module<T> {
    type Balance = Balance;

    type CurrencyId = TokenId;

    fn create_pool(
        sender: T::AccountId,
        first_asset_id: Self::CurrencyId,
        first_asset_amount: Self::Balance,
        second_asset_id: Self::CurrencyId,
        second_asset_amount: Self::Balance,
    ) -> DispatchResult {
        let vault: T::AccountId = Module::<T>::account_id();

        ensure!(
            !first_asset_amount.is_zero() && !second_asset_amount.is_zero(),
            Error::<T>::ZeroAmount,
        );

        ensure!(
            !Pools::contains_key((first_asset_id, second_asset_id)),
            Error::<T>::PoolAlreadyExists,
        );

        ensure!(
            !Pools::contains_key((second_asset_id, first_asset_id)),
            Error::<T>::PoolAlreadyExists,
        );

        let first_asset_free_balance: Self::Balance =
            T::Currency::free_balance(first_asset_id.into(), &sender).into();
        let second_asset_free_balance: Self::Balance =
            T::Currency::free_balance(second_asset_id.into(), &sender).into();

        ensure!(
            first_asset_free_balance >= first_asset_amount,
            Error::<T>::NotEnoughAssets,
        );

        ensure!(
            second_asset_free_balance >= second_asset_amount,
            Error::<T>::NotEnoughAssets,
        );

        T::Currency::ensure_can_withdraw(
            first_asset_id.into(),
            &sender,
            first_asset_amount.into(),
            WithdrawReasons::all(),
            { first_asset_free_balance - first_asset_amount }.into(),
        )
        .or(Err(Error::<T>::NotEnoughAssets))?;

        T::Currency::ensure_can_withdraw(
            second_asset_id.into(),
            &sender,
            second_asset_amount.into(),
            WithdrawReasons::all(),
            { second_asset_free_balance - second_asset_amount }.into(),
        )
        .or(Err(Error::<T>::NotEnoughAssets))?;

        ensure!(first_asset_id != second_asset_id, Error::<T>::SameAsset,);

        let initial_liquidity = first_asset_amount + second_asset_amount;

        Pools::insert((first_asset_id, second_asset_id), first_asset_amount);

        Pools::insert((second_asset_id, first_asset_id), second_asset_amount);

        T::Currency::transfer(
            first_asset_id.into(),
            &sender,
            &vault,
            first_asset_amount.into(),
            ExistenceRequirement::AllowDeath,
        )?;

        T::Currency::transfer(
            second_asset_id.into(),
            &sender,
            &vault,
            second_asset_amount.into(),
            ExistenceRequirement::AllowDeath,
        )?;

        let liquidity_asset_id: Self::CurrencyId =
            T::Currency::create(&sender, initial_liquidity.into()).into();

        LiquidityAssets::insert((first_asset_id, second_asset_id), liquidity_asset_id);
        LiquidityPools::insert(liquidity_asset_id, (first_asset_id, second_asset_id));

        Module::<T>::deposit_event(RawEvent::PoolCreated(
            sender,
            first_asset_id,
            first_asset_amount,
            second_asset_id,
            second_asset_amount,
        ));

        Ok(())
    }

    fn sell_asset(
        sender: T::AccountId,
        sold_asset_id: Self::CurrencyId,
        bought_asset_id: Self::CurrencyId,
        sold_asset_amount: Self::Balance,
        min_amount_out: Self::Balance,
    ) -> DispatchResult {
        ensure!(
            Pools::contains_key((sold_asset_id, bought_asset_id)),
            Error::<T>::NoSuchPool,
        );

        ensure!(!sold_asset_amount.is_zero(), Error::<T>::ZeroAmount,);

        let input_reserve = Pools::get((sold_asset_id, bought_asset_id));
        let output_reserve = Pools::get((bought_asset_id, sold_asset_id));
        let bought_asset_amount =
            Module::<T>::calculate_sell_price(input_reserve, output_reserve, sold_asset_amount)?;

        ensure!(
            T::Currency::free_balance(sold_asset_id.into(), &sender).into() >= sold_asset_amount,
            Error::<T>::NotEnoughAssets,
        );

        ensure!(
            bought_asset_amount >= min_amount_out,
            Error::<T>::InsufficientOutputAmount,
        );

        let vault = Module::<T>::account_id();

        T::Currency::transfer(
            sold_asset_id.into(),
            &sender,
            &vault,
            sold_asset_amount.into(),
            ExistenceRequirement::KeepAlive,
        )?;
        T::Currency::transfer(
            bought_asset_id.into(),
            &vault,
            &sender,
            bought_asset_amount.into(),
            ExistenceRequirement::KeepAlive,
        )?;

        Pools::insert(
            (sold_asset_id, bought_asset_id),
            input_reserve + sold_asset_amount,
        );
        Pools::insert(
            (bought_asset_id, sold_asset_id),
            output_reserve - bought_asset_amount,
        );

        Module::<T>::deposit_event(RawEvent::AssetsSwapped(
            sender,
            sold_asset_id,
            sold_asset_amount,
            bought_asset_id,
            bought_asset_amount,
        ));

        Ok(())
    }

    fn buy_asset(
        sender: T::AccountId,
        sold_asset_id: Self::CurrencyId,
        bought_asset_id: Self::CurrencyId,
        bought_asset_amount: Self::Balance,
        max_amount_in: Self::Balance,
    ) -> DispatchResult {
        ensure!(
            Pools::contains_key((sold_asset_id, bought_asset_id)),
            Error::<T>::NoSuchPool,
        );

        let input_reserve = Pools::get((sold_asset_id, bought_asset_id));
        let output_reserve = Pools::get((bought_asset_id, sold_asset_id));

        ensure!(
            output_reserve > bought_asset_amount,
            Error::<T>::NotEnoughReserve,
        );

        ensure!(!bought_asset_amount.is_zero(), Error::<T>::ZeroAmount,);

        let sold_asset_amount =
            Module::<T>::calculate_buy_price(input_reserve, output_reserve, bought_asset_amount);

        ensure!(
            T::Currency::free_balance(sold_asset_id.into(), &sender).into() >= sold_asset_amount,
            Error::<T>::NotEnoughAssets,
        );

        ensure!(
            sold_asset_amount <= max_amount_in,
            Error::<T>::InsufficientInputAmount,
        );

        let vault = Module::<T>::account_id();

        T::Currency::transfer(
            sold_asset_id.into(),
            &sender,
            &vault,
            sold_asset_amount.into(),
            ExistenceRequirement::KeepAlive,
        )?;
        T::Currency::transfer(
            bought_asset_id.into(),
            &vault,
            &sender,
            bought_asset_amount.into(),
            ExistenceRequirement::KeepAlive,
        )?;

        Pools::insert(
            (sold_asset_id, bought_asset_id),
            input_reserve + sold_asset_amount,
        );
        Pools::insert(
            (bought_asset_id, sold_asset_id),
            output_reserve - bought_asset_amount,
        );

        Module::<T>::deposit_event(RawEvent::AssetsSwapped(
            sender,
            sold_asset_id,
            sold_asset_amount,
            bought_asset_id,
            bought_asset_amount,
        ));

        Ok(())
    }

    fn mint_liquidity(
        sender: T::AccountId,
        first_asset_id: Self::CurrencyId,
        second_asset_id: Self::CurrencyId,
        first_asset_amount: Self::Balance,
    ) -> DispatchResult {
        let vault = Module::<T>::account_id();

        ensure!(
            (LiquidityAssets::contains_key((first_asset_id, second_asset_id))
                || LiquidityAssets::contains_key((second_asset_id, first_asset_id))),
            Error::<T>::NoSuchPool,
        );

        let liquidity_asset_id = Module::<T>::get_liquidity_asset(first_asset_id, second_asset_id);

        ensure!(
            (Pools::contains_key((first_asset_id, second_asset_id))
                || Pools::contains_key((second_asset_id, first_asset_id))),
            Error::<T>::NoSuchPool,
        );

        let first_asset_reserve = Pools::get((first_asset_id, second_asset_id));
        let second_asset_reserve = Pools::get((second_asset_id, first_asset_id));
        let total_liquidity_assets: Self::Balance =
            T::Currency::total_issuance(liquidity_asset_id.into()).into();

        let first_asset_amount_u256: U256 = first_asset_amount.saturated_into::<u128>().into();
        let first_asset_reserve_u256: U256 = first_asset_reserve.saturated_into::<u128>().into();
        let second_asset_reserve_u256: U256 = second_asset_reserve.saturated_into::<u128>().into();
        let total_liquidity_assets_u256: U256 =
            total_liquidity_assets.saturated_into::<u128>().into();

        let second_asset_amount_u256: U256 =
            first_asset_amount_u256 * second_asset_reserve_u256 / first_asset_reserve_u256 + 1;
        let liquidity_assets_minted_u256: U256 =
            first_asset_amount_u256 * total_liquidity_assets_u256 / first_asset_reserve_u256;

        let second_asset_amount = second_asset_amount_u256
            .saturated_into::<u128>()
            .saturated_into::<Self::Balance>();
        let liquidity_assets_minted = liquidity_assets_minted_u256
            .saturated_into::<u128>()
            .saturated_into::<Self::Balance>();

        ensure!(
            !first_asset_amount.is_zero() && !second_asset_amount.is_zero(),
            Error::<T>::ZeroAmount,
        );

        ensure!(
            T::Currency::free_balance(first_asset_id.into(), &sender).into() >= first_asset_amount,
            Error::<T>::NotEnoughAssets,
        );

        ensure!(
            T::Currency::free_balance(second_asset_id.into(), &sender).into()
                >= second_asset_amount,
            Error::<T>::NotEnoughAssets,
        );

        T::Currency::transfer(
            first_asset_id.into(),
            &sender,
            &vault,
            first_asset_amount.into(),
            ExistenceRequirement::KeepAlive,
        )?;
        T::Currency::transfer(
            second_asset_id.into(),
            &sender,
            &vault,
            second_asset_amount.into(),
            ExistenceRequirement::KeepAlive,
        )?;

        T::Currency::mint(
            liquidity_asset_id.into(),
            &sender,
            liquidity_assets_minted.into(),
        )?;

        Pools::insert(
            (&first_asset_id, &second_asset_id),
            first_asset_reserve + first_asset_amount,
        );
        Pools::insert(
            (&second_asset_id, &first_asset_id),
            second_asset_reserve + second_asset_amount,
        );

        Module::<T>::deposit_event(RawEvent::LiquidityMinted(
            sender,
            first_asset_id,
            first_asset_amount,
            second_asset_id,
            second_asset_amount,
            liquidity_asset_id,
            second_asset_amount,
        ));

        Ok(())
    }

    fn burn_liquidity(
        sender: T::AccountId,
        first_asset_id: Self::CurrencyId,
        second_asset_id: Self::CurrencyId,
        liquidity_asset_amount: Self::Balance,
    ) -> DispatchResult {
        let vault = Module::<T>::account_id();

        ensure!(
            Pools::contains_key((first_asset_id, second_asset_id)),
            Error::<T>::NoSuchPool,
        );

        let first_asset_reserve = Pools::get((first_asset_id, second_asset_id));
        let second_asset_reserve = Pools::get((second_asset_id, first_asset_id));
        let liquidity_asset_id = Module::<T>::get_liquidity_asset(first_asset_id, second_asset_id);

        ensure!(
            T::Currency::can_slash(
                liquidity_asset_id.into(),
                &sender,
                liquidity_asset_amount.into()
            ),
            Error::<T>::NotEnoughAssets,
        );
        let new_balance: Self::Balance =
            T::Currency::free_balance(liquidity_asset_id.into(), &sender).into()
                - liquidity_asset_amount;

        T::Currency::ensure_can_withdraw(
            liquidity_asset_id.into(),
            &sender,
            liquidity_asset_amount.into(),
            WithdrawReasons::all(),
            new_balance.into(),
        )
        .or(Err(Error::<T>::NotEnoughAssets))?;

        let (first_asset_amount, second_asset_amount) =
            Module::<T>::get_burn_amount(first_asset_id, second_asset_id, liquidity_asset_amount);

        ensure!(
            !first_asset_amount.is_zero() && !second_asset_amount.is_zero(),
            Error::<T>::ZeroAmount,
        );

        T::Currency::transfer(
            first_asset_id.into(),
            &vault,
            &sender,
            first_asset_amount.into(),
            ExistenceRequirement::KeepAlive,
        )?;
        T::Currency::transfer(
            second_asset_id.into(),
            &vault,
            &sender,
            second_asset_amount.into(),
            ExistenceRequirement::KeepAlive,
        )?;
        Pools::insert(
            (&first_asset_id, &second_asset_id),
            first_asset_reserve - first_asset_amount,
        );
        Pools::insert(
            (&second_asset_id, &first_asset_id),
            second_asset_reserve - second_asset_amount,
        );

        if (first_asset_reserve - first_asset_amount == 0.saturated_into::<Self::Balance>())
            || (second_asset_reserve - second_asset_amount == 0.saturated_into::<Self::Balance>())
        {
            Pools::remove((first_asset_id, second_asset_id));
            Pools::remove((second_asset_id, first_asset_id));
        }

        T::Currency::burn_and_settle(
            liquidity_asset_id.into(),
            &sender,
            liquidity_asset_amount.into(),
        )?;

        Module::<T>::deposit_event(RawEvent::LiquidityBurned(
            sender,
            first_asset_id,
            first_asset_amount,
            second_asset_id,
            second_asset_amount,
            liquidity_asset_id,
            second_asset_amount,
        ));

        Ok(())
    }

    // This function has not been verified
    fn get_tokens_required_for_minting(
        liquidity_asset_id: Self::CurrencyId,
        liquidity_token_amount: Self::Balance,
    ) -> (
        Self::CurrencyId,
        Self::Balance,
        Self::CurrencyId,
        Self::Balance,
    ) {
        let (first_asset_id, second_asset_id) = LiquidityPools::get(liquidity_asset_id);
        let first_asset_reserve = Pools::get((first_asset_id, second_asset_id));
        let second_asset_reserve = Pools::get((second_asset_id, first_asset_id));
        let total_liquidity_assets: Balance =
            T::Currency::total_issuance(liquidity_asset_id.into()).into();

        let liquidity_token_amount_u256: U256 =
            liquidity_token_amount.saturated_into::<u128>().into();
        let first_asset_reserve_u256: U256 = first_asset_reserve.saturated_into::<u128>().into();
        let second_asset_reserve_u256: U256 = second_asset_reserve.saturated_into::<u128>().into();
        let total_liquidity_assets_u256: U256 =
            total_liquidity_assets.saturated_into::<u128>().into();

        let second_asset_amount_u256: U256 =
            liquidity_token_amount_u256 * second_asset_reserve_u256 / total_liquidity_assets_u256
                + 1;
        let first_asset_amount_u256: U256 = liquidity_token_amount_u256 * first_asset_reserve_u256
            / total_liquidity_assets_u256
            + 1;

        let second_asset_amount = second_asset_amount_u256
            .saturated_into::<u128>()
            .saturated_into::<Balance>();
        let first_asset_amount = first_asset_amount_u256
            .saturated_into::<u128>()
            .saturated_into::<Balance>();

        (
            first_asset_id,
            first_asset_amount,
            second_asset_id,
            second_asset_amount,
        )
    }
}

pub trait Valuate {
    type Balance: AtLeast32BitUnsigned
        + FullCodec
        + Copy
        + MaybeSerializeDeserialize
        + Debug
        + Default
        + From<Balance>
        + Into<Balance>;

    type CurrencyId: Parameter
        + Member
        + Copy
        + MaybeSerializeDeserialize
        + Ord
        + Default
        + AtLeast32BitUnsigned
        + FullCodec
        + From<TokenId>
        + Into<TokenId>;

    fn get_liquidity_token_mng_pool(
        liquidity_token_id: Self::CurrencyId,
    ) -> Result<(Self::CurrencyId, Self::CurrencyId), DispatchError>;

    fn valuate_liquidity_token(
        liquidity_token_id: Self::CurrencyId,
        liquidity_token_amount: Self::Balance,
    ) -> Self::Balance;

    fn scale_liquidity_by_mng_valuation(
        mng_valuation: Self::Balance,
        liquidity_token_amount: Self::Balance,
        mng_token_amount: Self::Balance,
    ) -> Self::Balance;
}

impl<T: Trait> Valuate for Module<T> {
    type Balance = Balance;

    type CurrencyId = TokenId;

    fn get_liquidity_token_mng_pool(
        liquidity_token_id: Self::CurrencyId,
    ) -> Result<(Self::CurrencyId, Self::CurrencyId), DispatchError> {
        let (first_token_id, second_token_id) = LiquidityPools::get(liquidity_token_id);
        let native_currency_id = T::NativeCurrencyId::get();
        match native_currency_id {
            _ if native_currency_id == first_token_id => Ok((first_token_id, second_token_id)),
            _ if native_currency_id == second_token_id => Ok((second_token_id, first_token_id)),
            _ => Err(Error::<T>::NotMangataLiquidityAsset.into()),
        }
    }

    fn valuate_liquidity_token(
        liquidity_token_id: Self::CurrencyId,
        liquidity_token_amount: Self::Balance,
    ) -> Self::Balance {
        let (mng_token_id, other_token_id) =
            match Self::get_liquidity_token_mng_pool(liquidity_token_id) {
                Ok(pool) => pool,
                Err(_) => return Default::default(),
            };
        let mng_token_reserve = Pools::get((mng_token_id, other_token_id));
        let liquidity_token_reserve = T::Currency::total_issuance(liquidity_token_id.into());
        let mng_token_reserve_u256: U256 = mng_token_reserve.saturated_into::<u128>().into();
        let liquidity_token_amount_u256: U256 =
            liquidity_token_amount.saturated_into::<u128>().into();
        let liquidity_token_reserve_u256: U256 =
            liquidity_token_reserve.saturated_into::<u128>().into();
        let mng_token_amount_u256 =
            mng_token_reserve_u256 * liquidity_token_amount_u256 / liquidity_token_reserve_u256;
        let mng_token_amount = mng_token_amount_u256
            .saturated_into::<u128>()
            .saturated_into::<Self::Balance>();
        mng_token_amount
    }

    fn scale_liquidity_by_mng_valuation(
        mng_valuation: Self::Balance,
        liquidity_token_amount: Self::Balance,
        mng_token_amount: Self::Balance,
    ) -> Self::Balance {
        if mng_valuation.is_zero() {
            return 0u128.into();
        }
        let mng_valuation_u256: U256 = mng_valuation.saturated_into::<u128>().into();
        let liquidity_token_amount_u256: U256 =
            liquidity_token_amount.saturated_into::<u128>().into();
        let mng_token_amount_u256: U256 = mng_token_amount.saturated_into::<u128>().into();
        let scaled_liquidity_token_amount_u256 =
            liquidity_token_amount_u256 * mng_token_amount_u256 / mng_valuation_u256;
        let scaled_liquidity_token_amount = scaled_liquidity_token_amount_u256
            .saturated_into::<u128>()
            .saturated_into::<Self::Balance>();
        scaled_liquidity_token_amount
    }
}
