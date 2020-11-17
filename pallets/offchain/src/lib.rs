#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// https://substrate.dev/docs/en/knowledgebase/runtime/frame

//use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch, traits::Get};
use frame_support::{
	debug, decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult,
	traits::Currency,
	traits::ExistenceRequirement,
};
//use frame_system::ensure_signed;
use frame_system::{
	self as system, ensure_none, ensure_signed,
	offchain::{
		AppCrypto, CreateSignedTransaction,
		SignedPayload, SigningTypes,
	},
};

use sp_std::{
	prelude::*, str,
	// collections::vec_deque::VecDeque,
};

use sp_runtime::{
	RuntimeDebug,
	// offchain as rt_offchain,
	// offchain::{
	// 	storage::StorageValueRef,
	// 	storage_lock::{StorageLock, BlockAndTime},
	// },
	transaction_validity::{
		InvalidTransaction, TransactionSource, TransactionValidity,
		ValidTransaction,
	},
};

use parity_scale_codec::{Decode, Encode};
use sp_core::crypto::KeyTypeId;
use hex_literal::hex;
//use sp_core::crypto::UncheckedInto;
use sp_runtime::AccountId32;
// use substrate_primitives as primitives;
// use substrate_primitives::crypto::UncheckedInto;

pub const NUM_VEC_LEN: usize = 10;
pub const UNSIGNED_TXS_PRIORITY: u64 = 100;
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"demo");

pub mod crypto {
	use crate::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	use sp_runtime::{
		traits::Verify,
		MultiSignature, MultiSigner,
	};

	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;
	// implemented for ocw-runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// implemented for mock runtime in test
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct Payload<Public> {
	number: u64,
	public: Public
}

impl <T: SigningTypes> SignedPayload<T> for Payload<T::Public> {
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}
 
#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

/// Configure the pallet by specifying the parameters and types on which it depends.
// pub trait Trait: frame_system::Trait {
// 	/// Because this pallet emits events, it depends on the runtime's definition of an event.
// 	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
// }

type Balance<T> = <<T as Trait>::Currency as Currency<<T as system::Trait>::AccountId>>::Balance;

/// This is the pallet's configuration trait
pub trait Trait: frame_system::Trait + CreateSignedTransaction<Call<Self>> {
	/// The identifier type for an offchain worker.
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
	type Currency: Currency<Self::AccountId>;
}

// The pallet's runtime storage items.
// https://substrate.dev/docs/en/knowledgebase/runtime/storage
decl_storage! {
	// A unique name is used to ensure that the pallet's storage items are isolated.
	// This name may be updated, but each pallet in the runtime must use a unique name.
	// ---------------------------------vvvvvvvvvvvvvv
	trait Store for Module<T: Trait> as TemplateModule {
		// Learn more about declaring storage items:
		// https://substrate.dev/docs/en/knowledgebase/runtime/storage#declaring-storage-items
		//Something get(fn something): Option<u32>;
		//Numbers get(fn numbers): VecDeque<u64>;
		Numbers get(fn numbers): Option<u64>;
		Sendlist: map hasher(blake2_128_concat) T::AccountId => Option<<T as frame_system::Trait>::BlockNumber>;
	}
}

// Pallets use events to inform users when important changes are made.
// https://substrate.dev/docs/en/knowledgebase/runtime/events
decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		/// Event documentation should end with an array that provides descriptive names for event
		/// parameters. [something, who]
		//SomethingStored(u32, AccountId),
		NewNumber(Option<AccountId>, u64),
	}
);

// Errors inform users that something went wrong.
decl_error! {
	pub enum Error for Module<T: Trait> {
		/// Error names should be descriptive.
		NoneValue,
		/// Errors should have helpful documentation associated with them.
		StorageOverflow,
	}
}

// Dispatchable functions allows users to interact with the pallet and invoke state changes.
// These functions materialize as "extrinsics", which are often compared to transactions.
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		// Errors must be initialized if they are used by the pallet.
		type Error = Error<T>;

		// Events must be initialized if they are used by the pallet.
		fn deposit_event() = default;

		/// An example dispatchable that takes a singles value as a parameter, writes the value to
		/// storage and emits an event. This function must be dispatched by a signed extrinsic.
		// #[weight = 10_000]
		// pub fn do_something(origin, something: u32) -> dispatch::DispatchResult {
		// 	// Check that the extrinsic was signed and get the signer.
		// 	// This function will return an error if the extrinsic is not signed.
		// 	// https://substrate.dev/docs/en/knowledgebase/runtime/origin
		// 	let who = ensure_signed(origin)?;

		// 	// Update storage.
		// 	Something::put(something);

		// 	// Emit an event.
		// 	Self::deposit_event(RawEvent::SomethingStored(something, who));
		// 	// Return a successful DispatchResult
		// 	Ok(())
		// }

		/// An example dispatchable that may throw a custom error.
		// #[weight = 10_000]
		// pub fn cause_error(origin) -> dispatch::DispatchResult {
		// 	let _who = ensure_signed(origin)?;

		// 	// Read a value from storage.
		// 	match Something::get() {
		// 		// Return an error if the value has not been set.
		// 		None => Err(Error::<T>::NoneValue)?,
		// 		Some(old) => {
		// 			// Increment the value read from storage; will error in the event of overflow.
		// 			let new = old.checked_add(1).ok_or(Error::<T>::StorageOverflow)?;
		// 			// Update the value in storage with the incremented result.
		// 			Something::put(new);
		// 			Ok(())
		// 		},
		// 	}
		// }
		#[weight = 10000]
		pub fn submit_number_unsigned(origin, number: Balance<T>, to: T::AccountId) -> DispatchResult {
			let _ = ensure_none(origin)?;
			//debug::info!("submit_number_unsigned: {}", number);
			//Self::append_or_replace_number(number);
			//Numbers::put(number);
			let account32: AccountId32 = hex!["d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"].into();
			let mut from32 = AccountId32::as_ref(&account32);
			let from : T::AccountId = T::AccountId::decode(&mut from32).unwrap_or_default();
			T::Currency::transfer(&from,&to,number,ExistenceRequirement::KeepAlive);
			//Self::deposit_event(RawEvent::NewNumber(None, number));
			Ok(())
		}
		#[weight = 10000]
		pub fn submit_number_signed(origin, number: u64) -> DispatchResult {
			let who = ensure_signed(origin)?;
			debug::info!("submit_number_signed: ({}, {:?})", number, who);
			//Self::append_or_replace_number(number);
			Numbers::put(number);
			Self::deposit_event(RawEvent::NewNumber(Some(who), number));
			Ok(())
		}

		#[weight = 10000]
		pub fn submit_number_unsigned_with_signed_payload(origin, payload: Payload<T::Public>,
			_signature: T::Signature) -> DispatchResult
		{
			let _ = ensure_none(origin)?;
			// we don't need to verify the signature here because it has been verified in
			//   `validate_unsigned` function when sending out the unsigned tx.
			let Payload { number, public } = payload;
			debug::info!("submit_number_unsigned_with_signed_payload: ({}, {:?})", number, public);
			//Self::append_or_replace_number(number);
			Numbers::put(number);
			Self::deposit_event(RawEvent::NewNumber(None, number));
			Ok(())
		}

	}
}

// impl<T: Trait> Module<T> {
// 	/// Append a new number to the tail of the list, removing an element from the head if reaching
// 	///   the bounded length.
// 	fn append_or_replace_number(number: u64) {
// 		Numbers::mutate(|numbers| {
// 			if numbers.len() == NUM_VEC_LEN {
// 				let _ = numbers.pop_front();
// 			}
// 			numbers.push_back(number);
// 			debug::info!("Number vector: {:?}", numbers);
// 		});
// 	}
// }

// impl <T: Trait> std::convert::Into<<T as frame_system::Trait>::AccountId> for sp_runtime::AccountId32 {
// 	fn into(aid: AccountId32) -> T::AccountId {
// 		aid.into()
// 	}
// }

impl<T: Trait> frame_support::unsigned::ValidateUnsigned for Module<T> {
	type Call = Call<T>;

	fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
		let valid_tx = |provide| ValidTransaction::with_tag_prefix("offchain-pallet")
			.priority(UNSIGNED_TXS_PRIORITY)
			.and_provides([&provide])
			.longevity(3)
			.propagate(true)
			.build();

		match call {
			Call::submit_number_unsigned(_number,_to) => valid_tx(b"submit_number_unsigned".to_vec()),
			Call::submit_number_unsigned_with_signed_payload(ref payload, ref signature) => {
				if !SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone()) {
					return InvalidTransaction::BadProof.into();
				}
				valid_tx(b"submit_number_unsigned_with_signed_payload".to_vec())
			},
			_ => InvalidTransaction::Call.into(),
		}
	}
}
