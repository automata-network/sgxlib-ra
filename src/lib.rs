#![cfg_attr(feature = "tstd", no_std)]

#[cfg(feature = "tstd")]
#[macro_use]
extern crate sgxlib as std;

mod ias_server;
pub use ias_server::*;

mod types;
pub use types::*;

mod api;
pub use api::*;

#[cfg(feature = "epid")]
mod client;
#[cfg(feature = "epid")]
pub use client::*;

mod ffi;
pub use ffi::*;

// #[cfg(all(feature = "epid"))]
// mod epid_report;
// #[cfg(all(feature = "epid"))]
// pub use epid_report::*;

#[cfg(all(feature = "tstd", feature = "dcap"))]
mod dcap;
#[cfg(all(feature = "tstd", feature = "dcap"))]
pub use dcap::*;
#[cfg(all(feature = "tstd", feature = "dcap"))]
mod execution_client;
#[cfg(all(feature = "tstd", feature = "dcap"))]
pub use execution_client::*;
