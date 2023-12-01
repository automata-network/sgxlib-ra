use std::prelude::v1::*;

use crypto::Secp256k1PrivateKey;
use jsonrpc::RpcClient;
use sgx_dcap_ql_rs::{sgx_qe_get_target_info, sgx_target_info_t};
use sgxlib::sgx_types::{sgx_report_data_t, sgx_status_t};

use crate::submit_dcap_quote;
use crate::{ExecutionClient, RaFfi, SgxQuote, SgxReport};
use eth_types::HexBytes;

pub fn dcap_generate_quote(data: [u8; 64]) -> Result<SgxQuote, String> {
    use crate::SgxTarget;
    use base::format::debug;
    use core::mem::size_of;
    use sgx_dcap_quoteverify_rs as quoteverify;
    use sgx_dcap_quoteverify_rs::{
        sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, tee_supp_data_descriptor_t, tee_verify_quote,
    };
    use sgxlib::sgx_types;

    let target = RaFfi::dcap_get_target().map_err(debug)?;
    let result = RaFfi::create_report(&target, data).map_err(debug)?;
    let quote = RaFfi::dcap_get_quote(&result).map_err(debug)?;
    Ok(quote)
}

pub fn dcap_quote<C: RpcClient>(
    el: &ExecutionClient<C>,
    submitter: &Secp256k1PrivateKey,
) -> Result<SgxQuote, String> {
    let quote = dcap_generate_quote([0_u8; 64])?;
    if let Err(err) = submit_dcap_quote(el, submitter, &quote.as_bytes()) {
        return Err(err);
    }
    Ok(quote)
}

pub fn dcap_verify_quote(quote: &SgxQuote) -> Result<(), String> {
    use base::format::debug;
    let reason = RaFfi::dcap_verify_quote(quote).map_err(debug)?;
    if reason != "" {
        glog::info!("{}", reason);
    }
    Ok(())
}
