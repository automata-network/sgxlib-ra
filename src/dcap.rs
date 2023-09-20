use std::prelude::v1::*;

use sgx_dcap_ql_rs::{sgx_qe_get_target_info, sgx_target_info_t};
use sgxlib::sgx_types::{sgx_report_data_t, sgx_status_t};

use crate::{RaFfi, SgxReport, SgxQuote};
use eth_types::HexBytes;

pub fn dcap_quote() -> Result<SgxQuote, String> {
    use crate::SgxTarget;
    use core::mem::size_of;
    use base::format::debug;
    use sgx_dcap_quoteverify_rs as quoteverify;
    use sgx_dcap_quoteverify_rs::{
        sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, tee_supp_data_descriptor_t, tee_verify_quote,
    };
    use sgxlib::sgx_types;

    let target = RaFfi::dcap_get_target().map_err(debug)?;
    let mut data = [0_u8; 64];
    let result = RaFfi::create_report(&target, data).map_err(debug)?;
    let quote = RaFfi::dcap_get_quote(&result).map_err(debug)?;
    // let reason = RaFfi::dcap_verify_quote(&quote).map_err(debug)?;
    // if reason != "" {
    //     return Err(reason);
    // }
    Ok(quote)
}
