use std::prelude::v1::*;

use base::format::debug;
use crypto::Aes128Key;
use eth_types::HexBytes;
use serde::{Deserialize, Serialize};
use sgxlib::{
    sgx_tkey_exchange::rsgx_ra_init,
    sgx_types::{
        sgx_ec256_public_t, sgx_ecall_get_ga_trusted_t, sgx_enclave_id_t,
        sgx_get_extended_epid_group_id, sgx_quote_nonce_t, sgx_ra_context_t, sgx_ra_msg1_t,
        sgx_ra_msg2_t, sgx_ra_msg3_t, sgx_ra_proc_msg2, sgx_report_t, sgx_status_t,
        sgx_target_info_t, size_t, uint32_t,
    },
    to_result,
};

#[cfg(feature = "tstd")]
use sgxlib::{sgx_tkey_exchange::rsgx_ra_get_keys, sgx_types::sgx_ra_key_type_t};

#[derive(Debug, Serialize, Deserialize)]
pub enum RaFfi {
    GetEpidGid {
        response: Option<u32>,
    },
    GetMsg1 {
        request: Option<(sgx_ra_context_t, sgx_enclave_id_t)>,
        response: Option<HexBytes>,
    },
    ProcMsg2 {
        request: Option<(sgx_ra_context_t, sgx_enclave_id_t, Vec<u8>)>,
        response: Option<HexBytes>,
    },
}

impl RaFfi {
    #[cfg(feature = "std")]
    pub fn call(self) -> Result<RaFfi, String> {
        Ok(match self {
            Self::GetEpidGid { response: None } => Self::GetEpidGid {
                response: Some(Self::get_epid_gpid()),
            },
            Self::GetMsg1 {
                request: Some((context, eid)),
                response: None,
            } => Self::GetMsg1 {
                request: None,
                response: Some(Self::sgx_ra_get_msg1(context, eid)?),
            },
            Self::ProcMsg2 {
                request: Some((ctx, eid, msg2)),
                response: None,
            } => Self::ProcMsg2 {
                request: None,
                response: Some(Self::sgx_ra_proc_msg2(ctx, eid, &msg2)?),
            },
            other => return Err(format!("unexpect enum {:?}", other)),
        })
    }

    #[cfg(feature = "std")]
    pub unsafe fn on_call(
        msg_in: *const u8,
        msg_in_size: size_t,
        msg_out: *mut u8,
        msg_out_size: size_t,
    ) -> sgx_status_t {
        let msg_in = std::slice::from_raw_parts(msg_in, msg_in_size);
        let msg_in: RaFfi = match serde_json::from_slice(msg_in) {
            Ok(n) => n,
            Err(err) => {
                glog::error!("decode msg_in fail: {:?}", err);
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        };
        let sig = format!("{:?}", msg_in);
        match msg_in.call() {
            Ok(result) => {
                let out = serde_json::to_vec(&result).unwrap();
                if out.len() > msg_out_size {
                    glog::error!(
                        "buffer too small [want:{}, got:{}] [{:?}]",
                        out.len(),
                        msg_out_size,
                        String::from_utf8_lossy(&out)
                    );
                    return sgx_status_t::SGX_ERROR_UNEXPECTED;
                }
                let msg_out = std::slice::from_raw_parts_mut(msg_out, out.len());
                msg_out.copy_from_slice(&out);
                sgx_status_t::SGX_SUCCESS
            }
            Err(err) => {
                glog::error!("process fail: on {} {}", sig, err);
                sgx_status_t::SGX_ERROR_UNEXPECTED
            }
        }
    }

    #[cfg(feature = "tstd")]
    pub fn call(self) -> Result<RaFfi, String> {
        let data = serde_json::to_vec(&self).map_err(debug)?;
        let mut out = vec![0_u8; 4096];
        unsafe_ocall!(sgxlib_ra_ocall(
            data.len(),
            data.as_ptr(),
            out.len(),
            out.as_mut_ptr(),
        ))
        .map_err(|err| format!("ocall fail: {:?}", err))?;
        let len = out
            .iter()
            .position(|n| *n == '\0' as u8)
            .ok_or(format!("invalid result"))?;
        let result: RaFfi = serde_json::from_slice(&out[..len]).map_err(debug)?;
        Ok(result)
    }

    #[cfg(feature = "std")]
    pub fn get_epid_gpid() -> u32 {
        let mut extended_epid_gid = 0u32;
        unsafe { to_result(sgx_get_extended_epid_group_id(&mut extended_epid_gid)).unwrap() }
        extended_epid_gid
    }

    #[cfg(feature = "tstd")]
    pub fn get_epid_gpid() -> u32 {
        let result = Self::GetEpidGid { response: None }.call().unwrap();
        if let Self::GetEpidGid { response: Some(id) } = result {
            return id;
        }
        unreachable!()
    }

    #[cfg(feature = "std")]
    pub fn sgx_ra_get_msg1(
        context: sgx_ra_context_t,
        eid: sgx_enclave_id_t,
    ) -> Result<HexBytes, String> {
        use crate::RaMsg1;
        glog::info!("call sgx_ra_get_msg1 on std");
        let mut msg1 = sgx_ra_msg1_t::default();
        unsafe {
            to_result(sgx_ra_get_msg1(
                context,
                eid,
                sgx_ra_get_ga,
                (&mut msg1) as *mut sgx_ra_msg1_t,
            ))
            .map_err(debug)?;
        }
        Ok(RaMsg1::to_hex(msg1))
    }

    #[cfg(feature = "tstd")]
    pub fn sgx_ra_get_msg1(
        context: sgx_ra_context_t,
        eid: sgx_enclave_id_t,
    ) -> Result<HexBytes, String> {
        let result = Self::GetMsg1 {
            request: Some((context, eid)),
            response: None,
        }
        .call()?;
        if let Self::GetMsg1 {
            request: None,
            response: Some(msg),
        } = result
        {
            return Ok(msg);
        }
        unreachable!()
    }

    #[cfg(feature = "std")]
    pub fn sgx_ra_proc_msg2(
        context: sgx_ra_context_t,
        enclave_id: sgx_enclave_id_t,
        msg2: &[u8],
    ) -> Result<HexBytes, String> {
        let p_msg2 = msg2 as *const _ as *const sgx_ra_msg2_t;
        let msg2_size = msg2.len() as u32;
        let mut msg3_ptr: *mut sgx_ra_msg3_t = 0 as *mut sgx_ra_msg3_t;
        let mut msg3_size = 0_u32;
        unsafe {
            to_result(sgx_ra_proc_msg2(
                context,
                enclave_id,
                sgx_ra_proc_msg2_trusted,
                sgx_ra_get_msg3_trusted,
                p_msg2,
                msg2_size,
                &mut msg3_ptr,
                &mut msg3_size,
            ))
            .map_err(debug)?
        }

        let msg3_slice =
            unsafe { std::slice::from_raw_parts(msg3_ptr as *const u8, msg3_size as usize) };
        Ok(msg3_slice.to_vec().into())
    }

    #[cfg(feature = "tstd")]
    pub fn sgx_ra_proc_msg2(
        context: sgx_ra_context_t,
        enclave_id: sgx_enclave_id_t,
        msg2: &[u8],
    ) -> Result<HexBytes, String> {
        let result = Self::ProcMsg2 {
            request: Some((context, enclave_id, msg2.into())),
            response: None,
        }
        .call()
        .unwrap();
        if let Self::ProcMsg2 {
            request: None,
            response: Some(msg3),
        } = result
        {
            return Ok(msg3);
        }
        unreachable!()
    }

    pub fn init_ra(pubkey: &sgx_ec256_public_t) -> Result<sgx_ra_context_t, sgx_status_t> {
        let ctx = rsgx_ra_init(pubkey, 0)?;
        Ok(ctx)
    }

    // #[cfg(feature = "tstd")]
    // pub fn enclave_ra_finalize(
    //     ra_context: sgx_ra_context_t,
    //     msg: Sr25519SignedMsg<Secp256r1PublicKey>,
    // ) -> Result<Aes128EncryptedMsg, String> {
    //     let finalize_request_bytes = serde_json::to_vec(&msg).unwrap();
    //     let sk: Aes128Key = rsgx_ra_get_keys(ra_context, sgx_ra_key_type_t::SGX_RA_KEY_SK)
    //         .unwrap()
    //         .into();
    //     let msg = sk.encrypt(&finalize_request_bytes);
    //     Ok(msg)
    // }

    #[cfg(feature = "tstd")]
    pub fn get_ra_key(ra_context: sgx_ra_context_t) -> Result<Aes128Key, String> {
        Ok(
            rsgx_ra_get_keys(ra_context, sgx_ra_key_type_t::SGX_RA_KEY_SK)
                .map_err(debug)?
                .into(),
        )
    }

    #[cfg(feature = "std")]
    pub fn get_ra_key(_ra_context: sgx_ra_context_t) -> Result<Aes128Key, String> {
        unimplemented!("not support calling get_ra_key on std mode yet")
    }
}

#[cfg(feature = "tstd")]
extern "C" {
    // ocalls

    fn ra_get_epid_group_id(retval: *mut u32);
    fn sgxlib_ra_ocall(
        retval: *mut sgx_status_t,
        msg_in_size: size_t,
        msg_in: *const u8,
        msg_out_size: size_t,
        msg_out: *mut u8,
    );
    fn ra_get_msg1(
        retval: *mut sgx_status_t,
        context: sgx_ra_context_t,
        eid: sgx_enclave_id_t,
        msg1: &mut sgx_ra_msg1_t,
    );
    fn ra_proc_msg2(
        retval: *mut sgx_status_t,
        context: sgx_ra_context_t,
        eid: sgx_enclave_id_t,
        msg2_len: size_t,
        msg2: *const u8,
        msg3: *mut *mut sgx_ra_msg3_t,
        msg3_len: *mut size_t,
    );
}

extern "C" {
    pub fn rsgx_self_identity(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    pub fn sgx_ra_get_msg1(
        context: sgx_ra_context_t,
        eid: sgx_enclave_id_t,
        p_get_ga: sgx_ecall_get_ga_trusted_t,
        p_msg1: *mut sgx_ra_msg1_t,
    ) -> sgx_status_t;
    pub fn sgx_ra_get_ga(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        context: sgx_ra_context_t,
        g_a: *mut sgx_ec256_public_t,
    ) -> sgx_status_t;
    pub fn sgx_ra_proc_msg2_trusted(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        context: sgx_ra_context_t,
        p_msg2: *const sgx_ra_msg2_t,
        p_qe_target: *const sgx_target_info_t,
        p_report: *mut sgx_report_t,
        nonce: *mut sgx_quote_nonce_t,
    ) -> sgx_status_t;
    pub fn sgx_ra_get_msg3_trusted(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        context: sgx_ra_context_t,
        quote_size: uint32_t,
        qe_report: *mut sgx_report_t,
        p_msg3: *mut sgx_ra_msg3_t,
        msg3_size: uint32_t,
    ) -> sgx_status_t;
}
