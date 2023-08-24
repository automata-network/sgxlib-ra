use std::prelude::v1::*;

use core::mem::size_of;
use core::mem::transmute;
use crypto::Aes128EncryptedMsg;
use crypto::Aes128Key;
use crypto::Aes128Mac;
use crypto::Secp256r1PublicKey;
use eth_types::HexBytes;
use memoffset::offset_of;
use serde::{Deserialize, Serialize};
use sgxlib::sgx_types::{
    sgx_attributes_t, sgx_isv_svn_t, sgx_mac_t, sgx_prod_id_t, sgx_quote_t, sgx_ra_msg1_t,
    sgx_ra_msg2_t, sgx_ra_msg3_t, sgx_report_body_t, uint32_t, SGX_FLAGS_DEBUG, SGX_FLAGS_INITTED,
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IasReportRequest {
    pub isv_enclave_quote: String,
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IasReportResponse {
    pub id: String,
    pub timestamp: String,
    pub version: u32,
    pub isv_enclave_quote_status: String,
    pub isv_enclave_quote_body: String,
    pub revocation_reason: Option<String>,
    pub pse_manifest_status: Option<String>,
    pub pse_manifest_hash: Option<String>,
    pub platform_info_blob: Option<String>,
    pub nonce: Option<String>,
    pub epid_pseudonym: Option<String>,
    #[serde(rename(serialize = "advisoryURL"))]
    #[serde(rename(deserialize = "advisoryURL"))]
    pub advisory_url: Option<String>,
    #[serde(rename(serialize = "advisoryIDs"))]
    #[serde(rename(deserialize = "advisoryIDs"))]
    pub advisory_ids: Option<Vec<String>>,
}

impl IasReportResponse {
    pub fn get_isv_enclave_quote_body(&self) -> Option<SgxQuote> {
        let isv_enclave_quote_body = match base64::decode(&self.isv_enclave_quote_body) {
            Ok(v) => v,
            Err(_) => return None,
        };
        // size of sgx_quote_t is 436 bytes,
        // isv_enclave_quote_body don't have signature and signature len
        SgxQuote::from_isv_bytes(isv_enclave_quote_body)
    }

    pub fn get_isv_enclave_quote_status(&self) -> String {
        self.isv_enclave_quote_status.to_owned()
    }

    pub fn is_enclave_secure(&self, allow_conditional: bool) -> bool {
        // let isv_enclave_quote_status =
        //     EnclaveQuoteStatus::from_str(&self.isv_enclave_quote_status).unwrap();
        let is_secure = match self.isv_enclave_quote_status.as_str() {
            "Ok" => true,
            "SignatureInvalid" => false,
            "GroupRevoked" => false,
            "SignatureRevoked" => false,
            "KeyRevoked" => false,
            "SigrlVersionMismatch" => false,
            // the following items are conditionally "secure"
            "GroupOutOfDate" => allow_conditional,
            "ConfigurationNeeded" => allow_conditional,
            "SwHardeningNeeded" => allow_conditional,
            "ConfigurationAndSwHardeningNeeded" => allow_conditional,
            _ => false,
        };
        is_secure
    }
}

// #[derive(Display, EnumString)]
// #[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
// enum EnclaveQuoteStatus {
//     Ok,
//     SignatureInvalid,
//     GroupRevoked,
//     SignatureRevoked,
//     KeyRevoked,
//     SigrlVersionMismatch,
//     GroupOutOfDate,
//     ConfigurationNeeded,
//     SwHardeningNeeded,
//     ConfigurationAndSwHardeningNeeded,
// }

#[derive(Default, Clone)]
pub struct SgxRaMsg3 {
    pub raw_ra_msg3: sgx_ra_msg3_t,
    pub quote: SgxQuote,
}

#[derive(Default, Clone)]
pub struct SgxQuote {
    pub raw_quote: sgx_quote_t,
    pub signature: Vec<u8>,
}

impl SgxQuote {
    pub fn get_report_body(&self) -> sgx_report_body_t {
        self.raw_quote.report_body
    }

    pub fn get_mr_enclave(&self) -> [u8; 32] {
        self.raw_quote.report_body.mr_enclave.m
    }

    pub fn get_mr_signer(&self) -> [u8; 32] {
        self.raw_quote.report_body.mr_signer.m
    }

    pub fn get_attributes(&self) -> sgx_attributes_t {
        self.raw_quote.report_body.attributes
    }

    pub fn get_isv_prod_id(&self) -> sgx_prod_id_t {
        self.raw_quote.report_body.isv_prod_id
    }

    pub fn get_isv_svn(&self) -> sgx_isv_svn_t {
        self.raw_quote.report_body.isv_svn
    }

    pub fn is_enclave_debug(&self) -> bool {
        self.raw_quote.report_body.attributes.flags & SGX_FLAGS_DEBUG != 0
    }

    pub fn is_enclave_init(&self) -> bool {
        self.raw_quote.report_body.attributes.flags & SGX_FLAGS_INITTED != 0
    }

    #[allow(unaligned_references)]
    pub fn from_isv_bytes(quote_bytes: Vec<u8>) -> Option<SgxQuote> {
        // Check that quote_bytes is sgx_quote_t up till report_body
        if offset_of!(sgx_quote_t, signature_len) != quote_bytes.len() {
            return None;
        }
        let mut raw_quote_buf = [0_u8; size_of::<sgx_quote_t>()];
        raw_quote_buf[..offset_of!(sgx_quote_t, signature_len)].copy_from_slice(&quote_bytes);
        let quote = SgxQuote {
            raw_quote: unsafe {
                transmute::<[u8; size_of::<sgx_quote_t>()], sgx_quote_t>(raw_quote_buf)
            },
            signature: Vec::new(),
        };
        Some(quote)
    }

    pub fn from_bytes(quote_bytes: Vec<u8>) -> Option<SgxQuote> {
        // Check that quote_bytes is at least sgx_quote_t large
        let actual_sig_size: i32 = quote_bytes.len() as i32 - size_of::<sgx_quote_t>() as i32;
        if actual_sig_size < 0 {
            return None;
        }

        let raw_quote = unsafe { *(quote_bytes.as_ptr() as *const sgx_quote_t) };
        if actual_sig_size as usize != raw_quote.signature_len as usize {
            return None;
        }

        let mut signature: Vec<u8> = vec![0; raw_quote.signature_len as usize];
        signature.copy_from_slice(&quote_bytes[size_of::<sgx_quote_t>()..]);

        let quote = SgxQuote {
            raw_quote: raw_quote,
            signature: signature,
        };
        Some(quote)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let quote_size = size_of::<sgx_quote_t>() + self.signature.len();
        let mut quote_bytes = vec![0_u8; quote_size];
        let quote_bytes_ptr = (&self.raw_quote as *const sgx_quote_t) as *const u8;
        let quote_bytes_slice =
            unsafe { core::slice::from_raw_parts(quote_bytes_ptr, size_of::<sgx_quote_t>()) };
        quote_bytes[..size_of::<sgx_quote_t>()].copy_from_slice(quote_bytes_slice);
        quote_bytes[size_of::<sgx_quote_t>()..].copy_from_slice(self.signature.as_slice());
        quote_bytes
    }
}

impl SgxRaMsg3 {
    pub fn verify(&self, smk: &Aes128Key) -> bool {
        let msg3_bytes = self.as_bytes();
        let msg3_content = match msg3_bytes.get(size_of::<sgx_mac_t>()..) {
            Some(v) => v,
            None => return false,
        };
        let msg3_mac = Aes128Mac {
            mac: self.raw_ra_msg3.mac,
        };
        match smk.verify(msg3_content, &msg3_mac) {
            Ok(v) => v,
            Err(err) => {
                glog::error!("aes128cmac_verify meet error: {:?}", err);
                return false;
            }
        }
    }

    pub fn from_slice(msg3_bytes: &[u8]) -> Result<SgxRaMsg3, String> {
        // We take in a vector of bytes representing the entire msg3.
        // As long as we work within the size of the vec, we're safe.

        // Ensure that the length of vec is at least sgx_ra_msg3_t + sgx_quote_t
        if msg3_bytes.len() < size_of::<sgx_ra_msg3_t>() {
            return Err(format!("msg3 msg is too small"));
        }
        let quote_size = msg3_bytes.len() - size_of::<sgx_ra_msg3_t>();
        if quote_size < size_of::<sgx_quote_t>() {
            return Err(format!("invalid quote size"));
        }

        // TODO: Do some sanity check on the structure of sgx_ra_msg3_t
        // sanity_check(msg3);

        // Create a buffer for safety and copy quote object into it
        let mut quote_bytes: Vec<u8> = vec![0; quote_size];
        let msg3_bytes_ptr = msg3_bytes.as_ptr();
        let quote_bytes_ptr = unsafe { msg3_bytes_ptr.offset(size_of::<sgx_ra_msg3_t>() as isize) };
        let quote_slice = unsafe { core::slice::from_raw_parts(quote_bytes_ptr, quote_size) };
        quote_bytes.copy_from_slice(quote_slice);

        // Try to instantiate SgxQuote object
        if let Some(quote) = SgxQuote::from_bytes(quote_bytes) {
            let msg3 = SgxRaMsg3 {
                raw_ra_msg3: unsafe { *(msg3_bytes_ptr as *const sgx_ra_msg3_t) },
                quote: quote,
            };
            Ok(msg3)
        } else {
            return Err(format!("invalid quote"));
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let msg3_size = size_of::<sgx_ra_msg3_t>() + self.quote.as_bytes().len();
        let mut msg3_bytes = vec![0_u8; msg3_size];
        let msg3_bytes_ptr = (&self.raw_ra_msg3 as *const sgx_ra_msg3_t) as *const u8;
        let msg3_bytes_slice =
            unsafe { core::slice::from_raw_parts(msg3_bytes_ptr, size_of::<sgx_ra_msg3_t>()) };
        msg3_bytes[..size_of::<sgx_ra_msg3_t>()].copy_from_slice(msg3_bytes_slice);
        msg3_bytes[size_of::<sgx_ra_msg3_t>()..].copy_from_slice(self.quote.as_bytes().as_slice());
        msg3_bytes
    }
}

#[derive(Debug)]
pub struct AttestationServerInfo {
    pub conditional_secure: bool,
}

#[derive(Clone, Default)]
pub struct SessionKeys {
    pub g_a: Secp256r1PublicKey,
    pub g_b: Secp256r1PublicKey,
    pub kdk: Aes128Key,
    pub smk: Aes128Key,
    pub sk: Aes128Key,
    pub mk: Aes128Key,
}

pub struct RaMsg1;

impl RaMsg1 {
    pub fn to_hex(msg1: sgx_ra_msg1_t) -> HexBytes {
        let buf = unsafe {
            let slice = std::slice::from_raw_parts(
                (&msg1) as *const _ as *const u8,
                std::mem::size_of_val(&msg1),
            );
            slice.to_vec()
        };
        buf.into()
    }

    pub fn to_sgx(buf: &[u8]) -> sgx_ra_msg1_t {
        let mut p_msg1_buf = [0_u8; std::mem::size_of::<sgx_ra_msg1_t>()];
        p_msg1_buf.copy_from_slice(buf);
        let p_msg1: sgx_ra_msg1_t =
            unsafe { transmute::<[u8; size_of::<sgx_ra_msg1_t>()], sgx_ra_msg1_t>(p_msg1_buf) };
        p_msg1
    }
}

pub struct RaMsg2;
impl RaMsg2 {
    pub fn mac(smk: &Aes128Key, p_msg2: &sgx_ra_msg2_t) -> Result<Aes128Mac, String> {
        let p_msg2_slice_size =
            size_of::<sgx_ra_msg2_t>() - (size_of::<sgx_mac_t>() + size_of::<uint32_t>());
        let p_msg2_bytes_slice = unsafe {
            core::slice::from_raw_parts(
                p_msg2 as *const sgx_ra_msg2_t as *const u8,
                p_msg2_slice_size,
            )
        };
        smk.mac(p_msg2_bytes_slice)
    }

    pub fn to_hex(mut p_msg2: sgx_ra_msg2_t, sigrl: &[u8]) -> HexBytes {
        p_msg2.sig_rl_size = sigrl.len() as u32;
        let full_msg2_size = size_of::<sgx_ra_msg2_t>() + p_msg2.sig_rl_size as usize;
        let mut msg2_buf = vec![0; full_msg2_size];
        let msg2_slice = unsafe {
            core::slice::from_raw_parts(
                &p_msg2 as *const sgx_ra_msg2_t as *const u8,
                size_of::<sgx_ra_msg2_t>(),
            )
        };
        msg2_buf[..size_of::<sgx_ra_msg2_t>()].copy_from_slice(msg2_slice);
        msg2_buf[size_of::<sgx_ra_msg2_t>()..].copy_from_slice(sigrl);
        msg2_buf.into()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AttestationServerState {
    None,
    Msg0 {
        msg0: u32, // maybe should use u8?
        enclave_pubkey: Secp256r1PublicKey,
    },
    Msg1 {
        data: HexBytes,
        enclave_pubkey: Secp256r1PublicKey,
    },
    Msg3 {
        data: HexBytes,
        enclave_pubkey: Secp256r1PublicKey,
    },
    Finalize {
        msg: Aes128EncryptedMsg,
        enclave_pubkey: Secp256r1PublicKey,
    },
}

impl Default for AttestationServerState {
    fn default() -> Self {
        Self::None
    }
}

impl AttestationServerState {
    pub fn enclave_key(&self) -> Option<Secp256r1PublicKey> {
        Some(match self {
            Self::None => return None,
            Self::Msg0 { enclave_pubkey, .. } => *enclave_pubkey,
            Self::Msg1 { enclave_pubkey, .. } => *enclave_pubkey,
            Self::Msg3 { enclave_pubkey, .. } => *enclave_pubkey,
            Self::Finalize { enclave_pubkey, .. } => *enclave_pubkey,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AttestationClientState {
    None,
    Msg0 { success: bool },
    Msg2 { msg2_bytes: HexBytes },
    Msg3 { is_verified: bool },
    Finalize {},
}

#[derive(Debug)]
pub enum AttestationStateError {
    UnexpectedState,
    InvalidMsg0,
    InvalidMsg1,
    InvalidMsg3(String),
    ApplyMsg1Fail(String),
    GetMsg1Fail(String),
    GetMsg2Fail(String),
    Msg3FailGetQuote,
    Msg3FailVerifyQuote,
    Msg3FailVerify,
    ServerRejectedMsg0,
    ServerRejectedMsg3,
    ServerRejectedFinalize,
    FinalizeDecryptFail(String),
    FinalizeGenMsgFail(String),
}

