use std::prelude::v1::*;

use crate::{IasReportRequest, IasReportResponse, SgxQuote};

use base::format::debug;
use core::time::Duration;
use eth_types::HexBytes;
use net_http::{HttpClient, HttpMethod, HttpRequestBuilder, Uri};

pub struct IasServer {
    api_key: String,
    client: HttpClient,
    timeout: Option<Duration>,
    base_url: &'static str,
}

impl IasServer {
    pub fn new(apikey: &str, is_dev: bool, timeout: Option<Duration>) -> IasServer {
        let base_url = if is_dev {
            "https://api.trustedservices.intel.com/sgx/dev"
        } else {
            "https://api.trustedservices.intel.com/sgx"
        };

        IasServer {
            client: HttpClient::new(),
            api_key: String::from(apikey),
            base_url,
            timeout,
        }
    }

    pub fn verify_quote(&self, quote: SgxQuote) -> Result<IasReportResponse, String> {
        let quote_bytes = quote.as_bytes();

        // get a random nonce
        let random_nonce = {
            let mut buf = [0_u8; 16];
            crypto::read_rand(&mut buf);
            let random_nonce = format!("{}", HexBytes::from(&buf[..]));
            random_nonce[2..].to_owned()
        };

        let report_request = IasReportRequest {
            isv_enclave_quote: base64::encode(quote_bytes),
            nonce: Some(random_nonce),
        };
        let report_request_json = serde_json::to_string(&report_request).unwrap();

        let api_uri: Uri = format!("{}/attestation/v4/report", self.base_url)
            .parse()
            .map_err(debug)?;

        let api_key = self.api_key.clone();
        let mut req =
            HttpRequestBuilder::new_ex(api_uri, Some(report_request_json.into()), move |req| {
                req.header("Ocp-Apim-Subscription-Key", &api_key)
                    .header("Content-Type", "application/json")
                    .method(HttpMethod::Post);
            });
        let response = self.client.send(&mut req, self.timeout).map_err(debug)?;
        if !response.status.is_success() {
            return Err(String::from_utf8_lossy(&response.body).into());
        }
        let avr: IasReportResponse = serde_json::from_slice(&response.body).map_err(debug)?;
        Ok(avr)
    }

    pub fn get_sigrl(&self, gid: &[u8; 4]) -> Result<Vec<u8>, String> {
        let mut gid_be = [0_u8; 4];
        gid_be.copy_from_slice(gid);
        gid_be.reverse();
        let gid_base16 = base16::encode_lower(&gid_be);
        let api_uri: Uri = format!("{}/attestation/v4/sigrl/{}", self.base_url, gid_base16)
            .parse()
            .map_err(debug)?;
        let api_key = self.api_key.clone();
        let mut req = HttpRequestBuilder::new_ex(api_uri, None, move |req| {
            req.header("Ocp-Apim-Subscription-Key", &api_key)
                .method(HttpMethod::Get);
        });
        let res = self.client.send(&mut req, self.timeout).map_err(debug)?;
        if !res.status.is_success() {
            if res.body.len() == 0 {
                return Err(format!("get_sigrl: {:?}", res.status));
            }
            return Err(String::from_utf8_lossy(&res.body).into());
        }
        Ok(base64::decode(&res.body).map_err(debug)?)
    }
}
