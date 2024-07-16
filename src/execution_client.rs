use std::prelude::v1::*;

use base::{format::debug, trace::Alive};
use core::time::Duration;
use crypto::Secp256k1PrivateKey;
use eth_types::{BlockSelector, HexBytes, LegacyTx, Receipt, SH160, SH256, SU64, SU256, Transaction, TransactionInner};
use jsonrpc::{JsonrpcClient, MixRpcClient, RpcClient, RpcError};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use solidity::EncodeArg;

#[derive(Debug, Clone)]
pub struct ExecutionClient<C: RpcClient> {
    client: JsonrpcClient<C>,
    to: SH160,
    alive: Alive,
    chain_id: u64,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthCall {
    pub to: SH160,
    pub from: Option<SH160>,
    pub gas: Option<SU64>,
    pub gas_price: Option<SU256>,
    pub data: HexBytes,
}

impl<C: RpcClient> ExecutionClient<C> {
    pub fn new(client: C) -> Self {
        let client = JsonrpcClient::new(client);
        let chain_id: SU64 = client.rpc("eth_chainId", ()).unwrap();
        Self {
            client,
            to: "0x6467C250d968A852D3Adcd962c43d2A05811cF20".into(),
            alive: Alive::new(),
            chain_id: chain_id.as_u64(),
        }
    }

    pub fn raw(&self) -> &JsonrpcClient<C> {
        &self.client
    }

    pub fn chain_id(&self) -> Result<u64, RpcError> {
        let chain_id: SU64 = self.client.rpc("eth_chainId", ())?;
        Ok(chain_id.as_u64())
    }

    pub fn nonce(&self, addr: &SH160, block: BlockSelector) -> Result<SU64, RpcError> {
        self.client.rpc("eth_getTransactionCount", (addr, block))
    }

    pub fn gas_price(&self) -> Result<SU256, RpcError> {
        self.client.rpc("eth_gasPrice", ())
    }

    pub fn send_raw_transaction(&self, tx: &TransactionInner) -> Result<SH256, RpcError> {
        self.client.rpc("eth_sendRawTransaction", (tx,))
    }

    pub fn get_block_number(&self) -> Result<SU64, RpcError> {
        self.client.rpc("eth_blockNumber", ())
    }

    pub fn get_transaction(&self, tx: &SH256) -> Result<Transaction, RpcError> {
        self.client.rpc("eth_getTransactionByHash", [tx])
    }

    pub fn get_receipt(&self, hash: &SH256) -> Result<Option<Receipt>, RpcError> {
        self.client.rpc("eth_getTransactionReceipt", (hash,))
    }

    pub fn get_receipts(&self, hashes: &[SH256]) -> Result<Vec<Receipt>, RpcError> {
        let hashes = hashes.iter().map(|n| [n]).collect::<Vec<_>>();
        self.client.batch_rpc("eth_getTransactionReceipt", &hashes)
    }

    pub fn eth_call<T>(&self, call: EthCall, block: BlockSelector) -> Result<T, RpcError>
    where
        T: DeserializeOwned,
    {
        self.client.rpc("eth_call", (call, block))
    }

    fn send_tx(&self, submitter: &Secp256k1PrivateKey, data: Vec<u8>) -> Result<SH256, RpcError> {
        let addr = submitter.public().eth_accountid().into();
        let nonce = self.nonce(&addr, BlockSelector::Latest)?;
        let gas_price = self.gas_price()?;

        let call: Result<serde_json::Value, RpcError> = self.eth_call(
            EthCall {
                to: self.to.clone(),
                from: Some(addr),
                gas: None,
                gas_price: None,
                data: data.clone().into(),
            },
            BlockSelector::Latest,
        );
        match call {
            Ok(_) => {}
            Err(err) => {
                glog::info!("call: {:?}", err);
                return Err(err);
            }
        }

        let mut tx = TransactionInner::Legacy(LegacyTx {
            nonce,
            gas_price,
            gas: 9000000.into(),
            to: Some(self.to.clone()).into(),
            data: data.into(),
            ..Default::default()
        });
        tx.sign(submitter, self.chain_id);

        self.send_raw_transaction(&tx)
    }

    pub fn wait_receipt(&self, hash: &SH256, timeout: Duration) -> Result<(), String> {
        let alive = self.alive.fork_with_timeout(timeout);
        while alive.is_alive() {
            match self.get_receipt(&hash) {
                Ok(Some(receipt)) => {
                    glog::info!("got receipt({:?}): {:?}", hash, receipt);
                    return Ok(());
                }
                Ok(None) => {
                    glog::info!("waiting receipt({:?}): unconfirmed, retry in 1 secs", hash,);
                }
                Err(err) => {
                    glog::info!("waiting receipt({:?}): {:?}, retry in 1 secs", hash, err);
                }
            }
            alive.sleep_ms(1000);
        }
        Err(format!("waiting receipt({:?}) failed: timeout", hash))
    }

    pub fn submit_attestation_report(
        &self,
        submitter: &Secp256k1PrivateKey,
        dcap_report: &[u8],
    ) -> Result<(), String> {
        let mut encoder = solidity::Encoder::new("submitAttestation");
        encoder.add(dcap_report);
        encoder.add(&SU256::zero());
        encoder.add(&false);
        let deps: Vec<(SH160, SH256)> = vec![];
        encoder.add(&deps);
        let data = encoder.encode();
        let result = self.send_tx(submitter, data).map_err(debug)?;
        self.wait_receipt(&result, Duration::from_secs(60))?;
        Ok(())
    } 
}

pub fn submit_dcap_quote<C: RpcClient>(
    el: &ExecutionClient<C>,
    submitter: &Secp256k1PrivateKey,
    dcap_report: &[u8]
) -> Result<(), String> {
    el.submit_attestation_report(submitter, dcap_report)
}
