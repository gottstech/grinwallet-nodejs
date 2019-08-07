// Copyright 2019 Gary Yu.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
extern crate neon;
use neon::prelude::*;

use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::{channel, TryRecvError};

use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use grin_wallet_api::{Foreign, Owner};
use grin_wallet_config::{GrinRelayConfig, WalletConfig};
use grin_wallet_impls::{
    instantiate_wallet, Error, ErrorKind, FileWalletCommAdapter, HTTPNodeClient,
    HTTPWalletCommAdapter, LMDBBackend, GrinrelayWalletCommAdapter, WalletSeed,
};
use grin_wallet_libwallet::api_impl::types::InitTxArgs;
use grin_wallet_libwallet::{NodeClient, WalletInst, SlateVersion, VersionedSlate};
use grin_wallet_util::grin_core::global::ChainTypes;
use grin_wallet_util::grin_keychain::ExtKeychain;
use grin_wallet_util::grin_util::{file::get_first_line, Mutex, ZeroingString};
use grin_wallet_controller::{grinrelay_address, grinrelay_listener};
use neon::types::JsString;

/// Default minimum confirmation
pub const MINIMUM_CONFIRMATIONS: u64 = 10;

fn result_to_jsresult(mut cx: FunctionContext, res: Result<String, Error>) -> JsResult<JsString> {
    match res {
        Ok(res) => {
            Ok(cx.string(res))
        }
        Err(e) => {
            cx.throw_type_error(e.to_string())
        }
    }
}

fn result2_to_jsresult(mut cx: FunctionContext, res: Result<(bool, String), Error>) -> JsResult<JsString> {
    match res {
        Ok(res) => {
            //todo: how to parse the res.0 (i.e. the is_refreshed state)
            Ok(cx.string(res.1))
        }
        Err(e) => {
            cx.throw_type_error(e.to_string())
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct MobileWalletCfg {
    account: String,
    chain_type: String,
    data_dir: String,
    node_api_addr: String,
    password: String,
    minimum_confirmations: u64,
    grinrelay_config: Option<GrinRelayConfig>,
}

impl MobileWalletCfg {
    pub fn from_str(json_cfg: &str) -> Result<Self, Error> {
        serde_json::from_str::<MobileWalletCfg>(json_cfg)
            .map_err(|e| Error::from(ErrorKind::GenericError(e.to_string())))
    }
}

fn new_wallet_config(config: MobileWalletCfg) -> Result<WalletConfig, Error> {
    let chain_type = match config.chain_type.as_str() {
        "mainnet" => ChainTypes::Mainnet,
        "floonet" => ChainTypes::Floonet,
        _ => {
            return Err(Error::from(ErrorKind::GenericError(
                "unsupported chain type".to_owned(),
            )));
        }
    };

    Ok(WalletConfig {
        chain_type: Some(chain_type),
        api_listen_interface: "127.0.0.1".to_string(),
        api_listen_port: 3415,
        owner_api_listen_port: Some(3420),
        api_secret_path: Some(".api_secret".to_string()),
        node_api_secret_path: Some(config.data_dir.clone() + "/.api_secret"),
        check_node_api_http_addr: config.node_api_addr,
        owner_api_include_foreign: Some(false),
        data_file_dir: config.data_dir + "/wallet_data",
        no_commit_cache: Some(false),
        tls_certificate_file: None,
        tls_certificate_key: None,
        dark_background_color_scheme: Some(true),
        keybase_notify_ttl: Some(1440),
        grinrelay_config: Some(config.grinrelay_config.clone().unwrap_or_default()),
    })
}

fn check_password(json_cfg: &str, password: &str) -> Result<String, Error> {
    let wallet_config = new_wallet_config(MobileWalletCfg::from_str(json_cfg)?)?;
    WalletSeed::from_file(&wallet_config.data_file_dir, password).map_err(|e| Error::from(e))?;
    Ok("OK".to_owned())
}

#[no_mangle]
pub fn grin_check_password(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let password = cx.argument::<JsString>(1)?.value();

    let res = check_password(&json_cfg, &password);
    result_to_jsresult(cx, res)
}

fn init_wallet_seed() -> Result<String, Error> {
    WalletSeed::init_new(32).to_mnemonic()
}

#[no_mangle]
pub fn grin_init_wallet_seed(cx: FunctionContext) -> JsResult<JsString> {
    let res = init_wallet_seed();
    result_to_jsresult(cx, res)
}

fn wallet_init(json_cfg: &str, password: &str, is_12_phrases: bool) -> Result<String, Error> {
    let wallet_config = new_wallet_config(MobileWalletCfg::from_str(json_cfg)?)?;
    let node_api_secret = get_first_line(wallet_config.node_api_secret_path.clone());
    let seed_length = if is_12_phrases { 16 } else { 32 };
    let seed = WalletSeed::init_file(&wallet_config.data_file_dir, seed_length, None, password, false)?;
    let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, node_api_secret);
    let _: LMDBBackend<HTTPNodeClient, ExtKeychain> =
        LMDBBackend::new(wallet_config, password, node_client)?;
    seed.to_mnemonic()
}

#[no_mangle]
pub fn grin_wallet_init(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let password = cx.argument::<JsString>(1)?.value();
    let is_12_phrases= cx.argument::<JsBoolean>(2)?.value();

    let res = wallet_init(&json_cfg, &password, is_12_phrases);
    result_to_jsresult(cx, res)
}

fn wallet_init_recover(json_cfg: &str, mnemonic: &str) -> Result<String, Error> {
    let config = MobileWalletCfg::from_str(json_cfg)?;
    let wallet_config = new_wallet_config(config.clone())?;
    WalletSeed::recover_from_phrase(&wallet_config.data_file_dir, mnemonic, config.password.as_str())?;
    let node_api_secret = get_first_line(wallet_config.node_api_secret_path.clone());
    let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, node_api_secret);
    let _: LMDBBackend<HTTPNodeClient, ExtKeychain> =
        LMDBBackend::new(wallet_config, config.password.as_str(), node_client)?;
    Ok("OK".to_owned())
}

#[no_mangle]
pub fn grin_wallet_init_recover(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let mnemonic = cx.argument::<JsString>(1)?.value();

    let res = wallet_init_recover(
        &json_cfg,
        &mnemonic,
    );
    result_to_jsresult(cx, res)
}

fn wallet_change_password(
    json_cfg: &str,
    old_password: &str,
    new_password: &str,
) -> Result<String, Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);

    api.change_password(&Some(ZeroingString::from(old_password)), new_password)
        .map_err(|e| Error::from(e))?;
    Ok("OK".to_owned())
}

#[no_mangle]
pub fn grin_wallet_change_password(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let old_password = cx.argument::<JsString>(1)?.value();
    let new_password = cx.argument::<JsString>(2)?.value();

    let res = wallet_change_password(
        &json_cfg,
        &old_password,
        &new_password,
    );
    result_to_jsresult(cx, res)
}

fn wallet_restore(
    json_cfg: &str,
    start_index: u64,
    batch_size: u64,
) -> Result<String, Error> {
    let config = MobileWalletCfg::from_str(json_cfg)?;
    let wallet_config = new_wallet_config(config.clone())?;
    let node_api_secret = get_first_line(wallet_config.node_api_secret_path.clone());
    let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, node_api_secret);
    let wallet = instantiate_wallet(wallet_config, node_client, config.password.as_str(), &config.account)?;
    let api = Owner::new(wallet.clone());

    let (highest_index, last_retrieved_index, num_of_found) = api
        .restore_batch(start_index, batch_size)
        .map_err(|e| Error::from(e))?;
    Ok(json!({
        "highestIndex": highest_index,
        "lastRetrievedIndex": last_retrieved_index,
        "numberOfFound": num_of_found,
    })
        .to_string())
}

#[no_mangle]
pub fn grin_wallet_restore(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let start_index = cx.argument::<JsNumber>(1)?.value();
    let batch_size = cx.argument::<JsNumber>(2)?.value();

    let start_index = start_index as u64;
    let batch_size = batch_size as u64;

    let res = wallet_restore(
        &json_cfg,
        start_index,
        batch_size,
    );
    result_to_jsresult(cx, res)
}

fn wallet_check(
    json_cfg: &str,
    start_index: u64,
    batch_size: u64,
    update_outputs: bool,
) -> Result<String, Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);
    let (highest_index, last_retrieved_index) = api
        .check_repair_batch(true, start_index, batch_size, update_outputs)
        .map_err(|e| Error::from(e))?;

    Ok(json!({
        "highestIndex": highest_index,
        "lastRetrievedIndex": last_retrieved_index,
    })
        .to_string())
}

#[no_mangle]
pub fn grin_wallet_check(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let start_index = cx.argument::<JsNumber>(1)?.value();
    let batch_size = cx.argument::<JsNumber>(2)?.value();
    let update_outputs = cx.argument::<JsBoolean>(3)?.value();

    let start_index = start_index as u64;
    let batch_size = batch_size as u64;

    let res = wallet_check(
        &json_cfg,
        start_index,
        batch_size,
        update_outputs,
    );
    result_to_jsresult(cx, res)
}

fn get_wallet_mnemonic(json_cfg: &str) -> Result<String, Error> {
    let config = MobileWalletCfg::from_str(json_cfg)?;
    let wallet_config = new_wallet_config(config.clone())?;
    let seed = WalletSeed::from_file(&wallet_config.data_file_dir, config.password.as_str())?;
    seed.to_mnemonic()
}

#[no_mangle]
pub fn grin_get_wallet_mnemonic(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();

    let res = get_wallet_mnemonic(&json_cfg);
    result_to_jsresult(cx, res)
}

fn get_wallet_instance(
    config: MobileWalletCfg,
) -> Result<Arc<Mutex<WalletInst<impl NodeClient, ExtKeychain>>>, Error> {
    let wallet_config = new_wallet_config(config.clone())?;
    let node_api_secret = get_first_line(wallet_config.node_api_secret_path.clone());
    let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, node_api_secret);

    instantiate_wallet(
        wallet_config,
        node_client,
        config.password.as_str(),
        config.account.as_str(),
    )
}

fn get_balance(json_cfg: &str) -> Result<(bool, String), Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);
    let (validated, wallet_info) = api.retrieve_summary_info(true, MINIMUM_CONFIRMATIONS)?;
    Ok((validated, serde_json::to_string(&wallet_info).unwrap()))
}

#[no_mangle]
pub fn grin_get_balance(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();

    let res = get_balance(&json_cfg);
    result2_to_jsresult(cx, res)
}

fn tx_retrieve(json_cfg: &str, tx_slate_id: &str) -> Result<String, Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);
    let uuid = Uuid::parse_str(tx_slate_id).map_err(|e| ErrorKind::GenericError(e.to_string()))?;
    let txs = api.retrieve_txs(true, None, Some(uuid))?;
    Ok(serde_json::to_string(&txs).unwrap())
}

#[no_mangle]
pub fn grin_tx_retrieve(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let tx_slate_id = cx.argument::<JsString>(1)?.value();

    let res = tx_retrieve(
        &json_cfg,
        &tx_slate_id,
    );
    result_to_jsresult(cx, res)
}

fn txs_retrieve(json_cfg: &str) -> Result<String, Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);

    match api.retrieve_txs(true, None, None) {
        Ok(txs) => Ok(serde_json::to_string(&txs).unwrap()),
        Err(e) => Err(Error::from(e)),
    }
}

#[no_mangle]
pub fn grin_txs_retrieve(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();

    let res = txs_retrieve(&json_cfg);
    result_to_jsresult(cx, res)
}

fn outputs_retrieve(json_cfg: &str, tx_id: Option<u32>) -> Result<String, Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);
    let outputs = api.retrieve_outputs(true, true, tx_id)?;
    Ok(serde_json::to_string(&outputs).unwrap())
}

#[no_mangle]
pub fn grin_output_retrieve(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let tx_id = cx.argument::<JsNumber>(1)?.value();
    let tx_id = tx_id as u32;

    let res = outputs_retrieve(&json_cfg, Some(tx_id));
    result_to_jsresult(cx, res)
}

#[no_mangle]
pub fn grin_outputs_retrieve(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();

    let res = outputs_retrieve(&json_cfg, None);
    result_to_jsresult(cx, res)
}

fn init_send_tx(
    json_cfg: &str,
    amount: u64,
    selection_strategy: &str,
    target_slate_version: Option<u16>,
    message: &str,
) -> Result<String, Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);
    let tx_args = InitTxArgs {
        src_acct_name: None,
        amount,
        minimum_confirmations: MINIMUM_CONFIRMATIONS,
        max_outputs: 500,
        num_change_outputs: 1,
        selection_strategy: selection_strategy.to_string(),
        message: Some(message.to_string()),
        target_slate_version,
        estimate_only: None,
        send_args: None,
    };
    let slate = api.init_send_tx(tx_args)?;
    api.tx_lock_outputs(&slate, 0)?;
    Ok(serde_json::to_string(&slate).expect("fail to serialize slate to json string"))
}

#[no_mangle]
pub fn grin_init_tx(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let amount = cx.argument::<JsNumber>(1)?.value() as u64;
    let selection_strategy = cx.argument::<JsString>(2)?.value();
    let target_slate_version = cx.argument::<JsNumber>(3)?.value() as i16;
    let message = cx.argument::<JsString>(4)?.value();

    let mut slate_version: Option<u16> = None;
    if target_slate_version >= 0 {
        slate_version = Some(target_slate_version as u16);
    }

    let res = init_send_tx(
        &json_cfg,
        amount,
        &selection_strategy,
        slate_version,
        &message,
    );
    result_to_jsresult(cx, res)
}

fn listen(
    json_cfg: &str,
) -> Result<String, Error> {
    let config = MobileWalletCfg::from_str(json_cfg)?;
    let wallet = get_wallet_instance(config.clone())?;

    // The streaming channel between 'grinrelay_listener' and 'foreign_listener'
    let (relay_tx_as_payee, relay_rx) = channel();

    // Start a Grin Relay service firstly
    let grinrelay_listener = grinrelay_listener(
        wallet.clone(),
        config.grinrelay_config.clone().unwrap_or_default(),
        None,
        Some(relay_tx_as_payee),
    )?;

    let _handle = thread::spawn(move || {
        let api = Foreign::new(wallet, None);
        loop {
            match relay_rx.try_recv() {
                Ok((addr, slate)) => {
                    let _slate_id = slate.id;
                    if api.verify_slate_messages(&slate).is_ok() {
                        let slate_rx = api.receive_tx(&slate, Some(&config.account), None);
                        if let Ok(slate_rx) = slate_rx {
                            let versioned_slate =
                                VersionedSlate::into_version(slate_rx.clone(), SlateVersion::V2);
                            let res = grinrelay_listener.publish(&versioned_slate, &addr.to_owned());
                            match res {
                                Ok(_) => {
//                                    info!(
//                                        "Slate [{}] sent back to {} successfully",
//                                        slate_id.to_string().bright_green(),
//                                        addr.bright_green(),
//                                    );
                                }
                                Err(_e) => {
//                                    error!(
//                                        "Slate [{}] fail to sent back to {} for {}",
//                                        slate_id.to_string().bright_green(),
//                                        addr.bright_green(),
//                                        e,
//                                    );
                                }
                            }
                        }
                    }
                }
                Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {}
            }
            thread::sleep(Duration::from_millis(100));
        }
    });

//    if handle.is_err() {
//        Err(ErrorKind::GenericError("Listen thread fail to start".to_string()).into())?
//    }
    Ok("OK".to_owned())
}

#[no_mangle]
pub fn grin_listen(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();

    let res = listen(&json_cfg);
    result_to_jsresult(cx, res)
}

fn relay_addr(
    json_cfg: &str,
) -> Result<String, Error> {
    let config = MobileWalletCfg::from_str(json_cfg)?;
    let wallet = get_wallet_instance(config.clone())?;
    Ok(grinrelay_address(
        wallet.clone(),
        config.grinrelay_config.clone().unwrap_or_default(),
    )?)
}

#[no_mangle]
pub fn grin_relay_addr(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();

    let res = relay_addr(&json_cfg);
    result_to_jsresult(cx, res)
}

fn send_tx_by_http(
    json_cfg: &str,
    amount: u64,
    receiver_wallet_url: &str,
    selection_strategy: &str,
    target_slate_version: Option<u16>,
    message: &str,
) -> Result<String, Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);
    let args = InitTxArgs {
        src_acct_name: None,
        amount,
        minimum_confirmations: MINIMUM_CONFIRMATIONS,
        max_outputs: 500,
        num_change_outputs: 1,
        selection_strategy: selection_strategy.to_string(),
        message: Some(message.to_string()),
        target_slate_version,
        estimate_only: None,
        send_args: None,
    };
    let slate_r1 = api.init_send_tx(args)?;

    let adapter = HTTPWalletCommAdapter::new();
    match adapter.send_tx_sync(receiver_wallet_url, &slate_r1) {
        Ok(slate) => {
            api.verify_slate_messages(&slate)?;
            api.tx_lock_outputs(&slate_r1, 0)?;

            let finalized_slate = api.finalize_tx(&slate);
            if finalized_slate.is_err() {
                api.cancel_tx(None, Some(slate_r1.id))?;
            }
            let finalized_slate = finalized_slate?;

            let res = api.post_tx(&finalized_slate.tx, false);
            if res.is_err() {
                api.cancel_tx(None, Some(slate_r1.id))?;
                res?;
            }

            Ok(serde_json::to_string(&finalized_slate).expect("fail to serialize slate to json string"))
        }
        Err(e) => {
            Err(Error::from(e))
        }
    }
}

fn send_tx_by_relay(
    json_cfg: &str,
    amount: u64,
    receiver_addr: &str,
    selection_strategy: &str,
    target_slate_version: Option<u16>,
    message: &str,
) -> Result<String, Error> {
    let config = MobileWalletCfg::from_str(json_cfg)?;
    let wallet = get_wallet_instance(config.clone())?;
    let api = Owner::new(wallet.clone());
    let args = InitTxArgs {
        src_acct_name: None,
        amount,
        minimum_confirmations: MINIMUM_CONFIRMATIONS,
        max_outputs: 500,
        num_change_outputs: 1,
        selection_strategy: selection_strategy.to_string(),
        message: Some(message.to_string()),
        target_slate_version,
        estimate_only: None,
        send_args: None,
    };
    let slate_r1 = api.init_send_tx(args)?;

    // The streaming channel between 'grinrelay_listener' and 'GrinrelayWalletCommAdapter'
    let (relay_tx_as_payer, relay_rx) = channel();

    // Start a Grin Relay service firstly
    let grinrelay_listener = grinrelay_listener(
        wallet.clone(),
        config.grinrelay_config.clone().unwrap_or_default(),
        Some(relay_tx_as_payer),
        None,
    )?;
    thread::sleep(Duration::from_millis(1_000));

    let adapter = GrinrelayWalletCommAdapter::new(grinrelay_listener, relay_rx);
    match adapter.send_tx_sync(receiver_addr, &slate_r1.clone()) {
        Ok(mut slate) => {
            api.verify_slate_messages(&slate)?;
            api.tx_lock_outputs(&slate_r1, 0)?;

            let finalized_slate = api.finalize_tx(&mut slate);
            if finalized_slate.is_err() {
                api.cancel_tx(None, Some(slate_r1.id))?;
            }
            let finalized_slate = finalized_slate?;

            let res = api.post_tx(&finalized_slate.tx, false);
            if res.is_err() {
                api.cancel_tx(None, Some(slate_r1.id))?;
                res?;
            }

            Ok(serde_json::to_string(&finalized_slate).expect("fail to serialize slate to json string"))
        }
        Err(e) => {
            Err(Error::from(e))
        }
    }
}

#[no_mangle]
pub fn grin_send_tx(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let amount = cx.argument::<JsNumber>(1)?.value() as u64;
    let receiver_addr_or_url = cx.argument::<JsString>(2)?.value();
    let selection_strategy = cx.argument::<JsString>(3)?.value();
    let target_slate_version = cx.argument::<JsNumber>(4)?.value() as i16;
    let message = cx.argument::<JsString>(5)?.value();

    let mut slate_version: Option<u16> = None;
    if target_slate_version >= 0 {
        slate_version = Some(target_slate_version as u16);
    }

    let receiver = &receiver_addr_or_url;
    let res = if receiver.starts_with("http://") || receiver.starts_with("https://") {
        send_tx_by_http(
            &json_cfg,
            amount,
            receiver,
            &selection_strategy,
            slate_version,
            &message,
        )
    } else {
        send_tx_by_relay(
            &json_cfg,
            amount,
            receiver,
            &selection_strategy,
            slate_version,
            &message,
        )
    };
    result_to_jsresult(cx, res)
}

fn cancel_tx(json_cfg: &str, tx_slate_id: &str) -> Result<String, Error> {
    let uuid = Uuid::parse_str(tx_slate_id).map_err(|e| ErrorKind::GenericError(e.to_string()))?;
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);
    api.cancel_tx(None, Some(uuid))?;
    Ok("OK".to_owned())
}

#[no_mangle]
pub fn grin_cancel_tx(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let tx_slate_id = cx.argument::<JsString>(1)?.value();

    let res = cancel_tx(&json_cfg, &tx_slate_id);
    result_to_jsresult(cx, res)
}

fn post_tx(json_cfg: &str, tx_slate_id: &str) -> Result<String, Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);
    let uuid = Uuid::parse_str(tx_slate_id).map_err(|e| ErrorKind::GenericError(e.to_string()))?;
    let (validated, txs) = api.retrieve_txs(true, None, Some(uuid))?;
    if txs[0].confirmed {
        return Err(Error::from(ErrorKind::GenericError(format!(
            "Transaction already confirmed"
        ))));
    } else if !validated {
        return Err(Error::from(ErrorKind::GenericError(format!(
            "api.retrieve_txs not validated"
        ))));
    }

    let stored_tx = api.get_stored_tx(&txs[0])?;
    match stored_tx {
        Some(stored_tx) => {
            api.post_tx(&stored_tx, false)?;
            Ok("OK".to_owned())
        }
        None => Err(Error::from(ErrorKind::GenericError(format!(
            "transaction data not found"
        )))),
    }
}

#[no_mangle]
pub fn grin_post_tx(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let tx_slate_id = cx.argument::<JsString>(1)?.value();

    let res = post_tx(
        &json_cfg,
        &tx_slate_id,
    );
    result_to_jsresult(cx, res)
}

fn tx_file_receive(
    json_cfg: &str,
    slate_file_path: &str,
    message: &str,
) -> Result<String, Error> {
    let config = MobileWalletCfg::from_str(json_cfg)?;
    let wallet = get_wallet_instance(config.clone())?;
    let api = Foreign::new(wallet, None);
    let adapter = FileWalletCommAdapter::new();
    let mut slate = adapter.receive_tx_async(&slate_file_path)?;
    api.verify_slate_messages(&slate)?;
    slate = api.receive_tx(&slate, Some(&config.account), Some(message.to_string()))?;
    Ok(serde_json::to_string(&slate).expect("fail to serialize slate to json string"))
}

#[no_mangle]
pub fn grin_tx_file_receive(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let slate_file_path = cx.argument::<JsString>(1)?.value();
    let message = cx.argument::<JsString>(2)?.value();

    let res = tx_file_receive(
        &json_cfg,
        &slate_file_path,
        &message,
    );
    result_to_jsresult(cx, res)
}

fn tx_file_finalize(
    json_cfg: &str,
    slate_file_path: &str,
) -> Result<String, Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);
    let adapter = FileWalletCommAdapter::new();
    let mut slate = adapter.receive_tx_async(slate_file_path)?;
    api.verify_slate_messages(&slate)?;
    slate = api.finalize_tx(&slate)?;
    Ok(serde_json::to_string(&slate).expect("fail to serialize slate to json string"))
}

#[no_mangle]
pub fn grin_tx_file_finalize(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();
    let slate_file_path = cx.argument::<JsString>(1)?.value();

    let res = tx_file_finalize(
        &json_cfg,
        &slate_file_path,
    );
    result_to_jsresult(cx, res)
}

fn chain_height(json_cfg: &str) -> Result<String, Error> {
    let wallet = get_wallet_instance(MobileWalletCfg::from_str(json_cfg)?)?;
    let api = Owner::new(wallet);
    let height = api.node_height()?;
    Ok(serde_json::to_string(&height).unwrap())
}

#[no_mangle]
pub fn grin_chain_height(mut cx: FunctionContext) -> JsResult<JsString> {
    let json_cfg = cx.argument::<JsString>(0)?.value();

    let res = chain_height(&json_cfg);
    result_to_jsresult(cx, res)
}

register_module!(mut cx, {
    cx.export_function("grinCheckPassword", grin_check_password)?;
    cx.export_function("grinWalletChangePassword", grin_wallet_change_password)?;
    cx.export_function("grinWalletInit", grin_wallet_init)?;
    cx.export_function("grinWalletInitRecover", grin_wallet_init_recover)?;
    cx.export_function("grinWalletRestore", grin_wallet_restore)?;
    cx.export_function("grinWalletCheck", grin_wallet_check)?;
    cx.export_function("grinGetWalletMnemonic", grin_get_wallet_mnemonic)?;
    cx.export_function("grinGetBalance", grin_get_balance)?;
    cx.export_function("grinTxRetrieve", grin_tx_retrieve)?;
    cx.export_function("grinTxsRetrieve", grin_txs_retrieve)?;
    cx.export_function("grinOutputRetrieve", grin_output_retrieve)?;
    cx.export_function("grinOutputsRetrieve", grin_outputs_retrieve)?;
    cx.export_function("grinListen", grin_listen)?;
    cx.export_function("grinRelayAddr", grin_relay_addr)?;
    cx.export_function("grinInitTx", grin_init_tx)?;
    cx.export_function("grinSendTx", grin_send_tx)?;
    cx.export_function("grinCancelTx", grin_cancel_tx)?;
    cx.export_function("grinPostTx", grin_post_tx)?;
    cx.export_function("grinTxFileReceive", grin_tx_file_receive)?;
    cx.export_function("grinTxFileFinalize", grin_tx_file_finalize)?;
    cx.export_function("grinChainHeight", grin_chain_height)?;
    Ok(())
});
