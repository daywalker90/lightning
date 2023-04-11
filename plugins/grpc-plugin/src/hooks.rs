use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Error};
use cln_grpc::{datastore_htlc_expiry, datastore_update_state, listdatastore_state, Hodlstate};
use cln_plugin::Plugin;
use cln_rpc::primitives::Amount;
use log::{debug, info, warn};
use serde_json::json;
use tokio::time;

use crate::{
    util::{listinvoices, make_rpc_path},
    PluginState,
};

pub(crate) async fn htlc_handler(
    plugin: Plugin<PluginState>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    if let Some(htlc) = v.get("htlc") {
        if let Some(pay_hash) = htlc
            .get("payment_hash")
            .and_then(|pay_hash| pay_hash.as_str())
        {
            let rpc_path = make_rpc_path(&plugin);

            let invoice;
            let cltv_delta;
            let cltv_expiry;
            let amount_msat;
            let id;
            match listdatastore_state(&rpc_path, pay_hash.to_string()).await {
                Ok(_h) => {
                    id = match htlc.get("id") {
                        Some(ce) => ce.as_u64().unwrap(),
                        None => {
                            warn!("id not found! payment_hash: {}", pay_hash);
                            return Ok(json!({"result": "fail"}));
                        }
                    };
                    cltv_delta = plugin.state().config.lock().clone().cltv_delta.1 as u32;
                    cltv_expiry = match htlc.get("cltv_expiry") {
                        Some(ce) => ce.as_u64().unwrap() as u32,
                        None => {
                            warn!(
                                "htlc {}: cltv_expiry not found! payment_hash: {}",
                                id, pay_hash
                            );
                            return Ok(json!({"result": "fail"}));
                        }
                    };
                    invoice = listinvoices(&rpc_path, None, Some(pay_hash.to_string()))
                        .await?
                        .invoices
                        .first()
                        .ok_or(anyhow!("htlc {}: invoice not found", id))?
                        .clone();
                    amount_msat = match htlc.get("amount_msat") {
                        Some(ce) =>
                        // Amount::msat(&serde_json::from_str::<Amount>(ce).unwrap()), bugging trailing characters error
                        {
                            let amt_str = ce.as_str().unwrap();
                            amt_str[..amt_str.len() - 4].parse::<u64>().unwrap()
                        }
                        None => {
                            warn!(
                                "htlc {}: amount_msat not found! payment_hash: {} {:?}",
                                id, pay_hash, htlc
                            );
                            return Ok(json!({"result": "fail"}));
                        }
                    };
                    datastore_htlc_expiry(&rpc_path, pay_hash.to_string(), cltv_expiry.to_string())
                        .await?;

                    let mut invoice_amts = plugin.state().invoice_amts.lock();
                    if let Some(amt) = invoice_amts.get_mut(&pay_hash.to_string()) {
                        *amt += amount_msat;
                    } else {
                        invoice_amts.insert(pay_hash.to_string(), amount_msat);
                    }
                    info!(
                        "htlc {}: holding {}msat, payment_hash: `{}`",
                        id, amount_msat, pay_hash
                    );
                }
                Err(e) => {
                    debug!(
                        "{} not our invoice: payment_hash: {}",
                        e.to_string(),
                        pay_hash
                    );
                    return Ok(json!({"result": "continue"}));
                }
            }
            loop {
                {
                    match listdatastore_state(&rpc_path, pay_hash.to_string()).await {
                        Ok(hodlstate) => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            if invoice.expires_at <= now - 20 {
                                warn!(
                                    "htlc {}: hodlinvoice with payment_hash: {} expired, rejecting!",
                                    id,pay_hash
                                );

                                *plugin
                                    .state()
                                    .invoice_amts
                                    .lock()
                                    .get_mut(&pay_hash.to_string())
                                    .unwrap() -= amount_msat;
                                return Ok(json!({"result": "fail"}));
                            }

                            match hodlstate {
                                Hodlstate::Accepted => {
                                    let invoice_amts = plugin.state().invoice_amts.lock().clone();
                                    let cur_amt = invoice_amts.get(&pay_hash.to_string()).unwrap();
                                    if Amount::msat(&invoice.amount_msat.unwrap())
                                        > cur_amt - amount_msat
                                    {
                                        datastore_update_state(
                                            &rpc_path,
                                            pay_hash.to_string(),
                                            Hodlstate::Open.to_string(),
                                        )
                                        .await?;
                                    }
                                }
                                _ => (),
                            };

                            if cltv_expiry
                                <= plugin.state().blockheight.lock().clone() + cltv_delta + 6
                            {
                                warn!(
                                    "htlc {}: timed out for payment_hash: {}, rejecting!",
                                    id, pay_hash
                                );
                                let invoice_amts = plugin.state().invoice_amts.lock().clone();
                                let cur_amt = invoice_amts.get(&pay_hash.to_string()).unwrap();
                                if Amount::msat(&invoice.amount_msat.unwrap())
                                    > cur_amt - amount_msat
                                {
                                    datastore_update_state(
                                        &rpc_path,
                                        pay_hash.to_string(),
                                        Hodlstate::Open.to_string(),
                                    )
                                    .await?;
                                }
                                *plugin
                                    .state()
                                    .invoice_amts
                                    .lock()
                                    .get_mut(&pay_hash.to_string())
                                    .unwrap() -= amount_msat;
                                return Ok(json!({"result": "fail"}));
                            }

                            match hodlstate {
                                Hodlstate::Open => {
                                    if Amount::msat(&invoice.amount_msat.unwrap())
                                        <= *plugin
                                            .state()
                                            .invoice_amts
                                            .lock()
                                            .get(&pay_hash.to_string())
                                            .unwrap()
                                    {
                                        datastore_update_state(
                                            &rpc_path,
                                            pay_hash.to_string(),
                                            Hodlstate::Accepted.to_string(),
                                        )
                                        .await?;
                                        debug!(
                                            "htlc {}: invoice state: accepted, {}msats, payment_hash: {}",
                                            id, amount_msat, pay_hash
                                        );
                                    } else {
                                        debug!(
                                            "htlc {}: invoice state: open, {}msats, payment_hash: {}",
                                            id, amount_msat, pay_hash
                                        );
                                    }
                                }
                                Hodlstate::Accepted => {
                                    if Amount::msat(&invoice.amount_msat.unwrap())
                                        > *plugin
                                            .state()
                                            .invoice_amts
                                            .lock()
                                            .get(&pay_hash.to_string())
                                            .unwrap()
                                    {
                                        datastore_update_state(
                                            &rpc_path,
                                            pay_hash.to_string(),
                                            Hodlstate::Open.to_string(),
                                        )
                                        .await?;
                                        debug!(
                                            "htlc {}: invoice state: open, {}msats, payment_hash: {}",
                                            id, amount_msat, pay_hash
                                        );
                                    } else {
                                        debug!(
                                            "htlc {}: invoice state: accepted, {}msats, payment_hash: {}",
                                            id, amount_msat, pay_hash
                                        );
                                    }
                                }
                                Hodlstate::Settled => {
                                    debug!(
                                        "htlc {}: settling invoice, payment_hash: {}",
                                        id, pay_hash
                                    );
                                    return Ok(json!({"result": "continue"}));
                                }
                                Hodlstate::Canceled => {
                                    debug!(
                                        "htlc {}: canceling invoice, payment_hash: {}",
                                        id, pay_hash
                                    );
                                    return Ok(json!({"result": "fail"}));
                                }
                            }
                        }
                        Err(e) => {
                            debug!(
                                "{} not our invoice: payment_hash: {}",
                                e.to_string(),
                                pay_hash
                            );
                            return Ok(json!({"result": "continue"}));
                        }
                    }
                }
                time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Ok(json!({"result": "continue"}))
}

pub async fn block_added(plugin: Plugin<PluginState>, v: serde_json::Value) -> Result<(), Error> {
    match v.get("block") {
        Some(block) => match block.get("height") {
            Some(h) => *plugin.state().blockheight.lock() = h.as_u64().unwrap() as u32,
            None => return Err(anyhow!("could not find height for block")),
        },
        None => return Err(anyhow!("could not read block notification")),
    };
    Ok(())
}
