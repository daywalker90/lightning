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
    Hodlupdate, PluginState,
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
            debug!("payment_hash: `{}`. htlc_hook started!", pay_hash);
            let rpc_path = make_rpc_path(&plugin);

            let invoice;
            let cltv_delta;
            let cltv_expiry = match htlc.get("cltv_expiry") {
                Some(ce) => ce.as_u64().unwrap() as u32,
                None => {
                    warn!(
                        "payment_hash: `{}`. cltv_expiry not found! Rejecting htlc...",
                        pay_hash
                    );
                    return Ok(json!({"result": "fail"}));
                }
            };
            let amount_msat;
            let scid;
            let htlc_id;
            let hodlstate;
            {
                let mut states = plugin.state().states.lock().await;
                match states.get(&pay_hash.to_string()) {
                    Some(h) => {
                        debug!(
                            "payment_hash: `{}`. Htlc is for a known hodl-invoice! Processing...",
                            pay_hash
                        );
                        hodlstate = h.state;
                        invoice = plugin
                            .state()
                            .invoices
                            .lock()
                            .get(&pay_hash.to_string())
                            .unwrap()
                            .clone();
                    }
                    None => {
                        debug!(
                            "payment_hash: `{}`. Htlc for fresh invoice arrived. Checking if it's a hodl-invoice...",
                            pay_hash
                        );

                        match listdatastore_state(&rpc_path, pay_hash.to_string()).await {
                            Ok(s) => {
                                debug!(
                                    "payment_hash: `{}`. Htlc is indeed for a hodl-invoice! Processing...",
                                    pay_hash
                                );
                                hodlstate = Hodlstate::from_str(&s.string.unwrap())?;
                                let gen = if let Some(g) = s.generation { g } else { 0 };

                                datastore_htlc_expiry(
                                    &rpc_path,
                                    pay_hash.to_string(),
                                    cltv_expiry.to_string(),
                                )
                                .await?;

                                invoice = listinvoices(&rpc_path, None, Some(pay_hash.to_string()))
                                    .await?
                                    .invoices
                                    .first()
                                    .ok_or(anyhow!(
                                        "payment_hash: `{}`. Hodl-invoice not found!",
                                        pay_hash
                                    ))?
                                    .clone();
                                plugin
                                    .state()
                                    .invoices
                                    .lock()
                                    .insert(pay_hash.to_string(), invoice.clone());

                                states.insert(
                                    pay_hash.to_string(),
                                    Hodlupdate {
                                        state: hodlstate,
                                        generation: gen,
                                    },
                                );
                            }
                            Err(_e) => {
                                debug!(
                                    "payment_hash: `{}`. Not a hodl-invoice! Continue...",
                                    pay_hash
                                );
                                return Ok(json!({"result": "continue"}));
                            }
                        };
                    }
                }
            }
            debug!("payment_hash: `{}`. Init lock dropped", pay_hash);
            match hodlstate {
                Hodlstate::Canceled => {
                    info!(
                        "payment_hash: `{}`. Htlc arrived after hodl-cancellation was requested. Rejecting htlc...",
                        pay_hash
                    );
                    return Ok(json!({"result": "fail"}));
                }
                _ => (),
            }
            htlc_id = match htlc.get("id") {
                Some(ce) => ce.as_u64().unwrap(),
                None => {
                    warn!(
                        "payment_hash: `{}`. htlc id not found! Rejecting htlc...",
                        pay_hash
                    );
                    return Ok(json!({"result": "fail"}));
                }
            };
            scid = match htlc.get("short_channel_id") {
                Some(ce) => ce.as_str().unwrap(),
                None => {
                    warn!(
                        "payment_hash: `{}`. short_channel_id not found! Rejecting htlc...",
                        pay_hash
                    );
                    return Ok(json!({"result": "fail"}));
                }
            };
            cltv_delta = plugin.state().config.lock().clone().cltv_delta.1 as u32;

            amount_msat = match htlc.get("amount_msat") {
                Some(ce) =>
                // Amount::msat(&serde_json::from_str::<Amount>(ce).unwrap()), bugging trailing characters error
                {
                    // debug!("{:?}", htlc);
                    // let amt_str = ce.as_str().unwrap();
                    // amt_str[..amt_str.len() - 4].parse::<u64>().unwrap()
                    ce.as_u64().unwrap()
                }
                None => {
                    warn!(
                        "payment_hash: `{}` scid: `{}` htlc_id: {}: amount_msat not found! Rejecting htlc...",
                        pay_hash, scid, htlc_id
                    );
                    return Ok(json!({"result": "fail"}));
                }
            };
            {
                let mut invoice_amts = plugin.state().invoice_amts.lock();
                if let Some(amt) = invoice_amts.get_mut(&pay_hash.to_string()) {
                    *amt += amount_msat;
                } else {
                    invoice_amts.insert(pay_hash.to_string(), amount_msat);
                }
            }
            info!(
                "payment_hash: `{}` scid: `{}` htlc_id: `{}`. Holding {}msat",
                pay_hash,
                scid.to_string(),
                htlc_id,
                amount_msat
            );

            loop {
                {
                    let states = plugin.state().states.lock().await.clone();
                    match states.get(&pay_hash.to_string()) {
                        Some(datastore) => {
                            let hodlstate = datastore.state;
                            let generation = datastore.generation;
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();

                            if invoice.expires_at <= now + 60
                                && hodlstate.is_valid_transition(&Hodlstate::Canceled)
                            {
                                warn!(
                                    "payment_hash: `{}` scid: `{}` htlc: `{}`. Hodl-invoice expired! State=CANCELED",
                                    pay_hash, scid, htlc_id
                                );
                                match datastore_update_state(
                                    &rpc_path,
                                    pay_hash.to_string(),
                                    Hodlstate::Canceled.to_string(),
                                    generation,
                                )
                                .await
                                {
                                    Ok(_o) => (),
                                    Err(_e) => {
                                        time::sleep(Duration::from_secs(2)).await;
                                        continue;
                                    }
                                };
                                *plugin
                                    .state()
                                    .invoice_amts
                                    .lock()
                                    .get_mut(&pay_hash.to_string())
                                    .unwrap() -= amount_msat;
                                return Ok(json!({"result": "fail"}));
                            }

                            if cltv_expiry
                                <= plugin.state().blockheight.lock().clone() + cltv_delta + 6
                                && hodlstate.is_valid_transition(&Hodlstate::Open)
                            {
                                warn!(
                                    "payment_hash: `{}` scid: `{}` htlc: `{}`. HTLC timed out. Rejecting htlc...",
                                    pay_hash, scid, htlc_id
                                );
                                let invoice_amts = plugin.state().invoice_amts.lock().clone();
                                let cur_amt = invoice_amts.get(&pay_hash.to_string()).unwrap();
                                if Amount::msat(&invoice.amount_msat.unwrap())
                                    > cur_amt - amount_msat
                                    && hodlstate == Hodlstate::Accepted
                                {
                                    match datastore_update_state(
                                        &rpc_path,
                                        pay_hash.to_string(),
                                        Hodlstate::Open.to_string(),
                                        generation,
                                    )
                                    .await
                                    {
                                        Ok(_o) => (),
                                        Err(_e) => {
                                            time::sleep(Duration::from_secs(2)).await;
                                            continue;
                                        }
                                    };
                                    info!(
                                        "payment_hash: `{}` scid: `{}` htlc: `{}`. No longer enough msats for the hodl-invoice. State=OPEN",
                                        pay_hash, scid, htlc_id
                                    );
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
                                        && hodlstate.is_valid_transition(&Hodlstate::Accepted)
                                    {
                                        match datastore_update_state(
                                            &rpc_path,
                                            pay_hash.to_string(),
                                            Hodlstate::Accepted.to_string(),
                                            generation,
                                        )
                                        .await
                                        {
                                            Ok(_o) => (),
                                            Err(_e) => {
                                                time::sleep(Duration::from_secs(2)).await;
                                                continue;
                                            }
                                        };
                                        info!(
                                            "payment_hash: `{}` scid: `{}` htlc: `{}`. Got enough msats for the hodl-invoice. State=ACCEPTED",
                                            pay_hash, scid, htlc_id
                                        );
                                    } else {
                                        debug!(
                                            "payment_hash: `{}` scid: `{}` htlc: `{}`. Not enough msats for the hodl-invoice yet.",
                                            pay_hash, scid, htlc_id
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
                                        && hodlstate.is_valid_transition(&Hodlstate::Open)
                                    {
                                        match datastore_update_state(
                                            &rpc_path,
                                            pay_hash.to_string(),
                                            Hodlstate::Open.to_string(),
                                            generation,
                                        )
                                        .await
                                        {
                                            Ok(_o) => (),
                                            Err(_e) => {
                                                time::sleep(Duration::from_secs(2)).await;
                                                continue;
                                            }
                                        };
                                        info!(
                                            "payment_hash: `{}` scid: `{}` htlc: `{}`. No longer enough msats for the hodl-invoice. State=OPEN",
                                            pay_hash, scid, htlc_id
                                        );
                                    } else {
                                        debug!(
                                            "payment_hash: `{}` scid: `{}` htlc: `{}`. Holding accepted hodl-invoice.",
                                            pay_hash, scid, htlc_id
                                        );
                                    }
                                }
                                Hodlstate::Settled => {
                                    info!(
                                        "payment_hash: `{}` scid: `{}` htlc: `{}`. Settling htlc for hodl-invoice. State=SETTLED",
                                        pay_hash, scid, htlc_id
                                    );
                                    return Ok(json!({"result": "continue"}));
                                }
                                Hodlstate::Canceled => {
                                    info!(
                                        "payment_hash: `{}` scid: `{}` htlc: `{}`. Rejecting htlc for canceled hodl-invoice.  State=CANCELED",
                                        pay_hash, scid, htlc_id
                                    );
                                    return Ok(json!({"result": "fail"}));
                                }
                            }
                        }
                        None => {
                            warn!("payment_hash: `{}` scid: `{}` htlc: `{}`. DROPPED INVOICE from internal state!", pay_hash, scid, htlc_id);
                            return Err(anyhow!(
                                "Invoice dropped from internal state unexpectedly: {}",
                                pay_hash
                            ));
                        }
                    }
                }
                time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
    warn!("htlc_accepted hook could not find htlc object");
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
