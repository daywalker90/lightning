use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Error};
use cln_grpc::{datastore_htlc_expiry, datastore_update_state, listdatastore_state, Hodlstate};
use cln_plugin::Plugin;
use cln_rpc::primitives::Amount;
use log::{debug, info, warn};
use rand::{rngs::StdRng, RngCore, SeedableRng};
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
    // let mut rng = StdRng::from_entropy();
    // let mut buffer = [0; 8];
    // rng.fill_bytes(&mut buffer);
    // let random_number = u64::from_le_bytes(buffer);
    // time::sleep(Duration::from_secs(random_number)).await;
    // return Ok(json!({"result": "fail"}));
    if let Some(htlc) = v.get("htlc") {
        if let Some(pay_hash) = htlc
            .get("payment_hash")
            .and_then(|pay_hash| pay_hash.as_str())
        {
            info!("htlc_hook started for {}", pay_hash);
            let rpc_path = make_rpc_path(&plugin);

            let invoice;
            let cltv_delta;
            let cltv_expiry;
            let amount_msat;
            let id;
            match listdatastore_state(&rpc_path, pay_hash.to_string()).await {
                Ok(h) => {
                    let hodlstate = Hodlstate::from_str(&h.string.unwrap())?;
                    match hodlstate {
                        Hodlstate::Canceled => return Ok(json!({"result": "fail"})),
                        _ => (),
                    }
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
                    let mut states = plugin.state().states.lock().await;
                    match listdatastore_state(&rpc_path, pay_hash.to_string()).await {
                        Ok(datastore) => {
                            states.insert(
                                pay_hash.to_string(),
                                if let Some(g) = datastore.generation {
                                    g
                                } else {
                                    0
                                },
                            );
                            let hodlstate = Hodlstate::from_str(&datastore.string.unwrap())?;
                            // match hodlstate {
                            //     Hodlstate::Canceled | Hodlstate::Settled => {
                            //         states.insert(pay_hash.to_string(), hodlstate.clone());
                            //         cur_state = hodlstate;
                            //     }
                            //     _ => cur_state = states.get(&pay_hash.to_string()).unwrap().clone(),
                            // }
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            if invoice.expires_at <= now - 20 {
                                warn!(
                                    "htlc {}: hodlinvoice with payment_hash: {} expired, rejecting!",
                                    id,pay_hash
                                );
                                match datastore_update_state(
                                    &rpc_path,
                                    pay_hash.to_string(),
                                    Hodlstate::Canceled.to_string(),
                                    *states.get(&pay_hash.to_string()).unwrap(),
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

                            // match hodlstate {
                            //     Hodlstate::Accepted => {
                            //         let invoice_amts = plugin.state().invoice_amts.lock().clone();
                            //         let cur_amt = invoice_amts.get(&pay_hash.to_string()).unwrap();
                            //         if Amount::msat(&invoice.amount_msat.unwrap())
                            //             > cur_amt - amount_msat
                            //         {
                            //             info("htlc: {} | we lost full value {} {}",id,invoice.amount_msat.unwrap(),)
                            //             match datastore_update_state(
                            //                 &rpc_path,
                            //                 pay_hash.to_string(),
                            //                 Hodlstate::Open.to_string(),
                            //                 *states.get(&pay_hash.to_string()).unwrap(),
                            //             )
                            //             .await
                            //             {
                            //                 Ok(_o) => (),
                            //                 Err(_e) => {
                            //                     time::sleep(Duration::from_secs(2)).await;
                            //                     continue;
                            //                 }
                            //             };
                            //         }
                            //     }
                            //     _ => (),
                            // };

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
                                    match datastore_update_state(
                                        &rpc_path,
                                        pay_hash.to_string(),
                                        Hodlstate::Open.to_string(),
                                        *states.get(&pay_hash.to_string()).unwrap(),
                                    )
                                    .await
                                    {
                                        Ok(_o) => (),
                                        Err(_e) => {
                                            time::sleep(Duration::from_secs(2)).await;
                                            continue;
                                        }
                                    };
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
                                        info!("htlc: {}: got enough for the invoice! ACCEPT", id);
                                        match datastore_update_state(
                                            &rpc_path,
                                            pay_hash.to_string(),
                                            Hodlstate::Accepted.to_string(),
                                            *states.get(&pay_hash.to_string()).unwrap(),
                                        )
                                        .await
                                        {
                                            Ok(_o) => (),
                                            Err(_e) => {
                                                time::sleep(Duration::from_secs(2)).await;
                                                continue;
                                            }
                                        };
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
                                        info!(
                                            "htlc: {}: no longer enough for the invoice! OPEN",
                                            id
                                        );
                                        match datastore_update_state(
                                            &rpc_path,
                                            pay_hash.to_string(),
                                            Hodlstate::Open.to_string(),
                                            *states.get(&pay_hash.to_string()).unwrap(),
                                        )
                                        .await
                                        {
                                            Ok(_o) => (),
                                            Err(_e) => {
                                                time::sleep(Duration::from_secs(2)).await;
                                                continue;
                                            }
                                        };
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
                                    info!(
                                        "htlc {}: settling invoice, payment_hash: {}",
                                        id, pay_hash
                                    );
                                    return Ok(json!({"result": "continue"}));
                                }
                                Hodlstate::Canceled => {
                                    info!(
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
