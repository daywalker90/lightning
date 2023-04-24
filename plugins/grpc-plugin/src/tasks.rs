use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Error;
use cln_grpc::{
    del_datastore_htlc_expiry, del_datastore_state, listdatastore_raw, listdatastore_state,
    Hodlstate, HODLVOICE_PLUGIN_NAME,
};
use cln_plugin::Plugin;
use cln_rpc::model::ListinvoicesInvoicesStatus;
use log::{debug, info, warn};
use tokio::time::{self, Instant};

use crate::{
    util::{listinvoices, make_rpc_path},
    Hodlupdate, PluginState,
};

pub async fn lookup_state(plugin: Plugin<PluginState>) -> Result<(), Error> {
    info!("Starting lookup_state");

    let rpc_path = make_rpc_path(&plugin);
    loop {
        let now = Instant::now();
        {
            let states = plugin.state().states.lock().await.clone();
            let mut map = BTreeMap::new();
            for (pay_hash, _update) in states.iter() {
                match listdatastore_state(&rpc_path, pay_hash.clone()).await {
                    Ok(s) => {
                        let hodlstate = Hodlstate::from_str(&s.string.unwrap())?;
                        let gen = if let Some(g) = s.generation { g } else { 0 };
                        map.insert(
                            pay_hash.clone(),
                            Hodlupdate {
                                state: hodlstate,
                                generation: gen,
                            },
                        );
                    }
                    Err(e) => warn!(
                        "Error getting state for pay_hash: {} {}",
                        pay_hash,
                        e.to_string()
                    ),
                };
            }
            let mut states = plugin.state().states.lock().await;
            for (pay_hash, update) in map.iter() {
                states.insert(pay_hash.clone(), update.clone());
            }
        }
        debug!("updated states in {}ms", now.elapsed().as_millis());
        time::sleep(Duration::from_secs(2)).await;
    }
}

pub async fn clean_up(plugin: Plugin<PluginState>) -> Result<(), Error> {
    time::sleep(Duration::from_secs(60)).await;
    info!("Starting clean_up");

    let rpc_path = make_rpc_path(&plugin);
    loop {
        let now = Instant::now();
        // {
        //     debug!(
        //         "states: {:?} invoices: {:?} invoice_amts: {:?}",
        //         plugin.state().states.lock().await,
        //         plugin.state().invoices.lock(),
        //         plugin.state().invoice_amts.lock()
        //     );
        // }
        {
            let unix_now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut node_invoices = listinvoices(&rpc_path, None, None).await?.invoices;
            node_invoices.retain(|inv| {
                inv.expires_at + 3_600 <= unix_now
                    && match inv.status {
                        ListinvoicesInvoicesStatus::PAID | ListinvoicesInvoicesStatus::EXPIRED => {
                            true
                        }
                        ListinvoicesInvoicesStatus::UNPAID => false,
                    }
            });
            let expired_payment_hashes: Vec<String> = node_invoices
                .iter()
                .map(|invoice| invoice.payment_hash.to_string())
                .collect();
            // debug!("expired payment_hashes: {:?}", expired_payment_hashes);
            let datastore =
                listdatastore_raw(&rpc_path, Some(vec![HODLVOICE_PLUGIN_NAME.to_string()]))
                    .await?
                    .datastore;
            for data in datastore {
                if expired_payment_hashes.contains(&data.key[1]) {
                    let _res = del_datastore_htlc_expiry(&rpc_path, data.key[1].clone()).await;
                    let _res2 = del_datastore_state(&rpc_path, data.key[1].clone()).await;
                }
            }

            plugin
                .state()
                .states
                .lock()
                .await
                .retain(|hash, _| !expired_payment_hashes.contains(hash));

            plugin
                .state()
                .invoice_amts
                .lock()
                .retain(|hash, _| !expired_payment_hashes.contains(hash));

            plugin
                .state()
                .invoices
                .lock()
                .retain(|hash, _| !expired_payment_hashes.contains(hash));
        }
        // {
        //     debug!(
        //         "states: {:?} invoices: {:?} invoice_amts: {:?}",
        //         plugin.state().states.lock().await,
        //         plugin.state().invoices.lock(),
        //         plugin.state().invoice_amts.lock()
        //     );
        // }
        info!("cleaned up in {}ms", now.elapsed().as_millis());
        time::sleep(Duration::from_secs(3_600)).await;
    }
}
