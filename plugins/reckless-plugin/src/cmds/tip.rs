use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::{model::requests::XpayRequest, notifications::LogLevel, primitives::Amount};
use serde_json::json;

use crate::{
    structs::{PluginState, RecklessLogger, RecklessTopic, RpcResponse, RpcResult, TipArgs},
    util::{parse_target, read_reckless_manifest, search_sources},
};

pub async fn handle_tip(
    plugin: Plugin<PluginState>,
    args: TipArgs,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut result = RpcResult::new();
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Tip, verbose);

    let (plugin_name, git_ref) = match parse_target(&args.target) {
        Ok(res) => res,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    };
    if git_ref.is_some() {
        let line = "git refs are not supported here";
        logger.log(line, LogLevel::UNUSUAL).await?;
        return Err(anyhow!(line));
    }

    let mut search_results =
        match search_sources(plugin.clone(), Some(plugin_name.clone()), &mut logger).await {
            Ok(s) => s,
            Err(e) => {
                logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
                return Err(e);
            }
        };
    let Some(rl_plugin) = search_results.get_mut(&plugin_name) else {
        let line = format!("{plugin_name} not found in any known sources");
        logger.log(&line, LogLevel::UNUSUAL).await?;
        return Err(anyhow!(line));
    };

    let reckless_manifest = match read_reckless_manifest(rl_plugin.source_path()).await {
        Ok(res) => res,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(e);
        }
    };

    let Some(rm) = reckless_manifest else {
        return Err(anyhow!("no reckless manifest found for {plugin_name}"));
    };

    let Some(offer) = rm.offer else {
        return Err(anyhow!(
            "no offer found in reckless manifest for {plugin_name}"
        ));
    };

    let line = format!(
        "Sending {}msat to {plugin_name} author...",
        args.amount_msat
    );
    logger.log(&line, LogLevel::INFO).await?;

    let mut rpc = plugin.state().rpc.lock().await;
    let xpay = match rpc
        .call_typed(&XpayRequest {
            amount_msat: Some(Amount::from_msat(args.amount_msat)),
            dev_use_shadow: None,
            label: None,
            localinvreqid: None,
            maxdelay: None,
            maxfee: None,
            partial_msat: None,
            payer_note: args.payer_note,
            retry_for: None,
            layers: None,
            invstring: offer,
        })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            let line = format!(
                "Error sending {}msat to {plugin_name} author: {e}",
                args.amount_msat
            );
            logger.log(&line, LogLevel::UNUSUAL).await?;
            return Err(anyhow!(line));
        }
    };

    let line = format!(
        "Successfully sent {}msat to {plugin_name} author!",
        args.amount_msat
    );
    logger.log(&line, LogLevel::INFO).await?;

    result.push(xpay)?;

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}
