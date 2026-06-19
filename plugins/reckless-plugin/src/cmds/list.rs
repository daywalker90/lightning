use std::collections::HashMap;

use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::notifications::LogLevel;
use serde_json::{Map, Value, json};
use tokio::fs;

use crate::{
    structs::{Metadata, PluginState, RecklessLogger, RecklessTopic, RpcResponse, RpcResult},
    util::{read_metadata, read_reckless_manifest, search_sources},
};

pub async fn handle_list_available(
    plugin: Plugin<PluginState>,
    target: Option<String>,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Search, verbose);
    let mut result = RpcResult::new();

    let reckless_plugins = match search_sources(plugin.clone(), target, &mut logger).await {
        Ok(o) => o,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    };

    for (plugin_name, plugin) in reckless_plugins {
        let mut entry = Map::new();
        let reckless_manifests = read_reckless_manifest(plugin.source_path()).await?;
        entry.insert("name".to_owned(), json!(plugin_name));
        let Ok(Value::Object(plugin_json)) = serde_json::to_value(&plugin) else {
            let line = format!("failed to serialize plugin {plugin_name}");
            logger.log(&line, LogLevel::BROKEN).await?;
            return Err(anyhow!(line));
        };
        entry.extend(plugin_json);

        if let Some(manifest) = reckless_manifests {
            let Ok(Value::Object(m)) = serde_json::to_value(&manifest) else {
                let line = format!("failed to serialize manifest for {plugin_name}");
                logger.log(&line, LogLevel::BROKEN).await?;
                return Err(anyhow!(line));
            };
            entry.extend(m);
        }
        result.push(entry)?;
    }

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

pub async fn handle_list_installed(
    plugin: Plugin<PluginState>,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Search, verbose);
    let mut result = RpcResult::new();

    let installed = match list_installed(plugin.clone()).await {
        Ok(i) => i,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            HashMap::new()
        }
    };

    for (plugin_name, metadata) in installed {
        let mut entry = Map::new();
        entry.insert("plugin_name".to_owned(), json!(plugin_name));
        let Ok(Value::Object(plugin_json)) = serde_json::to_value(&metadata) else {
            return Err(anyhow!(
                "failed to serialize {plugin_name}'s metadata: {metadata:?}",
            ));
        };
        entry.extend(plugin_json);
        result.push(entry)?;
    }

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

pub async fn list_installed(
    plugin: Plugin<PluginState>,
) -> Result<HashMap<String, Metadata>, anyhow::Error> {
    let mut result: HashMap<String, Metadata> = HashMap::new();
    let mut entries = fs::read_dir(&plugin.state().reckless_dir).await?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let Ok(file_type) = entry.file_type().await else {
            continue;
        };
        if file_type.is_file() {
            continue;
        }
        if let Ok(metadata) = read_metadata(&entry.path()).await {
            result.insert(entry.file_name().to_string_lossy().to_string(), metadata);
        }
    }

    Ok(result)
}
