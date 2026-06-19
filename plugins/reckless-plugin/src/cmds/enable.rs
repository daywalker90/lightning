use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::notifications::LogLevel;
use serde_json::json;

use crate::{
    structs::{
        EnableArgs, PluginState, RecklessLogger, RecklessPlugin, RecklessTopic, RpcResponse,
        RpcResult, TargetResponse,
    },
    util::{
        add_plugin_to_config, cln_list_plugins, cln_start_plugin, cln_stop_plugin, find_entryfile,
        get_plugin_manifest, parse_options, parse_target, read_reckless_manifest,
        remove_plugin_from_config, search_sources,
    },
};

pub async fn handle_enable(
    plugin: Plugin<PluginState>,
    enable_args: EnableArgs,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Enable, verbose);
    let mut result = RpcResult::new();

    let (plugin_name, git_ref) = match parse_target(&enable_args.target) {
        Ok((n, g)) => (n, g),
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

    if !rl_plugin.path().exists() {
        let line = format!("{plugin_name} is not installed");
        logger.log(&line, LogLevel::UNUSUAL).await?;
        return Err(anyhow!(line));
    }

    match enable_plugin(
        plugin.clone(),
        &plugin_name,
        rl_plugin,
        enable_args.options,
        &mut logger,
    )
    .await
    {
        Ok(()) => result.push(TargetResponse { plugin_name })?,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            return Err(e);
        }
    }

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

pub async fn enable_plugin(
    plugin: Plugin<PluginState>,
    plugin_name: &str,
    rl_plugin: &RecklessPlugin,
    options: Vec<(String, Option<String>)>,
    logger: &mut RecklessLogger<'_>,
) -> Result<(), anyhow::Error> {
    let plugin_entry = rl_plugin
        .path()
        .join(find_entryfile(rl_plugin.path(), plugin_name).await?);

    let entry_file = plugin_entry
        .file_name()
        .ok_or_else(|| anyhow!("plugin entry path has no last segment"))?
        .to_str()
        .ok_or_else(|| anyhow!("entry filename has invalid unicode"))?
        .to_owned();

    let plugin_manifest = get_plugin_manifest(&plugin_entry, logger).await?;
    logger
        .log(&format!("{plugin_manifest:#?}"), LogLevel::TRACE)
        .await?;

    let parsed_options = parse_options(&plugin_manifest, &options)?;

    let rl_manifest = read_reckless_manifest(rl_plugin.source_path()).await?;

    if let Some(req_opts) = rl_manifest.and_then(|rl_m| rl_m.required_options) {
        for option in req_opts {
            if !parsed_options.iter().any(|(o, _)| o == &option) {
                return Err(anyhow!("option `{option}` is required"));
            }
        }
    }

    let running_plugins = cln_list_plugins(plugin.clone(), logger).await?;
    if running_plugins.contains(&entry_file) {
        let line = format!("Plugin {plugin_name} is already running");
        logger.log(&line, LogLevel::INFO).await?;
    } else if !running_plugins.contains(&entry_file) && plugin_manifest.is_dynamic() {
        cln_start_plugin(plugin.clone(), plugin_name, &plugin_entry, options, logger).await?;
    } else if !plugin_manifest.is_dynamic() {
        let line = format!(
            "{plugin_name} is not dynamic and will be started the next time the node starts"
        );
        logger.log(&line, LogLevel::INFO).await?;
    }

    match add_plugin_to_config(
        plugin.clone(),
        plugin_entry,
        parsed_options,
        plugin_manifest,
    )
    .await
    {
        Ok(()) => {
            let line = format!("{plugin_name} enabled");
            logger.log(&line, LogLevel::INFO).await?;
        }
        Err(e) => {
            return Err(anyhow!("{plugin_name} failed to enable: {e}"));
        }
    }

    Ok(())
}

pub async fn handle_disable(
    plugin: Plugin<PluginState>,
    target: String,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Enable, verbose);
    let mut result = RpcResult::new();

    let (plugin_name, git_ref) = match parse_target(&target) {
        Ok((pn, g)) => (pn, g),
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

    match disable_plugin(plugin.clone(), &plugin_name, &mut logger).await {
        Ok(()) => result.push(TargetResponse { plugin_name })?,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(e);
        }
    }

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

pub async fn disable_plugin(
    plugin: Plugin<PluginState>,
    plugin_name: &str,
    logger: &mut RecklessLogger<'_>,
) -> Result<(), anyhow::Error> {
    let install_path = plugin.state().reckless_dir.join(plugin_name);
    let entry_file = find_entryfile(&install_path, plugin_name).await?;
    let entry_path = install_path.join(&entry_file);

    let manifest = get_plugin_manifest(&entry_path, logger).await?;
    logger
        .log(&format!("{manifest:#?}"), LogLevel::TRACE)
        .await?;

    let running_plugins = cln_list_plugins(plugin.clone(), logger).await?;
    if running_plugins.contains(&entry_file) {
        cln_stop_plugin(plugin.clone(), plugin_name, &entry_path, logger).await?;
    } else {
        let line = format!("{plugin_name} already stopped");
        logger.log(&line, LogLevel::INFO).await?;
    }

    remove_plugin_from_config(plugin.clone(), entry_path, manifest).await?;
    let line = format!("{plugin_name} disabled");
    logger.log(&line, LogLevel::INFO).await?;

    Ok(())
}
