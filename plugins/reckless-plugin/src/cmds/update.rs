use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::notifications::LogLevel;
use serde_json::json;
use tokio::{fs, process::Command};

use crate::{
    cmds::list::list_installed,
    installers::{
        install_custom_plugin, install_go_plugin, install_nodejs_plugin, install_poetry_plugin,
        install_python_plugin, install_rust_plugin, install_uv_legacy_plugin, install_uv_plugin,
        install_uv_shebang_plugin,
    },
    structs::{
        Installer, PluginState, RecklessLogger, RecklessPlugin, RecklessTopic, RpcResponse,
        RpcResult, UpdateArgs,
    },
    util::{
        copy_dir_all, detect_installer, parse_target, read_metadata, run_logged_command,
        search_sources, write_metadata,
    },
};

pub async fn handle_update(
    plugin: Plugin<PluginState>,
    install_args: UpdateArgs,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut result = RpcResult::new();
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Install, verbose);

    let mut ignore_pinned = false;

    let targets = if let Some(target) = install_args.target {
        ignore_pinned = true;
        vec![target]
    } else {
        let listinstalled = match list_installed(plugin.clone()).await {
            Ok(o) => o,
            Err(e) => {
                logger.log(&e.to_string(), LogLevel::BROKEN).await?;
                return Err(e);
            }
        };
        let mut targets = Vec::new();
        for (name, _) in listinstalled {
            targets.push(name);
        }
        targets
    };

    for target in targets {
        let (plugin_name, git_ref) = match parse_target(&target) {
            Ok(o) => o,
            Err(e) => {
                logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
                return Err(e);
            }
        };
        let mut search_results =
            match search_sources(plugin.clone(), Some(plugin_name.clone()), &mut logger).await {
                Ok(o) => o,
                Err(e) => {
                    logger.log(&e.to_string(), LogLevel::BROKEN).await?;
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

        let update_result = update(
            &plugin_name,
            git_ref,
            rl_plugin,
            ignore_pinned,
            &mut logger,
            install_args.developer,
        )
        .await;
        match update_result {
            Ok(()) => {
                result.push(target)?;
            }
            Err(e) => {
                logger.log(&e.to_string(), LogLevel::UNUSUAL).await?;
            }
        }
    }

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

async fn update(
    plugin_name: &str,
    git_ref: Option<String>,
    rl_plugin: &mut RecklessPlugin,
    ignore_pinned: bool,
    logger: &mut RecklessLogger<'_>,
    developer: bool,
) -> Result<(), anyhow::Error> {
    let metadata = read_metadata(rl_plugin.path()).await?;

    if metadata.requested_commit.is_some() && !ignore_pinned {
        return Err(anyhow!("skipping update for pinned plugin: {plugin_name}"));
    }

    if !rl_plugin.origin_plugin_path().exists() {
        return Err(anyhow!(
            "repo does not exist: {}",
            rl_plugin.origin_repo_path().display()
        ));
    }

    if !rl_plugin.is_local_path() {
        let mut command = Command::new("git");
        command
            .args(["pull", "--ff-only"])
            .current_dir(rl_plugin.origin_repo_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["submodule", "sync", "--recursive"])
            .current_dir(rl_plugin.origin_repo_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["submodule", "update", "--init", "--recursive"])
            .current_dir(rl_plugin.origin_repo_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["checkout", git_ref.as_ref().unwrap_or(&"HEAD".to_owned())])
            .current_dir(rl_plugin.origin_plugin_path());
        run_logged_command(command, logger).await?;

        let mut command = Command::new("git");
        command
            .args(["rev-parse", "HEAD"])
            .current_dir(rl_plugin.origin_plugin_path());
        let commit_hash = run_logged_command(command, logger).await?;

        let ref_to_be_installed = if let Some(gr) = &git_ref {
            gr.clone()
        } else {
            commit_hash
        };

        rl_plugin.set_installed_commit(ref_to_be_installed.clone());

        if metadata.installed_commit == ref_to_be_installed {
            let line =
                format!("{plugin_name} is already on the latest version: {ref_to_be_installed}");
            logger.log(&line, LogLevel::INFO).await?;
            return Ok(());
        }

        let line = format!(
            "updating {plugin_name} from {} to {ref_to_be_installed}",
            metadata.installed_commit
        );
        logger.log(&line, LogLevel::INFO).await?;

        fs::create_dir_all(rl_plugin.source_path()).await?;

        copy_dir_all(
            rl_plugin.origin_plugin_path(),
            rl_plugin.source_path(),
            logger,
        )
        .await?;
    }

    let installer = detect_installer(rl_plugin.source_path()).await?;

    let entrypoint = match installer {
        Installer::PythonUv => install_uv_plugin(plugin_name, rl_plugin, logger).await?,
        Installer::PythonUvShebang => {
            install_uv_shebang_plugin(plugin_name, rl_plugin, logger).await?
        }
        Installer::PythonUvLegacy => {
            install_uv_legacy_plugin(plugin_name, rl_plugin, logger).await?
        }
        Installer::PoetryVenv => install_poetry_plugin(plugin_name, rl_plugin, logger).await?,
        Installer::PyprojectViaPip | Installer::Python => {
            install_python_plugin(plugin_name, rl_plugin, logger).await?
        }
        Installer::Nodejs => install_nodejs_plugin(plugin_name, rl_plugin, logger).await?,
        Installer::Rust => install_rust_plugin(plugin_name, rl_plugin, logger, developer).await?,
        Installer::Go => install_go_plugin(plugin_name, rl_plugin, logger).await?,
        Installer::Custom => install_custom_plugin(plugin_name, rl_plugin, logger).await?,
    };

    write_metadata(rl_plugin).await?;

    let line = format!("plugin updated: {}", entrypoint.display());
    logger.log(&line, LogLevel::INFO).await?;

    Ok(())
}
