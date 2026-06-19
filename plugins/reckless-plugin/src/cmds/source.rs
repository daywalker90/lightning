use std::{path::PathBuf, str::FromStr};

use anyhow::anyhow;
use cln_plugin::Plugin;
use cln_rpc::notifications::LogLevel;
use serde_json::json;
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use url::Url;

use crate::{
    structs::{PluginState, RecklessLogger, RecklessTopic, RpcResponse, RpcResult},
    util::{read_sources_file, repo_path_from_url, validate_path},
};

pub async fn handle_source_list(
    plugin: Plugin<PluginState>,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut result = RpcResult::new();
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Search, verbose);

    let (urls, paths, _source_file) = match read_sources_file(plugin.clone()).await {
        Ok(res) => res,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(e);
        }
    };

    for url in &urls {
        logger.log(url.as_ref(), LogLevel::INFO).await?;
    }
    for path in &paths {
        let line = format!("{}", path.display());
        logger.log(&line, LogLevel::INFO).await?;
    }

    let mut sources = Vec::new();
    sources.extend(urls.iter().map(url::Url::as_str).collect::<Vec<&str>>());
    sources.extend(
        paths
            .iter()
            .filter_map(|p| p.to_str())
            .collect::<Vec<&str>>(),
    );

    sources.sort_unstable();

    result.push(json!({"sources": sources}))?;

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

pub async fn handle_source_add(
    plugin: Plugin<PluginState>,
    target: String,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut result = RpcResult::new();
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Source, verbose);

    let (urls, paths, source_file) = match read_sources_file(plugin.clone()).await {
        Ok(res) => res,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(e);
        }
    };

    let mut file_handle = match OpenOptions::new().append(true).open(source_file).await {
        Ok(f) => f,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(anyhow!(e));
        }
    };

    let mut sources = Vec::new();
    let target_trimmed = target.trim();
    let url_result = Url::from_str(target_trimmed);
    let path_result = validate_path(target_trimmed);
    if let Ok(url) = url_result {
        if !urls.contains(&url) {
            if let Err(e) = file_handle
                .write_all(format!("{target_trimmed}\n").as_bytes())
                .await
            {
                logger.log(&e.to_string(), LogLevel::BROKEN).await?;
                return Err(anyhow!(e));
            }
            sources.push(target_trimmed.to_owned());
        }
    } else if let Ok(path) = path_result {
        if !paths.contains(&path) {
            if let Err(e) = file_handle
                .write_all(format!("{target_trimmed}\n").as_bytes())
                .await
            {
                logger.log(&e.to_string(), LogLevel::BROKEN).await?;
                return Err(anyhow!(e));
            }
            sources.push(target_trimmed.to_owned());
        }
    } else {
        let line = format!(
            "failed to add source {target_trimmed}, not a valid URL:{} or path:{}",
            url_result.err().unwrap(),
            path_result.err().unwrap()
        );
        logger.log(&line, LogLevel::UNUSUAL).await?;
        return Err(anyhow!(line));
    }

    for url in urls {
        sources.push(url.to_string());
    }
    for path in paths {
        sources.push(format!("{}", path.display()));
    }

    sources.sort();

    result.push(json!({"sources": sources}))?;

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

pub async fn handle_source_remove(
    plugin: Plugin<PluginState>,
    target: String,
    verbose: bool,
) -> Result<serde_json::Value, anyhow::Error> {
    let mut result = RpcResult::new();
    let mut logger = RecklessLogger::new(&plugin, RecklessTopic::Source, verbose);

    let (urls, paths, source_file) = match read_sources_file(plugin.clone()).await {
        Ok(res) => res,
        Err(e) => {
            logger.log(&e.to_string(), LogLevel::BROKEN).await?;
            return Err(e);
        }
    };

    let target_trimmed = target.trim();

    let (remove_urls, remove_paths) =
        match remove_source(&plugin, target_trimmed, &mut logger).await {
            Ok(res) => res,
            Err(e) => {
                logger.log(&e.to_string(), LogLevel::BROKEN).await?;
                return Err(e);
            }
        };

    let Ok(mut file_handle) = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&source_file)
        .await
    else {
        let line = format!("failed to open sources file: {}", source_file.display());
        logger.log(&line, LogLevel::BROKEN).await?;
        return Err(anyhow!(line));
    };

    let mut sources = Vec::new();

    for url in &urls {
        if !remove_urls.contains(url) {
            if let Err(e) = file_handle.write_all(format!("{url}\n").as_bytes()).await {
                logger.log(&e.to_string(), LogLevel::BROKEN).await?;
                return Err(anyhow!(e));
            }
            sources.push(url.to_string());
        }
    }
    for path in &paths {
        if !remove_paths.contains(path) {
            if let Err(e) = file_handle
                .write_all(format!("{}\n", path.to_str().unwrap()).as_bytes())
                .await
            {
                logger.log(&e.to_string(), LogLevel::BROKEN).await?;
                return Err(anyhow!(e));
            }
            sources.push(format!("{}", path.display()));
        }
    }

    sources.sort();

    result.push(json!({"sources": sources}))?;

    let response = RpcResponse::new(result, logger);

    Ok(json!(response))
}

async fn remove_source(
    plugin: &Plugin<PluginState>,
    target: &str,
    logger: &mut RecklessLogger<'_>,
) -> Result<(Vec<Url>, Vec<PathBuf>), anyhow::Error> {
    let mut remove_urls: Vec<Url> = Vec::new();
    let mut remove_paths: Vec<PathBuf> = Vec::new();

    let url_result = Url::from_str(target);
    let path_result = validate_path(target);
    if let Ok(url) = url_result {
        let repo_path = plugin.state().reckless_dir.join(repo_path_from_url(&url)?);
        match fs::remove_dir_all(&repo_path).await {
            Ok(()) => {
                let line = format!("source directory removed: {}", repo_path.display());
                logger.log(&line, LogLevel::INFO).await?;
                remove_urls.push(url);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let line = format!("source directory never existed: {}", repo_path.display());
                logger.log(&line, LogLevel::INFO).await?;
                remove_urls.push(url);
            }
            Err(e) => {
                let line = format!(
                    "failed to remove source directory: {}: {}",
                    repo_path.display(),
                    e
                );
                logger.log(&line, LogLevel::UNUSUAL).await?;
            }
        }

        match fs::read_dir(&repo_path).await {
            Ok(mut entries) => {
                if entries.next_entry().await?.is_none() {
                    fs::remove_dir_all(
                        repo_path
                            .parent()
                            .ok_or_else(|| anyhow!("source repo has no owner directory"))?,
                    )
                    .await?;
                }
            }
            Err(e) => {
                logger
                    .log(
                        &format!(
                            "failed to read source directory: {} {e}",
                            repo_path.display()
                        ),
                        LogLevel::BROKEN,
                    )
                    .await?;
            }
        }
    } else if let Ok(path) = path_result {
        let line = format!("plugin source removed: {target}");
        logger.log(&line, LogLevel::INFO).await?;
        remove_paths.push(path);
    } else {
        let line = format!(
            "failed to remove source {target}, not a valid URL:{} or path:{}",
            url_result.err().unwrap(),
            path_result.err().unwrap()
        );
        logger.log(&line, LogLevel::UNUSUAL).await?;
    }

    Ok((remove_urls, remove_paths))
}
