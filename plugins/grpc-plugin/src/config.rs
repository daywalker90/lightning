use anyhow::{anyhow, Error};
use cln_plugin::ConfiguredPlugin;
use log::warn;
use std::path::Path;

use tokio::fs;

use crate::PluginState;

#[derive(Clone, Debug)]
pub struct Config {
    pub cltv_delta: (String, u16),
}
impl Config {
    pub fn new() -> Config {
        Config {
            cltv_delta: ("cltv-delta".to_string(), 40),
        }
    }
}

pub async fn read_config(
    plugin: &ConfiguredPlugin<PluginState, tokio::io::Stdin, tokio::io::Stdout>,
    state: PluginState,
) -> Result<(), Error> {
    let mut configfile = String::new();
    let dir = plugin.clone().configuration().lightning_dir;
    match fs::read_to_string(Path::new(&dir).join("config")).await {
        Ok(file) => configfile = file,
        Err(_) => {
            match fs::read_to_string(Path::new(&dir).parent().unwrap().join("config")).await {
                Ok(file2) => configfile = file2,
                Err(_) => warn!("No config file found!"),
            }
        }
    }
    let mut config = state.config.lock();
    for line in configfile.lines() {
        if line.contains('=') {
            let splitline = line.split('=').collect::<Vec<&str>>();
            if splitline.len() == 2 {
                let name = splitline.clone().into_iter().nth(0).unwrap();
                let value = splitline.into_iter().nth(1).unwrap();

                match name {
                    opt if opt.eq(&config.cltv_delta.0) => match value.parse::<u16>() {
                        Ok(n) => config.cltv_delta.1 = n,
                        Err(e) => {
                            return Err(anyhow!(
                                "Error: Could not parse a number from `{}` for {}: {}",
                                value,
                                config.cltv_delta.0,
                                e
                            ))
                        }
                    },
                    _ => (),
                }
            }
        }
    }

    Ok(())
}
