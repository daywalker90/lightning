use cln_plugin::Plugin;
use cln_rpc::{
    model::responses::{CheckruneResponse, ShowrunesResponse},
    ClnRpc, RpcError,
};
use serde_json::json;

use crate::{handlers::AppError, PluginState};

pub async fn verify_rune(
    plugin: Plugin<PluginState>,
    rune_header: Option<String>,
    rpc_method: &str,
    rpc_params: &serde_json::Value,
) -> Result<(), AppError> {
    let rune = match rune_header {
        Some(rune) => rune,
        None => {
            let err = RpcError {
                code: Some(1501),
                data: None,
                message: "Not authorized: Missing rune".to_string(),
            };
            log::info!("{}", err);
            return Err(AppError::Forbidden(err));
        }
    };

    let checkrune_result = match call_rpc(
        plugin.clone(),
        "checkrune",
        json!({"rune": rune, "method": rpc_method, "params": rpc_params}),
    )
    .await
    {
        Ok(o) => serde_json::from_value::<CheckruneResponse>(o).unwrap(),
        Err(e) => {
            log::info!("{}", e);
            return Err(AppError::Unauthorized(e));
        }
    };

    if !checkrune_result.valid {
        let err = RpcError {
            code: Some(1502),
            message: "Rune is not valid".to_string(),
            data: None,
        };
        log::info!("{}", err);
        return Err(AppError::Unauthorized(err));
    }

    let showrunes_result = match call_rpc(plugin, "showrunes", json!({"rune": rune})).await {
        Ok(r) => serde_json::from_value::<ShowrunesResponse>(r).unwrap(),
        Err(e) => return Err(AppError::InternalServerError(e)),
    };

    let rune_id = match showrunes_result.runes.first() {
        Some(r) => &r.unique_id,
        None => {
            return Err(AppError::InternalServerError(RpcError {
                code: Some(-32603),
                message: format!(
                    "Rune that tried to access method:`{}` with params:`{}` \
                got deleted while checking!",
                    rpc_method, rpc_params
                ),
                data: None,
            }))
        }
    };

    log::info!(
        "Authorized rune_id:`{}` access to method:`{}` with params:`{}`",
        rune_id,
        rpc_method,
        rpc_params
    );

    Ok(())
}

pub async fn call_rpc(
    plugin: Plugin<PluginState>,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, RpcError> {
    let rpc_path = plugin.configuration().rpc_file;
    let mut rpc = ClnRpc::new(rpc_path).await.map_err(|e| RpcError {
        code: None,
        data: None,
        message: e.to_string(),
    })?;
    rpc.call_raw(method, &params).await
}

pub fn filter_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(arr) => {
            for v in arr {
                filter_json(v);
            }
        }
        serde_json::Value::Object(obj) => {
            obj.retain(|k, v| !is_unwanted(k, v));
            for v in obj.values_mut() {
                filter_json(v);
            }
        }
        _ => (),
    }
}

fn is_unwanted(key: &String, value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => {
            log::debug!("is_unwanted: key:{} value:{} (null)", key, value);
            true
        }
        _ => false,
    }
}
