use anyhow::{Context, Result};
use nvd_cvss::{v2, v3, v4};
use std::collections::HashMap;
use std::str::FromStr;
use wasm_minimal_protocol::*;

initiate_protocol!();

#[wasm_func]
fn v2(input: &[u8]) -> Result<Vec<u8>> {
    let vector = std::str::from_utf8(input).context("failed to parse input as UTF-8")?;
    match v2::CVSS::from_str(vector) {
        Ok(cvss) => {
            let mut buffer = vec![];
            ciborium::ser::into_writer(&cvss, &mut buffer).context("failed to serialize result")?;
            Ok(buffer)
        }
        Err(e) => {
            let mut buffer = vec![];
            // serialize error the enum
            let mut error: HashMap<String, String> = HashMap::new();
            error.insert("error".to_string(), e.to_string());
            ciborium::ser::into_writer(&error, &mut buffer)
                .context("failed to serialize result")?;
            Ok(buffer)
        }
    }
}

#[wasm_func]
fn v3(input: &[u8]) -> Result<Vec<u8>> {
    let vector = std::str::from_utf8(input).context("failed to parse input as UTF-8")?;
    match v3::CVSS::from_str(vector) {
        Ok(cvss) => {
            let mut buffer = vec![];
            ciborium::ser::into_writer(&cvss, &mut buffer).context("failed to serialize result")?;
            Ok(buffer)
        }
        Err(e) => {
            let mut buffer = vec![];
            // serialize error the enum
            let mut error: HashMap<String, String> = HashMap::new();
            error.insert("error".to_string(), e.to_string());
            ciborium::ser::into_writer(&error, &mut buffer)
                .context("failed to serialize result")?;
            Ok(buffer)
        }
    }
}

#[wasm_func]
fn v4(input: &[u8]) -> Result<Vec<u8>> {
    let vector = std::str::from_utf8(input).context("failed to parse input as UTF-8")?;
    match v4::CVSS::from_str(vector) {
        Ok(cvss) => {
            let mut buffer = vec![];
            ciborium::ser::into_writer(&cvss, &mut buffer).context("failed to serialize result")?;
            Ok(buffer)
        }
        Err(e) => {
            let mut buffer = vec![];
            // serialize error the enum
            let mut error: HashMap<String, String> = HashMap::new();
            error.insert("error".to_string(), e.to_string());
            ciborium::ser::into_writer(&error, &mut buffer)
                .context("failed to serialize result")?;
            Ok(buffer)
        }
    }
}
