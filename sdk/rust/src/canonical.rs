use std::fmt::Write;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn canonicalize_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let canonical = canonicalize_value(&value)?;
    Ok(canonical.into_bytes())
}

pub fn sha256_hex<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = canonicalize_bytes(value)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{:x}", digest))
}

fn canonicalize_value(value: &Value) -> Result<String, String> {
    let mut output = String::new();
    write_canonical_json(&mut output, value)?;
    Ok(output)
}

fn write_canonical_json(output: &mut String, value: &Value) -> Result<(), String> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(flag) => {
            if *flag {
                output.push_str("true");
            } else {
                output.push_str("false");
            }
        }
        Value::String(text) => {
            let encoded = serde_json::to_string(text).map_err(|error| error.to_string())?;
            output.push_str(&encoded);
        }
        Value::Number(number) => {
            if let Some(signed) = number.as_i64() {
                write!(output, "{signed}").map_err(|error| error.to_string())?;
            } else if let Some(unsigned) = number.as_u64() {
                write!(output, "{unsigned}").map_err(|error| error.to_string())?;
            } else {
                return Err(
                    "floating-point values are not supported in canonical action hashing"
                        .to_string(),
                );
            }
        }
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(output, item)?;
            }
            output.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();

            output.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                let encoded = serde_json::to_string(*key).map_err(|error| error.to_string())?;
                output.push_str(&encoded);
                output.push(':');
                write_canonical_json(output, &map[*key])?;
            }
            output.push('}');
        }
    }

    Ok(())
}
