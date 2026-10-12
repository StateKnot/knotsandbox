//! Fixed Kubernetes 1.36.4 CSI Pod comparison, not a publication capability.
//! Inputs are ordinary comparison data. No I/O, clock, certification or Gate.
use super::vendor_profile::{VendorActiveImageExpectation, VendorWorkloadExpectation};
use crate::nodeguard::protocol::{NodeBinding, valid_sha256};
use chrono::DateTime;
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, net::IpAddr};
use uuid::Uuid;

const ALPHABET: &str = "bcdfghjklmnpqrstvwxz2456789";
const API_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
const ZONE: &str = "topology.kubernetes.io/zone";
const POOL: &str = "sandbox.platform/node-pool";
const PROFILE: &str = "sandbox.platform/runtime-profile-sha256";
const CONTROLLERS: [&str; 6] = [
    "csi-provisioner",
    "external-disk-provisioner",
    "external-disk-attacher",
    "external-disk-resizer",
    "external-csi-snapshotter",
    "external-snapshot-controller",
];
const NODE_CONTAINERS: [&str; 2] = ["csi-plugin", "disk-driver-registrar"];
fn fixed_image(container: &str) -> Option<&'static str> {
    match container {
        "csi-plugin" => Some(
            "registry.cn-hangzhou.aliyuncs.com/acs/csi-plugin@sha256:f3dde54782067d2441ed1c784db0432e25056d298536903a3067b026e32afbbf",
        ),
        "disk-driver-registrar" => Some(
            "registry.cn-hangzhou.aliyuncs.com/acs/csi-node-driver-registrar@sha256:2c20e8022f88c8fed7e32445b78d4c3b7c879fd0d62fdf3b9c07192258c5a8d9",
        ),
        "csi-provisioner" => Some(
            "registry.cn-hangzhou.aliyuncs.com/acs/csi-plugin@sha256:f3dde54782067d2441ed1c784db0432e25056d298536903a3067b026e32afbbf",
        ),
        "external-disk-provisioner" => Some(
            "registry.cn-hangzhou.aliyuncs.com/acs/csi-provisioner@sha256:29f5332e701b804125edc1cb74224a1bd5a26108ca3b0c068d105fba750b9de3",
        ),
        "external-disk-attacher" => Some(
            "registry.cn-hangzhou.aliyuncs.com/acs/csi-attacher@sha256:8e0bcdca8dadcc77b8aa9e7343cc560d36209cd5ad57a9ef2aea16ec10b0be60",
        ),
        "external-disk-resizer" => Some(
            "registry.cn-hangzhou.aliyuncs.com/acs/csi-resizer@sha256:bf16104be28052c8a81bb87939775e53268f21d0ff2264c5bb7355d1b48e3f35",
        ),
        "external-csi-snapshotter" => Some(
            "registry.cn-hangzhou.aliyuncs.com/acs/csi-snapshotter@sha256:d87d0e892c1c2298a48be0ea665e89f61cec53351eeb5c4b5426c97987de0ca2",
        ),
        "external-snapshot-controller" => Some(
            "registry.cn-hangzhou.aliyuncs.com/acs/snapshot-controller@sha256:30cce2576a3d943233632b3883fabd2cea6f608bb9bca3df605bc0ce7d221433",
        ),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CsiPodProjectionError {
    #[error("CSI Pod comparison input rejected")]
    Input,
    #[error("CSI Pod installation branch unsupported")]
    Unsupported,
    #[error("CSI Pod differs from complete approved template")]
    Drift,
}
type Result<T> = std::result::Result<T, CsiPodProjectionError>;
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(CsiPodProjectionError::Drift)
    }
}
fn input(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(CsiPodProjectionError::Input)
    }
}
fn supported(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(CsiPodProjectionError::Unsupported)
    }
}
fn hash(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| CsiPodProjectionError::Input)?,
    )))
}
fn obj(v: &Value) -> Result<&Map<String, Value>> {
    v.as_object().ok_or(CsiPodProjectionError::Input)
}
fn arr(v: &Value) -> Result<&Vec<Value>> {
    v.as_array().ok_or(CsiPodProjectionError::Input)
}
fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or(CsiPodProjectionError::Input)
}
fn integer(v: &Value) -> Result<i64> {
    v.as_i64().ok_or(CsiPodProjectionError::Input)
}
fn at<'a>(v: &'a Value, path: &str) -> Result<&'a Value> {
    v.pointer(path).ok_or(CsiPodProjectionError::Input)
}
fn string<'a>(v: &'a Value, path: &str) -> Result<&'a str> {
    text(at(v, path)?)
}
fn bookkeeping<'a>(v: &'a Value, map: &str, key: &str) -> Result<&'a str> {
    text(at(v, map)?.get(key).ok_or(CsiPodProjectionError::Input)?)
}
fn put(v: &mut Value, key: &str, value: Value) -> Result<()> {
    v.as_object_mut()
        .ok_or(CsiPodProjectionError::Input)?
        .insert(key.into(), value);
    Ok(())
}
fn uuid(v: &Value) -> Result<Uuid> {
    let s = text(v)?;
    let u = Uuid::parse_str(s).map_err(|_| CsiPodProjectionError::Input)?;
    input(!u.is_nil() && u.to_string() == s)?;
    Ok(u)
}
fn name(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.split('.').all(|x| {
            !x.is_empty()
                && x.len() <= 63
                && x.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && x.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && x.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        })
}
fn alphabet(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| ALPHABET.as_bytes().contains(&b))
}
fn utc(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20
        || !s.ends_with('Z')
        || b.get(10) != Some(&b'T')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return false;
    }
    if ![&b[11..13], &b[14..16], &b[17..19]]
        .iter()
        .all(|x| x.iter().all(u8::is_ascii_digit))
        || &b[11..13] > b"23".as_slice()
        || &b[14..16] > b"59".as_slice()
        || &b[17..19] > b"59".as_slice()
    {
        return false;
    }
    if b.len() != 20
        && (b.len() < 22
            || b.len() > 30
            || b[19] != b'.'
            || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    DateTime::parse_from_rfc3339(s).is_ok()
}
fn empty(v: Option<&Value>) -> bool {
    v.is_none_or(|x| x.as_array().is_some_and(Vec::is_empty))
}
fn map_or_empty(v: Option<&Value>) -> Result<Value> {
    match v {
        None => Ok(json!({})),
        Some(x) => {
            obj(x)?;
            Ok(x.clone())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CsiPodPurpose {
    Controller,
    NodePlugin,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CsiPodPlacementExpected {
    zone_ids: [String; 3],
    selected_node: Option<NodeBinding>,
    selected_zone: Option<String>,
}
/// Strict eleven-key ordinary carrier; parsing it cannot authorize any operation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CsiPodProjectionInput {
    protocol: u32,
    purpose: CsiPodPurpose,
    workload_expectation: VendorWorkloadExpectation,
    active_images: Vec<VendorActiveImageExpectation>,
    workload: Value,
    service_account: Value,
    owner: Value,
    priority_class: Value,
    node: Value,
    placement: CsiPodPlacementExpected,
    pod: Value,
}
impl CsiPodProjectionInput {
    /// Future raw HTTP readers must call this BEFORE any ordinary Value parse;
    /// re-serializing an already lossy Value cannot recover duplicate wire keys.
    pub(crate) fn decode_api_object(raw: &[u8]) -> Result<Value> {
        input(raw.len() <= 1024 * 1024)?;
        let v: UniqueValue =
            serde_json::from_slice(raw).map_err(|_| CsiPodProjectionError::Input)?;
        bounds(&v.0, 0)?;
        obj(&v.0)?;
        Ok(v.0)
    }
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        input(raw.len() <= 8 * 1024 * 1024)?;
        let v: UniqueValue =
            serde_json::from_slice(raw).map_err(|_| CsiPodProjectionError::Input)?;
        Self::from_value(v.0)
    }
    /// Only ordinary expected/raw data. No trusted DTO or publication constructor.
    pub(crate) fn from_value(v: Value) -> Result<Self> {
        bounds(&v, 0)?;
        input(
            serde_json::to_vec(&v)
                .map_err(|_| CsiPodProjectionError::Input)?
                .len()
                <= 8 * 1024 * 1024,
        )?;
        let placement = obj(at(&v, "/placement")?)?;
        input(
            placement.len() == 3
                && ["zone_ids", "selected_node", "selected_zone"]
                    .iter()
                    .all(|k| placement.contains_key(*k)),
        )?;
        let m = obj(&v)?;
        input(m.len() == 11 && integer(at(&v, "/protocol")?)? == 1)?;
        for path in [
            "/workload_expectation/uid",
            "/workload_expectation/service_account_uid",
        ] {
            uuid(at(&v, path)?)?;
        }
        if let Some(n) = v
            .pointer("/placement/selected_node")
            .filter(|x| !x.is_null())
        {
            for k in ["cluster_epoch", "node_uid", "boot_id"] {
                uuid(n.get(k).ok_or(CsiPodProjectionError::Input)?)?;
            }
        }
        for k in [
            "workload",
            "service_account",
            "owner",
            "priority_class",
            "node",
            "pod",
        ] {
            input(
                serde_json::to_vec(m.get(k).ok_or(CsiPodProjectionError::Input)?)
                    .map_err(|_| CsiPodProjectionError::Input)?
                    .len()
                    <= 1024 * 1024,
            )?;
        }
        serde_json::from_value(v).map_err(|_| CsiPodProjectionError::Input)
    }
}
/// Protected pure comparison snapshot, not Verified/Certified/Gate or permission.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CsiPodProjection {
    facts: Value,
    pod_uid: Uuid,
    spec_sha256: String,
}
impl CsiPodProjection {
    pub(crate) fn same_runtime(&self, other: &Self) -> bool {
        self == other
    }
    pub(crate) fn pod_uid(&self) -> Uuid {
        self.pod_uid
    }
    pub(crate) fn spec_sha256(&self) -> &str {
        &self.spec_sha256
    }
}

// Raw API JSON must preserve unknown fields and reject duplicate keys before any
// typed carrier decoding. The existing canonical vault decoder is intentionally
// unsuitable here: live API JSON is not the ASCII canonical vault wire format.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Err(E::custom("noninteger JSON number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(json!(v)))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element::<UniqueValue>()? {
                    if out.len() >= 1024 {
                        return Err(de::Error::custom("array limit"));
                    }
                    out.push(v.0);
                }
                Ok(UniqueValue(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.len() >= 1024 || out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate key or map limit"));
                    }
                    let v = a.next_value::<UniqueValue>()?;
                    out.insert(k, v.0);
                }
                Ok(UniqueValue(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
fn bounds(v: &Value, depth: usize) -> Result<()> {
    input(depth <= 64)?;
    match v {
        Value::String(s) => input(s.len() <= 65536),
        Value::Number(n) => input(!n.is_f64()),
        Value::Array(a) => {
            input(a.len() <= 1024)?;
            for x in a {
                bounds(x, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(m) => {
            input(m.len() <= 1024)?;
            for (k, x) in m {
                input(k.len() <= 65536)?;
                bounds(x, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
// A data-driven CLOSED NAMED SHAPE table mechanically retains every validation
// field from the frozen official 1.36.4 definitions. It is not a general schema
// engine: envelope/IDs/limits/unions/runtime semantics are checked separately.
fn shape(v: &Value, s: &Value, defs: &Value, depth: usize) -> Result<()> {
    input(depth <= 64)?;
    if let Some(r) = s.get("$ref").and_then(Value::as_str) {
        let key = r
            .strip_prefix("#/definitions/")
            .ok_or(CsiPodProjectionError::Input)?;
        return shape(
            v,
            defs.get(key).ok_or(CsiPodProjectionError::Input)?,
            defs,
            depth + 1,
        );
    }
    if let Some(c) = s.get("const") {
        input(v == c)?;
    }
    let matches_type = |t: &str| match t {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "integer" => v.as_i64().is_some(),
        "null" => v.is_null(),
        _ => false,
    };
    if let Some(t) = s.get("type") {
        input(if let Some(t) = t.as_str() {
            matches_type(t)
        } else {
            arr(t)?.iter().filter_map(Value::as_str).any(matches_type)
        })?;
    }
    if let Some(fmt) = s.get("format").and_then(Value::as_str) {
        match fmt {
            "int32" => input(v.as_i64().is_some_and(|n| i32::try_from(n).is_ok()))?,
            "int64" => {
                integer(v)?;
            }
            "date-time" => input(v.is_null() || v.as_str().is_some_and(utc))?,
            "int-or-string" => {
                input(v.is_string() || v.as_i64().is_some_and(|n| i32::try_from(n).is_ok()))?
            }
            _ => return Err(CsiPodProjectionError::Input),
        }
    }
    if let Some(m) = v.as_object() {
        if let Some(required) = s.get("required") {
            for k in arr(required)? {
                input(m.contains_key(text(k)?))?;
            }
        }
        let properties = s.get("properties").and_then(Value::as_object);
        for (k, x) in m {
            if let Some(rule) = properties.and_then(|p| p.get(k)) {
                shape(x, rule, defs, depth + 1)?;
            } else {
                match s.get("additionalProperties") {
                    Some(Value::Bool(false)) => return Err(CsiPodProjectionError::Input),
                    Some(rule) if rule.is_object() => shape(x, rule, defs, depth + 1)?,
                    None => {}
                    _ => return Err(CsiPodProjectionError::Input),
                }
            }
        }
    }
    if let Some(a) = v.as_array() {
        let rule = s.get("items").ok_or(CsiPodProjectionError::Input)?;
        for x in a {
            shape(x, rule, defs, depth + 1)?;
        }
    }
    Ok(())
}
fn metadata(v: &Value, namespace: Option<&str>, generation: bool) -> Result<()> {
    let m = at(v, "/metadata")?;
    obj(m)?;
    uuid(at(m, "/uid")?)?;
    input(name(string(m, "/name")?, 253))?;
    let rv = string(m, "/resourceVersion")?;
    input(!rv.is_empty() && rv.len() <= 256 && rv.bytes().all(|b| (0x21..=0x7e).contains(&b)))?;
    input(utc(string(m, "/creationTimestamp")?))?;
    require(
        m.get("deletionTimestamp").is_none_or(Value::is_null)
            && !obj(m)?.contains_key("deletionGracePeriodSeconds"),
    )?;
    match namespace {
        Some(ns) => require(m.get("namespace") == Some(&json!(ns)))?,
        None => require(!obj(m)?.contains_key("namespace"))?,
    }
    if generation {
        input(integer(at(m, "/generation")?)? > 0)?;
    }
    for k in ["labels", "annotations"] {
        if let Some(x) = m.get(k) {
            input(
                serde_json::to_vec(x)
                    .map_err(|_| CsiPodProjectionError::Input)?
                    .len()
                    <= 65536,
            )?;
        }
    }
    if let Some(fields) = m.get("managedFields") {
        input(
            arr(fields)?.len() <= 64
                && serde_json::to_vec(fields)
                    .map_err(|_| CsiPodProjectionError::Input)?
                    .len()
                    <= 131072,
        )?;
        for f in arr(fields)? {
            input(
                matches!(string(f, "/operation")?, "Apply" | "Update")
                    && !string(f, "/manager")?.is_empty()
                    && string(f, "/manager")?.len() <= 128
                    && !string(f, "/apiVersion")?.is_empty()
                    && f.get("fieldsType") == Some(&json!("FieldsV1")),
            )?;
            if let Some(t) = f.get("time") {
                input(t.as_str().is_some_and(utc))?;
            }
            field_trie(at(f, "/fieldsV1")?, 0)?;
        }
    }
    Ok(())
}
fn field_trie(v: &Value, depth: usize) -> Result<()> {
    input(depth <= 64)?;
    for (k, x) in obj(v)? {
        let valid = k == "."
            || k.strip_prefix("f:").is_some_and(|s| !s.is_empty())
            || k.strip_prefix("i:")
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            || k.strip_prefix("k:").is_some_and(|s| {
                serde_json::from_str::<UniqueValue>(s).is_ok_and(|v| v.0.is_object())
            })
            || k.strip_prefix("v:")
                .is_some_and(|s| serde_json::from_str::<UniqueValue>(s).is_ok());
        input(valid && (k != "." || obj(x)?.is_empty()))?;
        field_trie(x, depth + 1)?;
    }
    Ok(())
}
fn owner_reference(kind: &str, name: &str, id: Uuid) -> Value {
    json!([{"apiVersion":"apps/v1","kind":kind,"name":name,"uid":id,"controller":true,"blockOwnerDeletion":true}])
}
fn metadata_maps(actual: &Value, template: &Value) -> Result<()> {
    for k in ["labels", "annotations"] {
        require(map_or_empty(actual.get(k))? == map_or_empty(template.get(k))?)?;
    }
    require(
        actual.get("finalizers") == template.get("finalizers")
            || (empty(actual.get("finalizers")) && empty(template.get("finalizers"))),
    )
}
fn ready_replicas(v: &Value) -> Result<()> {
    let generation = integer(at(v, "/metadata/generation")?)?;
    require(integer(at(v, "/status/observedGeneration")?)? == generation)?;
    for k in ["replicas", "readyReplicas", "availableReplicas"] {
        require(integer(at(v, &format!("/status/{k}"))?)? == 3)?;
    }
    require(
        v.pointer("/status/terminatingReplicas")
            .is_none_or(|v| v.as_i64() == Some(0)),
    )
}
fn controller_owner(i: &CsiPodProjectionInput) -> Result<(Value, Value)> {
    let w = &i.workload;
    let rs = &i.owner;
    metadata(rs, Some("kube-system"), true)?;
    require(
        rs.get("kind") == Some(&json!("ReplicaSet"))
            && rs.get("apiVersion") == Some(&json!("apps/v1")),
    )?;
    let rs_uid = uuid(at(rs, "/metadata/uid")?)?;
    require(
        at(rs, "/metadata/ownerReferences")?
            == &owner_reference("Deployment", "csi-provisioner", i.workload_expectation.uid),
    )?;
    let hash_label = string(rs, "/metadata/labels/pod-template-hash")?;
    input(alphabet(hash_label, 1, 10))?;
    let rs_name = format!("csi-provisioner-{hash_label}");
    require(string(rs, "/metadata/name")? == rs_name)?;
    let mut template = at(w, "/spec/template")?.clone();
    put(
        template
            .pointer_mut("/metadata/labels")
            .ok_or(CsiPodProjectionError::Input)?,
        "pod-template-hash",
        json!(hash_label),
    )?;
    let mut selector = at(w, "/spec/selector")?.clone();
    put(
        selector
            .pointer_mut("/matchLabels")
            .ok_or(CsiPodProjectionError::Input)?,
        "pod-template-hash",
        json!(hash_label),
    )?;
    let mut expected = json!({"replicas":3,"selector":selector,"template":template});
    if let Some(seconds) = w.pointer("/spec/minReadySeconds") {
        let n = integer(seconds)?;
        input(n >= 0)?;
        if n > 0 {
            put(&mut expected, "minReadySeconds", seconds.clone())?;
        }
    }
    require(
        at(rs, "/spec")? == &expected
            && at(rs, "/metadata/labels")? == at(&template, "/metadata/labels")?,
    )?;
    ready_replicas(w)?;
    ready_replicas(rs)?;
    require(
        integer(at(w, "/status/updatedReplicas")?)? == 3
            && w.pointer("/spec/paused").is_none_or(|x| x != &json!(true)),
    )?;
    let pmeta = at(&i.pod, "/metadata")?;
    require(
        pmeta.get("ownerReferences") == Some(&owner_reference("ReplicaSet", &rs_name, rs_uid)),
    )?;
    let prefix = format!("{rs_name}-");
    require(string(pmeta, "/generateName")? == prefix)?;
    require(
        string(pmeta, "/name")?
            .strip_prefix(&prefix)
            .is_some_and(|x| alphabet(x, 5, 5)),
    )?;
    metadata_maps(pmeta, at(&template, "/metadata")?)?;
    Ok((
        template,
        json!({"uid":rs_uid,"spec":hash(at(rs,"/spec")?)?}),
    ))
}
fn node_owner(i: &CsiPodProjectionInput) -> Result<(Value, Value)> {
    let ds = &i.workload;
    let cr = &i.owner;
    let pmeta = at(&i.pod, "/metadata")?;
    metadata(cr, Some("kube-system"), false)?;
    require(
        cr.get("kind") == Some(&json!("ControllerRevision"))
            && cr.get("apiVersion") == Some(&json!("apps/v1")),
    )?;
    let h = string(pmeta, "/labels/controller-revision-hash")?;
    input(alphabet(h, 1, 10))?;
    let cr_name = format!("csi-plugin-{h}");
    require(string(cr, "/metadata/name")? == cr_name && integer(at(cr, "/revision")?)? > 0)?;
    let reference = owner_reference("DaemonSet", "csi-plugin", i.workload_expectation.uid);
    require(
        at(cr, "/metadata/ownerReferences")? == &reference
            && pmeta.get("ownerReferences") == Some(&reference),
    )?;
    let mut template = at(ds, "/spec/template")?.clone();
    let mut labels = at(&template, "/metadata/labels")?.clone();
    put(&mut labels, "controller-revision-hash", json!(h))?;
    require(at(cr, "/metadata/labels")? == &labels && pmeta.get("labels") == Some(&labels))?;
    require(
        map_or_empty(cr.pointer("/metadata/annotations"))?
            == map_or_empty(ds.pointer("/metadata/annotations"))?,
    )?;
    let mut patch = template.clone();
    put(&mut patch, "$patch", json!("replace"))?;
    require(cr.get("data") == Some(&json!({"spec":{"template":patch}})))?;
    let prefix = "csi-plugin-";
    require(
        string(pmeta, "/generateName")? == prefix
            && string(pmeta, "/name")?
                .strip_prefix(prefix)
                .is_some_and(|x| alphabet(x, 5, 5)),
    )?;
    put(
        template
            .pointer_mut("/metadata/labels")
            .ok_or(CsiPodProjectionError::Input)?,
        "controller-revision-hash",
        json!(h),
    )?;
    metadata_maps(pmeta, at(&template, "/metadata")?)?;
    let generation = integer(at(ds, "/metadata/generation")?)?;
    require(integer(at(ds, "/status/observedGeneration")?)? == generation)?;
    let desired = integer(at(ds, "/status/desiredNumberScheduled")?)?;
    require(desired > 0)?;
    for k in [
        "currentNumberScheduled",
        "numberReady",
        "numberAvailable",
        "updatedNumberScheduled",
    ] {
        require(integer(at(ds, &format!("/status/{k}"))?)? == desired)?;
    }
    require(
        integer(at(ds, "/status/numberMisscheduled")?)? == 0
            && ds
                .pointer("/status/numberUnavailable")
                .is_none_or(|v| v.as_i64() == Some(0)),
    )?;
    Ok((
        template,
        json!({"uid":uuid(at(cr,"/metadata/uid")?)?,"data":hash(at(cr,"/data")?)?,"revision":integer(at(cr,"/revision")?)?}),
    ))
}
fn placement(i: &CsiPodProjectionInput) -> Result<Value> {
    let p = &i.placement;
    let n = &i.node;
    input(
        p.zone_ids.iter().all(|z| {
            name(z, 64)
                && z.starts_with("cn-")
                && z.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && z.split('-').count() >= 3
                && z.split('-').all(|x| !x.is_empty())
        }) && p.zone_ids.iter().collect::<BTreeSet<_>>().len() == 3,
    )?;
    metadata(n, None, false)?;
    require(n.get("kind") == Some(&json!("Node")) && n.get("apiVersion") == Some(&json!("v1")))?;
    let node_name = string(n, "/metadata/name")?;
    let node_uid = uuid(at(n, "/metadata/uid")?)?;
    let zone = bookkeeping(n, "/metadata/labels", ZONE)?;
    require(
        p.zone_ids.iter().any(|x| x == zone)
            && string(n, "/status/nodeInfo/architecture")? == "amd64"
            && string(n, "/status/nodeInfo/operatingSystem")? == "linux",
    )?;
    require(
        n.pointer("/spec/unschedulable")
            .is_none_or(|v| v != &json!(true)),
    )?;
    let ready = arr(at(n, "/status/conditions")?)?
        .iter()
        .filter(|c| c.get("type") == Some(&json!("Ready")))
        .collect::<Vec<_>>();
    require(ready.len() == 1 && ready[0].get("status") == Some(&json!("True")))?;
    let pool = bookkeeping(n, "/metadata/labels", POOL)?;
    match i.purpose {
        CsiPodPurpose::Controller => {
            require(pool == "platform" && p.selected_node.is_none() && p.selected_zone.is_none())?
        }
        CsiPodPurpose::NodePlugin => {
            let selected = p
                .selected_node
                .as_ref()
                .ok_or(CsiPodProjectionError::Input)?;
            input(
                !selected.cluster_epoch.is_nil()
                    && !selected.boot_id.is_nil()
                    && valid_sha256(&selected.profile_sha256),
            )?;
            require(
                matches!(pool, "kata" | "platform")
                    && p.selected_zone.as_deref() == Some(zone)
                    && selected.node_name == node_name
                    && selected.node_uid == node_uid
                    && uuid(at(n, "/status/nodeInfo/bootID")?)? == selected.boot_id
                    && bookkeeping(n, "/metadata/annotations", PROFILE)? == selected.profile_sha256,
            )?;
        }
    }
    require(string(&i.pod, "/spec/nodeName")? == node_name)?;
    Ok(
        json!({"name":node_name,"uid":node_uid,"boot":uuid(at(n,"/status/nodeInfo/bootID")?)?,"zone":zone,"pool":pool,"selected":p.selected_node}),
    )
}
fn approved_template(i: &CsiPodProjectionInput, template: &Value) -> Result<()> {
    let s = at(template, "/spec")?;
    let labels = match i.purpose {
        CsiPodPurpose::Controller => {
            json!({"app":"csi-provisioner","pod-template-hash":string(&i.owner,"/metadata/labels/pod-template-hash")?})
        }
        CsiPodPurpose::NodePlugin => {
            json!({"app":"csi-plugin","app.kubernetes.io/name":"csi-plugin","nodepool":"default","controller-revision-hash":string(&i.pod,"/metadata/labels/controller-revision-hash")?})
        }
    };
    require(at(template, "/metadata/labels")? == &labels)?;
    for k in [
        "initContainers",
        "ephemeralContainers",
        "resources",
        "schedulingGates",
        "readinessGates",
        "runtimeClassName",
        "overhead",
        "resourceClaims",
        "schedulingGroup",
    ] {
        supported(!obj(s)?.contains_key(k))?;
    }
    supported(
        !obj(s)?.contains_key("nodeName")
            && !obj(s)?.contains_key("priority")
            && !obj(s)?.contains_key("preemptionPolicy"),
    )?;
    require(
        string(s, "/dnsPolicy")? == "ClusterFirst"
            && string(s, "/restartPolicy")? == "Always"
            && string(s, "/schedulerName")? == "default-scheduler"
            && integer(at(s, "/terminationGracePeriodSeconds")?)? >= 0
            && s.get("securityContext").is_some_and(Value::is_object),
    )?;
    require(
        s.get("serviceAccountName") == Some(&json!(i.workload_expectation.service_account_name)),
    )?;
    if let Some(alias) = s.get("serviceAccount") {
        require(alias == at(s, "/serviceAccountName")?)?;
    }
    let containers = arr(at(s, "/containers")?)?;
    let names = match i.purpose {
        CsiPodPurpose::Controller => CONTROLLERS.as_slice(),
        CsiPodPurpose::NodePlugin => NODE_CONTAINERS.as_slice(),
    };
    require(containers.len() == names.len() && i.active_images.len() == names.len())?;
    let mut active = BTreeSet::new();
    for (c, n) in containers.iter().zip(names) {
        require(string(c, "/name")? == *n)?;
        supported(c.pointer("/securityContext/appArmorProfile").is_none())?;
        require(
            string(c, "/imagePullPolicy")? == "IfNotPresent"
                && string(c, "/terminationMessagePath")? == "/dev/termination-log"
                && string(c, "/terminationMessagePolicy")? == "File",
        )?;
        for port in c.get("ports").map(arr).transpose()?.into_iter().flatten() {
            supported(port.get("protocol") == Some(&json!("TCP")))?;
        }
        for key in ["livenessProbe", "readinessProbe", "startupProbe"] {
            if let Some(probe) = c.get(key) {
                for field in [
                    "timeoutSeconds",
                    "periodSeconds",
                    "successThreshold",
                    "failureThreshold",
                ] {
                    supported(
                        probe
                            .get(field)
                            .is_some_and(|v| v.as_i64().is_some_and(|n| n > 0)),
                    )?;
                }
                if let Some(http) = probe.get("httpGet") {
                    supported(http.get("scheme") == Some(&json!("HTTP")))?;
                }
            }
        }
        let request = at(c, "/resources/requests")?;
        let limit = at(c, "/resources/limits")?;
        require(
            obj(request)?.len() == 2
                && obj(limit)?.len() == 2
                && request.get("cpu").is_some_and(Value::is_string)
                && request.get("memory").is_some_and(Value::is_string)
                && limit.get("cpu").is_some_and(Value::is_string)
                && limit.get("memory").is_some_and(Value::is_string)
                && request != limit,
        )?;
        let a = i
            .active_images
            .iter()
            .find(|a| a.container_name == *n)
            .ok_or(CsiPodProjectionError::Drift)?;
        input(
            a.container_kind == "regular"
                && a.workload_name == i.workload_expectation.name
                && valid_sha256(&a.platform_descriptor_sha256)
                && !a.runtime_image_id.is_empty()
                && a.runtime_image_id.len() <= 1024
                && a.runtime_image_id
                    .bytes()
                    .all(|b| (0x21..=0x7e).contains(&b)),
        )?;
        require(
            a.image_ref == string(c, "/image")?
                && fixed_image(n) == Some(a.image_ref.as_str())
                && a.image_ref
                    .starts_with("registry.cn-hangzhou.aliyuncs.com/acs/")
                && a.image_ref
                    .split_once("@sha256:")
                    .is_some_and(|(_, h)| valid_sha256(h))
                && active.insert(&a.container_name),
        )?;
        for mount in c
            .get("volumeMounts")
            .map(arr)
            .transpose()?
            .into_iter()
            .flatten()
        {
            supported(mount.get("mountPath") != Some(&json!(API_PATH)))?;
        }
    }
    let cloud = arr(at(s, "/volumes")?)?
        .iter()
        .filter(|v| v.get("name") == Some(&json!("cloud-identity")))
        .collect::<Vec<_>>();
    let mode = match i.purpose {
        CsiPodPurpose::Controller => 288,
        CsiPodPurpose::NodePlugin => 256,
    };
    require(
        cloud.len() == 1
            && *cloud[0]
                == json!({"name":"cloud-identity","projected":{"defaultMode":mode,"sources":[{"serviceAccountToken":{"audience":"sts.aliyuncs.com","expirationSeconds":600,"path":"token"}}]}}),
    )?;
    for v in arr(at(s, "/volumes")?)? {
        supported(!string(v, "/name")?.starts_with("kube-api-access-"))?;
    }
    reject_feature_branches(s)?;
    let required = s
        .pointer("/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution")
        .ok_or(CsiPodProjectionError::Unsupported)?;
    let pool = match i.purpose {
        CsiPodPurpose::Controller => vec!["platform"],
        CsiPodPurpose::NodePlugin => vec!["kata", "platform"],
    };
    require(
        required
            == &json!({"nodeSelectorTerms":[{"matchExpressions":[{"key":POOL,"operator":"In","values":pool}]}]}),
    )?;
    match i.purpose {
        CsiPodPurpose::Controller => require(
            s.get("nodeSelector") == Some(&json!({POOL:"platform"}))
                && s.get("hostNetwork").is_none_or(|v| v == &json!(false)),
        )?,
        CsiPodPurpose::NodePlugin => require(
            !obj(s)?.contains_key("nodeSelector")
                && ["hostNetwork", "hostPID", "hostIPC"]
                    .iter()
                    .all(|k| s.get(*k) == Some(&json!(true))),
        )?,
    }
    Ok(())
}
fn reject_feature_branches(v: &Value) -> Result<()> {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                supported(!matches!(
                    k.as_str(),
                    "matchLabelKeys" | "mismatchLabelKeys" | "appArmorProfile"
                ))?;
                reject_feature_branches(x)?;
            }
        }
        Value::Array(a) => {
            for x in a {
                reject_feature_branches(x)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn reconstruct_spec(i: &CsiPodProjectionInput, template: &Value) -> Result<Value> {
    approved_template(i, template)?;
    let mut s = at(template, "/spec")?.clone();
    let sa = &i.service_account;
    metadata(sa, Some("kube-system"), false)?;
    require(
        empty(sa.pointer("/metadata/ownerReferences")) && empty(sa.pointer("/metadata/finalizers")),
    )?;
    require(
        string(sa, "/metadata/name")? == i.workload_expectation.service_account_name
            && uuid(at(sa, "/metadata/uid")?)? == i.workload_expectation.service_account_uid
            && empty(sa.get("secrets"))
            && empty(sa.get("imagePullSecrets")),
    )?;
    let automount = s
        .get("automountServiceAccountToken")
        .or_else(|| sa.get("automountServiceAccountToken"));
    require(automount.is_none_or(|v| v == &json!(true)))?;
    supported(empty(s.get("imagePullSecrets")))?;
    let pc = &i.priority_class;
    metadata(pc, None, false)?;
    require(
        empty(pc.pointer("/metadata/ownerReferences")) && empty(pc.pointer("/metadata/finalizers")),
    )?;
    let (pc_name, priority) = match i.purpose {
        CsiPodPurpose::Controller => ("system-cluster-critical", 2000000000_i64),
        CsiPodPurpose::NodePlugin => ("system-node-critical", 2000001000_i64),
    };
    require(
        string(pc, "/metadata/name")? == pc_name
            && s.get("priorityClassName") == Some(&json!(pc_name))
            && integer(at(pc, "/value")?)? == priority
            && pc.get("preemptionPolicy") == Some(&json!("PreemptLowerPriority"))
            && pc.get("globalDefault").is_none_or(|v| v == &json!(false)),
    )?;
    put(&mut s, "priority", json!(priority))?;
    put(&mut s, "preemptionPolicy", json!("PreemptLowerPriority"))?;
    put(
        &mut s,
        "serviceAccount",
        json!(i.workload_expectation.service_account_name),
    )?;
    put(
        &mut s,
        "nodeName",
        json!(string(&i.node, "/metadata/name")?),
    )?;
    if s.get("enableServiceLinks").is_none() {
        put(&mut s, "enableServiceLinks", json!(true))?;
    }
    let mut added = vec![
        json!({"key":"node.kubernetes.io/not-ready","operator":"Exists","effect":"NoExecute"}),
        json!({"key":"node.kubernetes.io/unreachable","operator":"Exists","effect":"NoExecute"}),
    ];
    match i.purpose {
        CsiPodPurpose::Controller => {
            for t in &mut added {
                put(t, "tolerationSeconds", json!(300))?;
            }
        }
        CsiPodPurpose::NodePlugin => {
            let required = s
                .pointer_mut(
                    "/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution",
                )
                .ok_or(CsiPodProjectionError::Input)?;
            *required = json!({"nodeSelectorTerms":[{"matchFields":[{"key":"metadata.name","operator":"In","values":[string(&i.node,"/metadata/name")?]}]}]});
            for k in [
                "disk-pressure",
                "memory-pressure",
                "pid-pressure",
                "unschedulable",
                "network-unavailable",
            ] {
                added.push(json!({"key":format!("node.kubernetes.io/{k}"),"operator":"Exists","effect":"NoSchedule"}));
            }
        }
    }
    let original = arr(at(&s, "/tolerations")?)?;
    let approved = match i.purpose {
        CsiPodPurpose::Controller => {
            json!([{"key":"node-role.kubernetes.io/master","operator":"Exists","effect":"NoSchedule"},{"key":"node-role.kubernetes.io/control-plane","operator":"Exists","effect":"NoSchedule"}])
        }
        CsiPodPurpose::NodePlugin => {
            json!([{"key":"sandbox.platform/untrusted","operator":"Equal","effect":"NoSchedule","value":"true"},{"key":"sandbox.platform/unverified","operator":"Equal","effect":"NoSchedule","value":"true"}])
        }
    };
    require(Value::Array(original.clone()) == approved)?;
    let mut tolerations = original.clone();
    tolerations.extend(added);
    put(&mut s, "tolerations", json!(tolerations))?;
    let pod_volumes = arr(at(&i.pod, "/spec/volumes")?)?;
    let approved_volumes = arr(at(&s, "/volumes")?)?;
    require(pod_volumes.len() == approved_volumes.len() + 1)?;
    let token = pod_volumes.last().ok_or(CsiPodProjectionError::Input)?;
    let token_name = string(token, "/name")?;
    input(
        token_name
            .strip_prefix("kube-api-access-")
            .is_some_and(|x| alphabet(x, 5, 5)),
    )?;
    let expected_token = json!({"name":token_name,"projected":{"defaultMode":420,"sources":[{"serviceAccountToken":{"expirationSeconds":3607,"path":"token"}},{"configMap":{"name":"kube-root-ca.crt","items":[{"key":"ca.crt","path":"ca.crt"}]}},{"downwardAPI":{"items":[{"path":"namespace","fieldRef":{"apiVersion":"v1","fieldPath":"metadata.namespace"}}]}}]}});
    require(token == &expected_token)?;
    let mut volumes = approved_volumes.clone();
    volumes.push(expected_token);
    put(&mut s, "volumes", json!(volumes))?;
    let host_network = s.get("hostNetwork") == Some(&json!(true));
    for c in s
        .get_mut("containers")
        .and_then(Value::as_array_mut)
        .ok_or(CsiPodProjectionError::Input)?
    {
        let m = c.as_object_mut().ok_or(CsiPodProjectionError::Input)?;
        let mounts = m
            .entry("volumeMounts")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or(CsiPodProjectionError::Input)?;
        mounts.push(json!({"name":token_name,"readOnly":true,"mountPath":API_PATH}));
        if host_network && let Some(ports) = m.get_mut("ports") {
            for p in ports.as_array_mut().ok_or(CsiPodProjectionError::Input)? {
                if p.get("hostPort").is_none_or(|v| v.as_i64() == Some(0)) {
                    let port = at(p, "/containerPort")?.clone();
                    put(p, "hostPort", port)?;
                }
            }
        }
    }
    Ok(s)
}
fn status(i: &CsiPodProjectionInput, spec: &Value) -> Result<Value> {
    let st = at(&i.pod, "/status")?;
    let generation = integer(at(&i.pod, "/metadata/generation")?)?;
    require(
        st.get("phase") == Some(&json!("Running"))
            && st.get("qosClass") == Some(&json!("Burstable")),
    )?;
    if let Some(g) = st.get("observedGeneration") {
        require(integer(g)? == generation)?;
    }
    for k in [
        "initContainerStatuses",
        "ephemeralContainerStatuses",
        "resourceClaimStatuses",
        "nodeAllocatableResourceClaimStatuses",
    ] {
        supported(empty(st.get(k)))?;
    }
    for k in [
        "resources",
        "allocatedResources",
        "extendedResourceClaimStatus",
        "resize",
    ] {
        supported(!obj(st)?.contains_key(k))?;
    }
    let mut conditions = BTreeSet::new();
    for c in arr(at(st, "/conditions")?)? {
        let t = string(c, "/type")?;
        require(
            matches!(
                t,
                "Ready"
                    | "ContainersReady"
                    | "Initialized"
                    | "PodScheduled"
                    | "PodReadyToStartContainers"
            ) && conditions.insert(t)
                && c.get("status") == Some(&json!("True")),
        )?;
        if let Some(g) = c.get("observedGeneration") {
            require(integer(g)? == generation)?;
        }
    }
    require(
        ["Ready", "ContainersReady", "Initialized", "PodScheduled"]
            .iter()
            .all(|k| conditions.contains(k)),
    )?;
    for k in ["podIP", "hostIP"] {
        if let Some(ip) = st.get(k) {
            input(text(ip)?.parse::<IpAddr>().is_ok())?;
        }
    }
    for k in ["podIPs", "hostIPs"] {
        if let Some(ips) = st.get(k) {
            for ip in arr(ips)? {
                input(string(ip, "/ip")?.parse::<IpAddr>().is_ok())?;
            }
        }
    }
    let containers = arr(at(spec, "/containers")?)?;
    let statuses = arr(at(st, "/containerStatuses")?)?;
    require(statuses.len() == containers.len())?;
    let mut seen = BTreeSet::new();
    let mut snapshots = Vec::new();
    for c in containers {
        let n = string(c, "/name")?;
        let active = i
            .active_images
            .iter()
            .find(|a| a.container_name == n)
            .ok_or(CsiPodProjectionError::Drift)?;
        let matches = statuses
            .iter()
            .filter(|x| x.get("name") == Some(&json!(n)))
            .collect::<Vec<_>>();
        require(matches.len() == 1 && seen.insert(n))?;
        let x = matches[0];
        require(
            x.get("ready") == Some(&json!(true))
                && x.get("started").is_none_or(|v| v == &json!(true))
                && integer(at(x, "/restartCount")?)? >= 0
                && string(x, "/imageID")? == active.runtime_image_id,
        )?;
        let state = at(x, "/state")?;
        require(obj(state)?.len() == 1 && state.get("running").is_some())?;
        input(utc(string(state, "/running/startedAt")?))?;
        for k in ["image", "containerID"] {
            let v = string(x, &format!("/{k}"))?;
            input(
                !v.is_empty() && v.len() <= 1024 && v.bytes().all(|b| (0x21..=0x7e).contains(&b)),
            )?;
        }
        if let Some(r) = x.get("resources") {
            require(r == at(c, "/resources")?)?;
        }
        if let Some(r) = x.get("allocatedResources") {
            require(r == at(c, "/resources/requests")?)?;
        }
        supported(
            empty(x.get("allocatedResourcesStatus"))
                && !obj(x)?.contains_key("stopSignal")
                && !obj(x)?.contains_key("user"),
        )?;
        if let Some(last) = x.get("lastState") {
            let m = obj(last)?;
            require(m.len() <= 1 && (m.is_empty() || m.contains_key("terminated")))?;
        }
        if let Some(mounts) = x.get("volumeMounts") {
            let expected = arr(at(c, "/volumeMounts")?)?;
            require(arr(mounts)?.len() == expected.len())?;
            let mut names = BTreeSet::new();
            for m in arr(mounts)? {
                let n = string(m, "/name")?;
                require(names.insert(n))?;
                let approved = expected
                    .iter()
                    .find(|x| x.get("name") == Some(&json!(n)))
                    .ok_or(CsiPodProjectionError::Drift)?;
                require(
                    m.get("mountPath") == approved.get("mountPath")
                        && m.get("readOnly").unwrap_or(&json!(false))
                            == approved.get("readOnly").unwrap_or(&json!(false)),
                )?;
                supported(
                    !obj(m)?.contains_key("recursiveReadOnly")
                        && !obj(m)?.contains_key("volumeStatus"),
                )?;
            }
        }
        snapshots.push(json!({"name":n,"containerID":x.get("containerID"),"image":x.get("image"),"imageID":x.get("imageID"),"restartCount":x.get("restartCount"),"running":state}));
    }
    Ok(json!(snapshots))
}
pub(crate) fn project_csi_pod(i: &CsiPodProjectionInput) -> Result<CsiPodProjection> {
    input(i.protocol == 1)?;
    let defs: Value = serde_json::from_str(include_str!("restore_csi_pod_shape.json"))
        .map_err(|_| CsiPodProjectionError::Input)?;
    let (kind, wname, saname, owner_kind) = match i.purpose {
        CsiPodPurpose::Controller => (
            "Deployment",
            "csi-provisioner",
            "sandbox-csi-controller",
            "ReplicaSet",
        ),
        CsiPodPurpose::NodePlugin => (
            "DaemonSet",
            "csi-plugin",
            "sandbox-csi-node",
            "ControllerRevision",
        ),
    };
    let expected = &i.workload_expectation;
    input(
        expected.kind == kind
            && expected.name == wname
            && expected.namespace == "kube-system"
            && expected.service_account_name == saname
            && !expected.uid.is_nil()
            && !expected.service_account_uid.is_nil()
            && valid_sha256(&expected.spec_sha256),
    )?;
    for (v, definition) in [
        (&i.workload, format!("io.k8s.api.apps.v1.{kind}")),
        (&i.owner, format!("io.k8s.api.apps.v1.{owner_kind}")),
        (
            &i.service_account,
            "io.k8s.api.core.v1.ServiceAccount".into(),
        ),
        (
            &i.priority_class,
            "io.k8s.api.scheduling.v1.PriorityClass".into(),
        ),
        (&i.node, "io.k8s.api.core.v1.Node".into()),
        (&i.pod, "io.k8s.api.core.v1.Pod".into()),
    ] {
        shape(
            v,
            defs.get(&definition).ok_or(CsiPodProjectionError::Input)?,
            &defs,
            0,
        )?;
    }
    metadata(&i.workload, Some("kube-system"), true)?;
    metadata(&i.pod, Some("kube-system"), true)?;
    require(
        string(&i.workload, "/metadata/name")? == wname
            && uuid(at(&i.workload, "/metadata/uid")?)? == expected.uid
            && hash(at(&i.workload, "/spec")?)? == expected.spec_sha256,
    )?;
    require(empty(i.workload.pointer("/metadata/ownerReferences")))?;
    let node = placement(i)?;
    let (template, owner) = match i.purpose {
        CsiPodPurpose::Controller => controller_owner(i)?,
        CsiPodPurpose::NodePlugin => node_owner(i)?,
    };
    let reconstructed = reconstruct_spec(i, &template)?;
    require(at(&i.pod, "/spec")? == &reconstructed)?;
    let containers = status(i, &reconstructed)?;
    let pod_uid = uuid(at(&i.pod, "/metadata/uid")?)?;
    let spec_sha256 = hash(&reconstructed)?;
    let facts = json!({"workloadUID":expected.uid,"workloadSpec":expected.spec_sha256,"owner":owner,"serviceAccountUID":expected.service_account_uid,"automount":i.service_account.get("automountServiceAccountToken"),"priorityClassUID":uuid(at(&i.priority_class,"/metadata/uid")?)?,"priority":i.priority_class.get("value"),"preemptionPolicy":i.priority_class.get("preemptionPolicy"),"node":node,"podUID":pod_uid,"podName":i.pod.pointer("/metadata/name"),"generation":i.pod.pointer("/metadata/generation"),"podSpec":spec_sha256,"containers":containers,"active":i.active_images});
    Ok(CsiPodProjection {
        facts,
        pod_uid,
        spec_sha256,
    })
}

#[cfg(test)]
#[path = "restore_csi_pod_projection_tests.rs"]
mod tests;
