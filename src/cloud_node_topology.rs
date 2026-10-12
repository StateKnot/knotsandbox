//! Independent, exact-instance read-only topology observations. No node/disk
//! mutation method, unverified response constructor or transport accessor.
use super::*;
use serde_json::{Value, json};
use std::net::Ipv4Addr;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeTopologyCloudConfig {
    pub account_id: String,
    pub region: String,
    pub role_arn: String,
    pub role_id: String,
    pub oidc_provider_arn: String,
    pub oidc_issuer: String,
    pub oidc_audience: String,
    pub oidc_subject: String,
    pub oidc_token_file: PathBuf,
    pub requests_per_second: u32,
    pub max_in_flight: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NodeTopologyCloudBinding {
    pub account_id: String,
    pub region: String,
    pub instance_id: String,
    pub zone_id: String,
    pub vpc_id: String,
    pub vswitch_id: String,
    pub private_ip: Ipv4Addr,
    pub deployment: String,
}
#[derive(Clone)]
pub(crate) struct AlibabaCloudNodeTopology {
    transport: AlibabaCloudFencing,
    binding: NodeTopologyCloudBinding,
}
// No Deserialize, public fields, From<Value> or test-only proof constructor.
pub(crate) struct NodeTopologyCloudObservation {
    binding: NodeTopologyCloudBinding,
    evidence: CloudRequestEvidence,
}
impl NodeTopologyCloudObservation {
    pub(crate) fn binding(&self) -> &NodeTopologyCloudBinding {
        &self.binding
    }
    pub(crate) fn observed_at(&self) -> DateTime<Utc> {
        self.evidence.received_at
    }
    pub(crate) fn projection(&self) -> Result<Value, CloudError> {
        let request_id = self
            .evidence
            .provider_request_id
            .as_deref()
            .filter(|v| visible(v, 256))
            .ok_or_else(|| err(CloudErrorCode::MalformedResponse))?;
        let response_sha256 = self
            .evidence
            .response_sha256
            .as_deref()
            .filter(|v| crate::nodeguard::protocol::valid_sha256(v))
            .ok_or_else(|| err(CloudErrorCode::MalformedResponse))?;
        let b = &self.binding;
        Ok(
            json!({"protocol":1,"account_id":b.account_id,"region":b.region,
            "instance_id":b.instance_id,"zone_id":b.zone_id,"vpc_id":b.vpc_id,
            "vswitch_id":b.vswitch_id,"private_ip":b.private_ip.to_string(),
            "deployment":b.deployment,"role":"kata","status":"Running",
            "request_id":request_id,"response_sha256":response_sha256,
            "observed_at":self.evidence.received_at.to_rfc3339_opts(SecondsFormat::Micros,true)}),
        )
    }
}
fn visible(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|v| v.is_ascii_graphic())
}
fn cloud_id(value: &str, prefix: &str) -> bool {
    value.len() <= 128
        && value
            .strip_prefix(prefix)
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric()))
}
fn valid_binding(b: &NodeTopologyCloudBinding) -> bool {
    b.account_id.len() == 16
        && b.account_id.bytes().all(|v| v.is_ascii_digit())
        && (4..=32).contains(&b.region.len())
        && b.region.starts_with("cn-")
        && b.region
            .bytes()
            .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'-')
        && b.zone_id.len() <= 64
        && b.zone_id
            .strip_prefix(&format!("{}-", b.region))
            .is_some_and(|v| {
                !v.is_empty()
                    && v.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            })
        && cloud_id(&b.instance_id, "i-")
        && cloud_id(&b.vpc_id, "vpc-")
        && cloud_id(&b.vswitch_id, "vsw-")
        && b.private_ip.is_private()
        && crate::backup_job::valid_deployment(&b.deployment)
}
impl AlibabaCloudNodeTopology {
    pub(crate) fn new(
        config: NodeTopologyCloudConfig,
        binding: NodeTopologyCloudBinding,
    ) -> Result<Self, CloudError> {
        let sts = url::Url::parse(&format!("https://sts.{}.aliyuncs.com/", config.region))
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        let ecs = url::Url::parse(&format!("https://ecs.{}.aliyuncs.com/", config.region))
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        Self::build(config, binding, sts, ecs, true)
    }
    fn build(
        config: NodeTopologyCloudConfig,
        binding: NodeTopologyCloudBinding,
        sts: url::Url,
        ecs: url::Url,
        https: bool,
    ) -> Result<Self, CloudError> {
        Self::build_fixed(
            config,
            binding,
            sts,
            ecs,
            https,
            "system:serviceaccount:sandbox-system:sandbox-node-topology-owner",
        )
    }
    // Visible only inside cloud_fencing. This entry is consumed solely by the
    // distinct admission wrapper; owner public constructors retain their exact
    // subject and the admission wrapper never exposes this inner owner type.
    pub(super) fn build_admission_readonly(
        config: NodeTopologyCloudConfig,
        binding: NodeTopologyCloudBinding,
        sts: url::Url,
        ecs: url::Url,
        https: bool,
    ) -> Result<Self, CloudError> {
        Self::build_fixed(
            config,
            binding,
            sts,
            ecs,
            https,
            "system:serviceaccount:sandbox-system:sandbox-admission",
        )
    }
    fn build_fixed(
        config: NodeTopologyCloudConfig,
        binding: NodeTopologyCloudBinding,
        sts: url::Url,
        ecs: url::Url,
        https: bool,
        subject: &'static str,
    ) -> Result<Self, CloudError> {
        if !valid_binding(&binding)
            || config.account_id != binding.account_id
            || config.region != binding.region
            || config.oidc_subject != subject
            || config.oidc_audience != "sts.aliyuncs.com"
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        // Official RAM table supports exact Instance ARN for DescribeInstances.
        // Session policy intersects operator RAM; no Stop/Reboot/Create/Delete,
        // tag write, disk API or ECS wildcard permission is exposed.
        let policy=serde_json::to_string(&json!({"Version":"1","Statement":[
            {"Effect":"Allow","Action":["ecs:DescribeInstances"],"Resource":[
                format!("acs:ecs:{}:{}:instance/{}",binding.region,binding.account_id,binding.instance_id)]},
            {"Effect":"Allow","Action":["sts:GetCallerIdentity"],"Resource":["*"]}
        ]})).map_err(|_| err(CloudErrorCode::Configuration))?;
        if policy.len() > 2048 {
            return Err(err(CloudErrorCode::Configuration));
        }
        let identity = CloudIdentityConfig {
            account_id: config.account_id,
            region: config.region,
            role_arn: config.role_arn,
            role_id: config.role_id,
            oidc_provider_arn: config.oidc_provider_arn,
            oidc_issuer: config.oidc_issuer,
            oidc_audience: config.oidc_audience,
            oidc_subject: config.oidc_subject,
            oidc_token_file: config.oidc_token_file,
            requests_per_second: config.requests_per_second,
            max_in_flight: config.max_in_flight,
            session_policy: Some(policy),
        };
        validate_identity_config(&identity)?;
        Ok(Self {
            transport: AlibabaCloudFencing::build_transport(
                identity,
                BTreeMap::new(),
                Some(binding.deployment.clone()),
                sts,
                ecs,
                https,
            )?,
            binding,
        })
    }
    pub(crate) fn binding(&self) -> &NodeTopologyCloudBinding {
        &self.binding
    }
    pub(crate) fn identity_matches(&self, issuer: &str, provider_arn: &str) -> bool {
        self.transport.inner.config.oidc_issuer == issuer
            && self.transport.inner.config.oidc_provider_arn == provider_arn
    }
    pub(crate) async fn observe(&self) -> Result<NodeTopologyCloudObservation, CloudError> {
        // Installation capture only. Admission's stricter decision deadline is
        // independent and may cancel these reads; neither timeout proves absence.
        tokio::time::timeout(Duration::from_secs(25), self.observe_inner())
            .await
            .map_err(|_| err(CloudErrorCode::Transport))?
    }
    async fn observe_inner(&self) -> Result<NodeTopologyCloudObservation, CloudError> {
        let credentials = self.transport.credentials().await?;
        let query = BTreeMap::from([
            ("RegionId".into(), self.binding.region.clone()),
            (
                "InstanceIds".into(),
                serde_json::to_string(&[&self.binding.instance_id])
                    .map_err(|_| err(CloudErrorCode::Configuration))?,
            ),
            ("MaxResults".into(), "10".into()),
        ]);
        // No status/tag/VPC filter may hide an existing changed identity.
        let r = self
            .transport
            .read_request(
                "DescribeInstances",
                ECS_VERSION,
                &self.transport.inner.ecs,
                &query,
                Some(&credentials),
            )
            .await?;
        self.decode(&r)
    }
    fn decode(&self, r: &Response) -> Result<NodeTopologyCloudObservation, CloudError> {
        let response: DescribeTopologyResponse = parse_response(r)?;
        if !response.next_token.as_deref().unwrap_or("").is_empty()
            || response.instances.instance.len() != 1
            || !visible(&response.request_id, 256)
            || r.evidence.provider_request_id.as_deref() != Some(response.request_id.as_str())
        {
            return Err(response_error(CloudErrorCode::IdentityMismatch, r));
        }
        let i = &response.instances.instance[0];
        let b = &self.binding;
        let mut tags = BTreeMap::new();
        if i.tags.tag.len() > 256 {
            return Err(response_error(CloudErrorCode::MalformedResponse, r));
        }
        for t in &i.tags.tag {
            if t.tag_key.is_empty()
                || t.tag_key.len() > 256
                || t.tag_value.len() > 256
                || t.tag_key.chars().any(char::is_control)
                || t.tag_value.chars().any(char::is_control)
                || tags
                    .insert(t.tag_key.as_str(), t.tag_value.as_str())
                    .is_some()
            {
                return Err(response_error(CloudErrorCode::IdentityMismatch, r));
            }
        }
        let mut ips = BTreeMap::new();
        for ip in &i.vpc_attributes.private_ip_address.ip_address {
            let address: Ipv4Addr = ip
                .parse()
                .map_err(|_| response_error(CloudErrorCode::IdentityMismatch, r))?;
            if address.to_string() != *ip
                || !address.is_private()
                || ips.insert(address, ()).is_some()
            {
                return Err(response_error(CloudErrorCode::IdentityMismatch, r));
            }
        }
        if !(1..=128).contains(&ips.len())
            || !ips.contains_key(&b.private_ip)
            || i.instance_id != b.instance_id
            || i.region_id != b.region
            || i.zone_id != b.zone_id
            || i.instance_network_type != "vpc"
            || i.vpc_attributes.vpc_id != b.vpc_id
            || i.vpc_attributes.v_switch_id != b.vswitch_id
            || i.status != "Running"
            || tags.get("Deployment") != Some(&b.deployment.as_str())
            || tags.get("Role") != Some(&"kata")
        {
            return Err(response_error(CloudErrorCode::IdentityMismatch, r));
        }
        let mut evidence = r.evidence.clone();
        // Sample the actual transport completion once; normalize down to the
        // SQL wire's microseconds, never round an expiry boundary upward.
        evidence.received_at =
            DateTime::from_timestamp_micros(evidence.received_at.timestamp_micros())
                .ok_or_else(|| response_error(CloudErrorCode::MalformedResponse, r))?;
        Ok(NodeTopologyCloudObservation {
            binding: b.clone(),
            evidence,
        })
    }
    #[cfg(test)]
    pub(crate) fn for_test(
        config: NodeTopologyCloudConfig,
        binding: NodeTopologyCloudBinding,
        endpoint: url::Url,
    ) -> Result<Self, CloudError> {
        if endpoint.scheme() != "http"
            || endpoint
                .host_str()
                .and_then(|v| v.parse::<IpAddr>().ok())
                .is_none_or(|v| !v.is_loopback())
            || endpoint.port().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        Self::build(config, binding, endpoint.clone(), endpoint, false)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DescribeTopologyResponse {
    request_id: String,
    instances: TopologyInstances,
    #[serde(default)]
    next_token: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TopologyInstances {
    instance: Vec<TopologyInstance>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TopologyInstance {
    instance_id: String,
    region_id: String,
    zone_id: String,
    instance_network_type: String,
    status: String,
    vpc_attributes: TopologyVpc,
    tags: Tags,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TopologyVpc {
    vpc_id: String,
    #[serde(rename = "VSwitchId")]
    v_switch_id: String,
    private_ip_address: PrivateIpAddresses,
}

// Narrow fixture seam: verify an actual received ACS3 request, never construct
// a topology observation or change production endpoints/credentials/identity.
#[cfg(test)]
pub(crate) fn verify_test_request(
    headers: &HeaderMap,
    query: &str,
    access_key: &str,
    secret: &str,
) -> bool {
    let values = headers
        .iter()
        .filter(|(k, _)| k.as_str() == "host" || k.as_str().starts_with("x-acs-"))
        .map(|(k, v)| v.to_str().map(|v| (k.to_string(), v.to_owned())))
        .collect::<std::result::Result<BTreeMap<_, _>, _>>();
    let Ok(values) = values else {
        return false;
    };
    let Ok((signed, digest)) = signature(&values, query, secret) else {
        return false;
    };
    headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(
            format!(
                "ACS3-HMAC-SHA256 Credential={access_key},SignedHeaders={signed},Signature={digest}"
            )
            .as_str(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> NodeTopologyCloudBinding {
        NodeTopologyCloudBinding {
            account_id: "1234567890123456".into(),
            region: "cn-hangzhou".into(),
            instance_id: "i-publictest".into(),
            zone_id: "cn-hangzhou-a".into(),
            vpc_id: "vpc-publictest".into(),
            vswitch_id: "vsw-publictest".into(),
            private_ip: Ipv4Addr::new(10, 1, 0, 10),
            deployment: "production-a".into(),
        }
    }
    fn config() -> NodeTopologyCloudConfig {
        NodeTopologyCloudConfig {
            account_id: "1234567890123456".into(),
            region: "cn-hangzhou".into(),
            role_arn: "acs:ram::1234567890123456:role/sandbox-node-topology-owner".into(),
            role_id: "1234567890123457".into(),
            oidc_provider_arn: "acs:ram::1234567890123456:oidc-provider/sandbox".into(),
            oidc_issuer: "https://workload.example.test".into(),
            oidc_audience: "sts.aliyuncs.com".into(),
            oidc_subject: "system:serviceaccount:sandbox-system:sandbox-node-topology-owner".into(),
            oidc_token_file: PathBuf::from("/public-test-token-not-read"),
            requests_per_second: 20,
            max_in_flight: 4,
        }
    }
    #[test]
    fn topology_constructor_fixes_readonly_policy_identity_and_official_endpoints()
    -> anyhow::Result<()> {
        let client = AlibabaCloudNodeTopology::new(config(), binding())?;
        assert_eq!(
            client.transport.inner.sts.as_str(),
            "https://sts.cn-hangzhou.aliyuncs.com/"
        );
        assert_eq!(
            client.transport.inner.ecs.as_str(),
            "https://ecs.cn-hangzhou.aliyuncs.com/"
        );
        let policy: Value = serde_json::from_str(
            client
                .transport
                .inner
                .config
                .session_policy
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing test policy"))?,
        )?;
        assert_eq!(
            policy,
            json!({"Version":"1","Statement":[
            {"Effect":"Allow","Action":["ecs:DescribeInstances"],"Resource":["acs:ecs:cn-hangzhou:1234567890123456:instance/i-publictest"]},
            {"Effect":"Allow","Action":["sts:GetCallerIdentity"],"Resource":["*"]}]})
        );
        let mut wrong = config();
        wrong.oidc_subject = "system:serviceaccount:sandbox-system:sandbox-fencing".into();
        assert!(AlibabaCloudNodeTopology::new(wrong, binding()).is_err());
        let mut wrong = config();
        wrong.oidc_audience = "other".into();
        assert!(AlibabaCloudNodeTopology::new(wrong, binding()).is_err());
        let mut wrong = binding();
        wrong.private_ip = Ipv4Addr::new(127, 0, 0, 1);
        assert!(AlibabaCloudNodeTopology::new(config(), wrong).is_err());
        let mut wrong = binding();
        wrong.zone_id = "cn-other-a".into();
        assert!(AlibabaCloudNodeTopology::new(config(), wrong).is_err());
        for url in [
            "http://localhost:1234/",
            "http://192.168.1.1:1234/",
            "https://127.0.0.1:1234/",
            "http://127.0.0.1:1234/arbitrary",
            "http://127.0.0.1:1234/?token=public-test",
        ] {
            assert!(
                AlibabaCloudNodeTopology::for_test(config(), binding(), url::Url::parse(url)?)
                    .is_err()
            );
        }
        Ok(())
    }
}
