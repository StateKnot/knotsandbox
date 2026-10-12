//! Independent admission workload. It has only signed read-only ECS identity
//! observations and cannot publish owner topology receipts or expose an owner
//! client. The deployment subject/role/token/egress require separate review.
use super::{
    CloudError, CloudErrorCode,
    node_topology::{
        AlibabaCloudNodeTopology, NodeTopologyCloudBinding, NodeTopologyCloudConfig,
        NodeTopologyCloudObservation,
    },
};
use std::{net::IpAddr, time::Duration};

#[derive(Clone)]
pub(crate) struct AlibabaCloudAdmissionNodeTopology {
    inner: AlibabaCloudNodeTopology,
}
impl AlibabaCloudAdmissionNodeTopology {
    pub(crate) fn new(
        config: NodeTopologyCloudConfig,
        binding: NodeTopologyCloudBinding,
    ) -> Result<Self, CloudError> {
        let sts = url::Url::parse(&format!("https://sts.{}.aliyuncs.com/", config.region))
            .map_err(|_| super::err(CloudErrorCode::Configuration))?;
        let ecs = url::Url::parse(&format!("https://ecs.{}.aliyuncs.com/", config.region))
            .map_err(|_| super::err(CloudErrorCode::Configuration))?;
        Ok(Self {
            inner: AlibabaCloudNodeTopology::build_admission_readonly(
                config, binding, sts, ecs, true,
            )?,
        })
    }
    pub(crate) fn binding(&self) -> &NodeTopologyCloudBinding {
        self.inner.binding()
    }
    pub(crate) fn identity_matches(&self, issuer: &str, provider: &str) -> bool {
        self.inner.identity_matches(issuer, provider)
    }
    pub(crate) async fn observe(&self) -> Result<NodeTopologyCloudObservation, CloudError> {
        // This inner timeout does not widen the service's original first/last
        // reader budgets or the external apiserver's existing four seconds.
        tokio::time::timeout(Duration::from_secs(3), self.inner.observe())
            .await
            .map_err(|_| super::err(CloudErrorCode::Transport))?
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
            return Err(super::err(CloudErrorCode::Configuration));
        }
        Ok(Self {
            inner: AlibabaCloudNodeTopology::build_admission_readonly(
                config,
                binding,
                endpoint.clone(),
                endpoint,
                false,
            )?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn owner_subject_and_nonliteral_endpoints_cannot_enter_admission_client() {
        let account = "1234567890123456";
        let config = NodeTopologyCloudConfig {
            account_id: account.into(),
            region: "cn-hangzhou".into(),
            role_arn: format!("acs:ram::{account}:role/admission-readonly"),
            role_id: "1234567890".into(),
            oidc_provider_arn: format!("acs:ram::{account}:oidc-provider/fixture"),
            oidc_issuer: "https://issuer.fixture.invalid".into(),
            oidc_audience: "sts.aliyuncs.com".into(),
            oidc_subject: "system:serviceaccount:sandbox-system:sandbox-admission".into(),
            oidc_token_file: "/__sandbox_private_topology_unit__/token".into(),
            requests_per_second: 1,
            max_in_flight: 1,
        };
        let binding = NodeTopologyCloudBinding {
            account_id: account.into(),
            region: "cn-hangzhou".into(),
            instance_id: "i-unitnode".into(),
            zone_id: "cn-hangzhou-a".into(),
            vpc_id: "vpc-unit".into(),
            vswitch_id: "vsw-unit".into(),
            private_ip: "10.0.0.5".parse().unwrap(),
            deployment: "sandbox".into(),
        };
        // Constructors only; no observe(), token file read or network access.
        assert!(AlibabaCloudAdmissionNodeTopology::new(config.clone(), binding.clone()).is_ok());
        assert!(AlibabaCloudNodeTopology::new(config.clone(), binding.clone()).is_err());
        let mut owner = config.clone();
        owner.oidc_subject =
            "system:serviceaccount:sandbox-system:sandbox-node-topology-owner".into();
        assert!(AlibabaCloudAdmissionNodeTopology::new(owner.clone(), binding.clone()).is_err());
        assert!(AlibabaCloudNodeTopology::new(owner, binding.clone()).is_ok());
        for endpoint in [
            "http://localhost:1234/",
            "http://10.0.0.5:1234/",
            "https://127.0.0.1:1234/",
            "http://127.0.0.1/",
            "http://127.0.0.1:1234/unreviewed",
            "http://127.0.0.1:1234/?x=1",
            "http://user@127.0.0.1:1234/",
        ] {
            assert!(
                AlibabaCloudAdmissionNodeTopology::for_test(
                    config.clone(),
                    binding.clone(),
                    endpoint.parse().unwrap()
                )
                .is_err(),
                "{endpoint}"
            );
        }
    }
}
