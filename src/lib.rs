#![recursion_limit = "256"]

pub mod admin;
pub mod admission;
pub mod api;
pub mod api_secret_init;
pub mod api_tls;
pub mod auth;
pub mod automation;
mod automation_authority;
pub mod bff;
pub mod bff_config;
pub mod bff_crypto;
mod bff_ledger;
pub mod bff_oidc;
pub mod capabilities;
pub mod config;
pub mod db;
pub mod domain;
pub mod engine;
pub mod error;
pub mod event_stream;
pub mod execution;
pub mod grants;
pub mod history;
pub mod instance_details;
pub mod instance_security;
pub mod lifecycle;
pub mod logging;
pub mod model;
pub mod request;
pub mod resource_accounting;
mod resource_accounting_schema;
pub mod runner;
pub mod runtime;
mod runtime_class_guard;
pub mod runtime_manifest;
mod runtime_resource_contract;
pub mod timers;

pub mod worker;
mod worker_observation;

pub mod gateway_protocol;

pub mod gateway_ledger;
pub mod gateway_runtime;

pub mod file_api;
pub mod file_cleanup;
pub mod file_store;
mod oss_signing;
pub mod output_store;

pub mod gateway_transport;

pub mod gateway;

pub mod execution_output;

pub mod node_enrollment;
pub mod nodeguard;
pub mod service_clients;
pub mod tenant_audit;
pub mod termination;
pub mod termination_client;
pub mod termination_runtime;

pub mod termination_ledger;

#[cfg(test)]
extern crate self as sandbox_platform;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
#[allow(dead_code)]
pub(crate) mod test_support_db;

pub mod cloud_fencing;

pub mod node_fencing;

pub mod workspaces;

pub mod volume_deletion;

pub mod execution_output_stream;
pub mod volume_deletion_runtime;

pub mod backup_admission;
pub mod backup_manifest;

pub mod backup_ledger;
pub mod backup_runtime;

pub mod backup_object;

pub mod instance_metrics;
pub mod metrics;

pub mod launch_authority;

pub mod never_authorized_gc;

pub mod backup_job;

pub mod backup_host;

pub mod tls;

pub mod backup_controller;

pub mod backup_profile;

pub mod bucket_retention;

pub mod diagnostics;

pub mod file_transfer;

pub mod workspace_restore;

// Private acceptance code is compiled by normal Cargo/CI. Presence of a test
// module does not export restore APIs or enable a draft production migration.
#[cfg(test)]
#[path = "restore.rs"]
mod restore;

pub mod service_lifecycle;
