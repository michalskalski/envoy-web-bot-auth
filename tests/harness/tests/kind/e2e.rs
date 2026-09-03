//! Kubernetes system checks for the dynamic module and fixture resolver.
//!
//! The suite owns mode changes and resets fixture resolver state before each
//! request group. This prevents cache and retry state from leaking between
//! cases.

mod authentication;
mod cache;
mod composition;
mod context;
mod diagnostics;
mod external_resolver;
mod portability;
mod scenario;

use scenario::{ExpectedResponse, Mode};

use std::{
    env,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const EG_NAMESPACE: &str = "envoy-gateway-system";
const GATEWAY_NAMESPACE: &str = "default";
const SELECTOR: &str = "gateway.envoyproxy.io/owning-gateway-name=web-bot-auth";
const BASE_URL: &str = "http://127.0.0.1";
const AGENT_B: &str = "https://fixture-b.web-bot-auth.test";
const READY_STATUSES: &[u16] = &[200, 400, 403, 429, 503];
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const ROLLOUT_RESTART_RETRY_DELAY: Duration = Duration::from_millis(1_100);
const ROLLOUT_RESTART_TOO_SOON: &str = "if restart has already been triggered within the past second, please wait before attempting to trigger another";

struct PortForward {
    child: Child,
    local_port: u16,
    output: Arc<Mutex<String>>,
}

impl PortForward {
    const fn port(&self) -> u16 {
        self.local_port
    }

    fn output(&self) -> String {
        self.output
            .lock()
            .map(|output| output.clone())
            .unwrap_or_default()
    }
}

impl Drop for PortForward {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn kubeconfig() -> String {
    env::var("KIND_KUBECONFIG").unwrap_or_else(|_| {
        repository_path(".kind/envoy-web-bot-auth.kubeconfig")
            .display()
            .to_string()
    })
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the harness crate stays under the repository root")
        .to_path_buf()
}

pub(crate) fn repository_path(relative: &str) -> PathBuf {
    repository_root().join(relative)
}

fn record_failure(code: &str, detail: &str) {
    diagnostics::record(&repository_root(), code, detail);
}

fn wait_until<F>(timeout: Duration, error: &'static str, mut condition: F) -> Result<(), String>
where
    F: FnMut() -> Result<bool, String>,
{
    let deadline = Instant::now() + timeout;
    loop {
        match condition() {
            Ok(true) => return Ok(()),
            Ok(false) | Err(_) if Instant::now() < deadline => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Ok(false) | Err(_) => {
                record_failure(error, "condition did not become true before the deadline");
                return Err(error.into());
            }
        }
    }
}

fn append_forward_output(output: &Arc<Mutex<String>>, line: &str) {
    const MAX_OUTPUT_BYTES: usize = 8 * 1024;
    let Ok(mut output) = output.lock() else {
        return;
    };
    if output.len() < MAX_OUTPUT_BYTES {
        output.push_str(line);
        output.push('\n');
        output.truncate(MAX_OUTPUT_BYTES);
    }
}

fn capture_forward_output<R>(reader: R, output: Arc<Mutex<String>>)
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            append_forward_output(&output, &line);
        }
    });
}

fn output_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).into_owned()
    } else {
        stderr.into_owned()
    }
}

fn run_command(
    mut command: Command,
    timeout: Duration,
    error: &'static str,
) -> Result<Output, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| format!("{error}_start_failed"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|_| format!("{error}_wait_failed"));
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(COMMAND_POLL_INTERVAL);
            }
            Ok(None) => {
                let _ = child.kill();
                let output = child.wait_with_output().ok();
                if let Some(output) = output.as_ref() {
                    record_failure(error, &output_detail(output));
                } else {
                    record_failure(error, "command timed out and its output was unavailable");
                }
                return Err(error.into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                record_failure(error, "command status could not be read");
                return Err(error.into());
            }
        }
    }
}

fn run_command_with_input(
    mut command: Command,
    input: &[u8],
    timeout: Duration,
    error: &'static str,
) -> Result<Output, String> {
    command.stdin(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| format!("{error}_start_failed"))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        if stdin.write_all(input).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{error}_write_failed"));
        }
    }
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|_| format!("{error}_wait_failed"));
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(COMMAND_POLL_INTERVAL);
            }
            Ok(None) => {
                let _ = child.kill();
                let output = child.wait_with_output().ok();
                if let Some(output) = output.as_ref() {
                    record_failure(error, &output_detail(output));
                } else {
                    record_failure(error, "command timed out and its output was unavailable");
                }
                return Err(error.into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                record_failure(error, "command status could not be read");
                return Err(error.into());
            }
        }
    }
}

fn reported_forward_port(output: &str) -> Option<u16> {
    output.lines().find_map(|line| {
        let remainder = line.split_once("127.0.0.1:")?.1;
        let digits = remainder
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        let port = digits.parse().ok()?;
        (port != 0).then_some(port)
    })
}

fn kubectl(args: &[&str]) -> Result<String, String> {
    kubectl_with_timeout(args, Duration::from_secs(180), "kubectl_command_failed")
}

fn kubectl_with_timeout(
    args: &[&str],
    timeout: Duration,
    error: &'static str,
) -> Result<String, String> {
    let mut command = Command::new("kubectl");
    command.arg("--kubeconfig").arg(kubeconfig()).args(args);
    let output = run_command(command, timeout, error)?;
    if output.status.success() {
        String::from_utf8(output.stdout).map_err(|_| "kubectl_output_invalid".to_owned())
    } else {
        record_failure(error, &output_detail(&output));
        Err(error.to_owned())
    }
}

fn rollout_restart_was_triggered_too_soon(detail: &str) -> bool {
    let detail = detail.trim();
    let Some(resource) = detail.strip_prefix("error: failed to create patch for ") else {
        return false;
    };
    let Some(resource) = resource.strip_suffix(ROLLOUT_RESTART_TOO_SOON) else {
        return false;
    };
    !resource.trim().is_empty() && !detail.contains('\n')
}

fn restart_rollout_with_deadline(deployment: &str, deadline: Instant) -> Result<(), String> {
    let args = [
        "rollout",
        "restart",
        "deployment",
        deployment,
        "--namespace",
        EG_NAMESPACE,
    ];
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            record_failure("gateway_restart_failed", "restart deadline elapsed");
            return Err("gateway_restart_failed".into());
        }

        let mut command = Command::new("kubectl");
        command.arg("--kubeconfig").arg(kubeconfig()).args(args);
        let output = run_command(command, timeout, "gateway_restart_failed")?;
        if output.status.success() {
            return Ok(());
        }

        let detail = output_detail(&output);
        if !rollout_restart_was_triggered_too_soon(&detail) {
            record_failure("gateway_restart_failed", &detail);
            return Err("gateway_restart_failed".into());
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            record_failure("gateway_restart_failed", &detail);
            return Err("gateway_restart_failed".into());
        }
        std::thread::sleep(ROLLOUT_RESTART_RETRY_DELAY.min(remaining));
    }
}

fn render_kustomization(path: &Path, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut command = Command::new("kubectl");
    command.args([
        "kustomize",
        path.to_str().ok_or("kustomization_path_invalid")?,
        "--load-restrictor=LoadRestrictionsNone",
    ]);
    let output = run_command(command, timeout, "kustomize_failed")?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        record_failure("kustomize_failed", &output_detail(&output));
        Err("kustomize_failed".into())
    }
}

fn apply_manifest(manifest: &[u8], timeout: Duration) -> Result<(), String> {
    let mut command = Command::new("kubectl");
    command
        .arg("--kubeconfig")
        .arg(kubeconfig())
        .args(["apply", "--filename", "-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_command_with_input(command, manifest, timeout, "kubectl_apply_failed")?;
    if output.status.success() {
        Ok(())
    } else {
        record_failure("kubectl_apply_failed", &output_detail(&output));
        Err("kubectl_apply_failed".into())
    }
}

fn apply_mode(mode: Mode) -> Result<(), String> {
    apply_mode_with_timeout(mode, Duration::from_secs(180))
}

fn apply_mode_with_timeout(mode: Mode, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let overlay = repository_path(&format!("examples/kind/overlays/{}", mode.name()));
    let rendered = render_kustomization(&overlay, timeout)?;
    apply_manifest(
        &rendered,
        deadline.saturating_duration_since(Instant::now()),
    )?;
    let deployment = gateway_deployment_with_deadline(deadline)?;
    wait_for_deployment_ready_with_deadline(
        EG_NAMESPACE,
        &deployment,
        None,
        deadline,
        "gateway_rollout_failed",
    )?;
    wait_for_policy_convergence_with_deadline("web-bot-auth", deadline)
}

fn deployment_is_ready(document: &serde_json::Value, expected_replicas: Option<u64>) -> bool {
    let generation = document
        .get("metadata")
        .and_then(|metadata| metadata.get("generation"))
        .and_then(serde_json::Value::as_u64);
    let observed_generation = document
        .get("status")
        .and_then(|status| status.get("observedGeneration"))
        .and_then(serde_json::Value::as_u64);
    if generation.is_none() || generation != observed_generation {
        return false;
    }

    let desired_replicas = document
        .get("spec")
        .and_then(|spec| spec.get("replicas"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    let available_replicas = document
        .get("status")
        .and_then(|status| status.get("availableReplicas"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let replicas = document
        .get("status")
        .and_then(|status| status.get("replicas"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let updated_replicas = document
        .get("status")
        .and_then(|status| status.get("updatedReplicas"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();

    if replicas != desired_replicas || updated_replicas != desired_replicas {
        return false;
    }

    match expected_replicas {
        Some(expected) => desired_replicas == expected && available_replicas == expected,
        None => available_replicas >= desired_replicas,
    }
}

fn wait_for_deployment_ready_with_deadline(
    namespace: &str,
    deployment: &str,
    expected_replicas: Option<u64>,
    deadline: Instant,
    error: &'static str,
) -> Result<(), String> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let document = kubectl_with_timeout(
            &[
                "get",
                "deployment",
                deployment,
                "--namespace",
                namespace,
                "--output",
                "json",
            ],
            remaining.min(Duration::from_secs(10)),
            "deployment_status_failed",
        );
        if let Ok(document) = document
            && serde_json::from_str::<serde_json::Value>(&document)
                .map(|document| deployment_is_ready(&document, expected_replicas))
                .unwrap_or(false)
        {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(COMMAND_POLL_INTERVAL.min(remaining));
    }
    record_failure(
        error,
        "deployment did not observe its generation with enough replicas",
    );
    Err(error.into())
}

fn wait_for_policy_convergence(name: &str) -> Result<(), String> {
    wait_for_policy_convergence_with_deadline(name, Instant::now() + Duration::from_secs(180))
}

fn wait_for_policy_convergence_with_deadline(name: &str, deadline: Instant) -> Result<(), String> {
    wait_for_accepted_policy(
        "envoyextensionpolicy",
        name,
        deadline,
        "extension_policy_not_converged",
        "extension policy did not report the current generation as accepted",
    )
}

fn wait_for_backend_policy_convergence(name: &str) -> Result<(), String> {
    wait_for_accepted_policy(
        "backendtrafficpolicy",
        name,
        Instant::now() + Duration::from_secs(180),
        "backend_policy_not_converged",
        "backend policy did not report the current generation as accepted",
    )
}

fn wait_for_accepted_policy(
    kind: &str,
    name: &str,
    deadline: Instant,
    error: &'static str,
    detail: &'static str,
) -> Result<(), String> {
    loop {
        let Ok(document) = kubectl_with_timeout(
            &[
                "get",
                kind,
                name,
                "--namespace",
                GATEWAY_NAMESPACE,
                "--output",
                "json",
            ],
            deadline.saturating_duration_since(Instant::now()),
            "policy_status_failed",
        ) else {
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
            continue;
        };
        let Ok(document) = serde_json::from_str::<serde_json::Value>(&document) else {
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
            continue;
        };
        let generation = document
            .get("metadata")
            .and_then(|metadata| metadata.get("generation"))
            .and_then(serde_json::Value::as_u64);
        let accepted = document
            .get("status")
            .and_then(|status| status.get("ancestors"))
            .and_then(serde_json::Value::as_array)
            .and_then(|ancestors| ancestors.first())
            .and_then(|ancestor| ancestor.get("conditions"))
            .and_then(serde_json::Value::as_array)
            .and_then(|conditions| {
                conditions.iter().find(|condition| {
                    condition.get("type").and_then(serde_json::Value::as_str) == Some("Accepted")
                })
            });
        let accepted_generation = accepted
            .and_then(|condition| condition.get("observedGeneration"))
            .and_then(serde_json::Value::as_u64);
        if accepted
            .and_then(|condition| condition.get("status"))
            .and_then(serde_json::Value::as_str)
            == Some("True")
            && generation.is_some()
            && generation == accepted_generation
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    record_failure(error, detail);
    Err(error.into())
}

fn wait_for_backend_policy_absent(deadline: Instant) -> Result<(), String> {
    let name = "web-bot-auth-composition-quota";
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let result = kubectl_with_timeout(
            &[
                "get",
                "backendtrafficpolicy",
                name,
                "--namespace",
                GATEWAY_NAMESPACE,
                "--ignore-not-found=true",
                "--output",
                "name",
            ],
            remaining.min(Duration::from_secs(10)),
            "backend_policy_delete_status_failed",
        );
        if result.is_ok_and(|resource| resource.trim().is_empty()) {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(COMMAND_POLL_INTERVAL.min(remaining));
    }
    record_failure(
        "backend_policy_not_deleted",
        "composition rate policy remained after cleanup",
    );
    Err("backend_policy_not_deleted".into())
}

fn apply_kustomization(path: &str) -> Result<(), String> {
    let path = repository_path(path);
    let rendered = render_kustomization(&path, Duration::from_secs(180))?;
    apply_manifest(&rendered, Duration::from_secs(180))
}

fn apply_file(path: &str) -> Result<(), String> {
    let path = repository_path(path);
    kubectl(&[
        "apply",
        "--filename",
        path.to_str().ok_or("manifest_path_invalid")?,
    ])
    .map(|_| ())
}

fn delete_file_with_timeout(path: &str, timeout: Duration) -> Result<(), String> {
    let path = repository_path(path);
    let wait_for_policy = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "local-catchall.yaml" | "global-identity.yaml"));
    let wait = if wait_for_policy {
        "--wait=true"
    } else {
        "--wait=false"
    };
    kubectl_with_timeout(
        &[
            "delete",
            "--filename",
            path.to_str().ok_or("manifest_path_invalid")?,
            "--ignore-not-found=true",
            wait,
        ],
        timeout,
        "composition_delete_failed",
    )
    .map(|_| ())
}

pub(crate) struct CompositionCleanup;

pub(crate) fn composition_cleanup() -> CompositionCleanup {
    CompositionCleanup
}

impl Drop for CompositionCleanup {
    fn drop(&mut self) {
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let mut removed_rate_policy = false;
        for path in [
            "examples/kind/composition/routes.yaml",
            "examples/kind/composition/local-catchall.yaml",
            "examples/kind/composition/global-identity.yaml",
        ] {
            let is_rate_policy =
                path.ends_with("local-catchall.yaml") || path.ends_with("global-identity.yaml");
            let timeout = deadline.saturating_duration_since(Instant::now());
            if delete_file_with_timeout(path, timeout).is_err() {
                record_failure("composition_cleanup_incomplete", path);
            } else if is_rate_policy {
                removed_rate_policy = true;
            }
        }
        if let Err(error) = wait_for_backend_policy_absent(deadline) {
            record_failure("composition_cleanup_incomplete", &error);
        }
        if removed_rate_policy && let Err(error) = restart_gateway(Some(1)) {
            record_failure("composition_gateway_restore_failed", &error);
        }
        if let Err(error) = apply_mode_with_timeout(
            Mode::Observe,
            deadline.saturating_duration_since(Instant::now()),
        ) {
            record_failure("composition_baseline_restore_failed", &error);
        }
    }
}

fn apply_composition() -> Result<(), String> {
    apply_kustomization("examples/kind/composition")?;
    let deployment = gateway_deployment()?;
    wait_for_deployment_ready_with_deadline(
        EG_NAMESPACE,
        &deployment,
        None,
        Instant::now() + Duration::from_secs(180),
        "gateway_rollout_failed",
    )?;
    wait_for_policy_convergence("web-bot-auth-composition-auth")?;
    wait_for_policy_convergence("web-bot-auth-composition-quota")
}

fn apply_rate_policy(path: &str, replicas: u16) -> Result<(), String> {
    apply_file(path)?;
    wait_for_backend_policy_convergence("web-bot-auth-composition-quota")?;
    restart_gateway(Some(replicas))
}

fn gateway_deployment() -> Result<String, String> {
    gateway_deployment_with_deadline(Instant::now() + Duration::from_secs(180))
}

fn gateway_deployment_with_deadline(deadline: Instant) -> Result<String, String> {
    let deployment = kubectl_with_timeout(
        &[
            "get",
            "deployment",
            "--namespace",
            EG_NAMESPACE,
            "--selector",
            SELECTOR,
            "--output",
            "jsonpath={.items[0].metadata.name}",
        ],
        deadline.saturating_duration_since(Instant::now()),
        "gateway_deployment_lookup_failed",
    )?;
    if deployment.is_empty() {
        Err("gateway_deployment_missing".into())
    } else {
        Ok(deployment)
    }
}

fn gateway_pods() -> Result<Vec<String>, String> {
    let pods = kubectl(&[
        "get",
        "pods",
        "--namespace",
        EG_NAMESPACE,
        "--selector",
        SELECTOR,
        "--field-selector=status.phase=Running",
        "--output",
        "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
    ])?;
    let pods = pods
        .lines()
        .filter_map(|pod| {
            let deleting = kubectl(&[
                "get",
                "pod",
                "--namespace",
                EG_NAMESPACE,
                pod,
                "--output",
                "jsonpath={.metadata.deletionTimestamp}",
            ])
            .ok()?;
            deleting.is_empty().then(|| pod.to_owned())
        })
        .collect::<Vec<_>>();
    if pods.is_empty() {
        Err("gateway_pods_missing".into())
    } else {
        Ok(pods)
    }
}

pub(crate) fn wait_for_gateway_pods(count: usize) -> Result<(), String> {
    wait_until(Duration::from_secs(180), "gateway_pods_not_ready", || {
        Ok(gateway_pods()
            .map(|pods| pods.len() == count)
            .unwrap_or(false))
    })
}

pub(crate) fn wait_for_deployment_replicas(
    namespace: &str,
    deployment: &str,
    expected: u64,
) -> Result<(), String> {
    wait_for_deployment_ready_with_deadline(
        namespace,
        deployment,
        Some(expected),
        Instant::now() + Duration::from_secs(180),
        "deployment_replicas_not_ready",
    )
}

fn redis_pod() -> Result<String, String> {
    let pod = kubectl(&[
        "get",
        "pod",
        "--namespace",
        "web-bot-auth-rate-limit",
        "--selector",
        "app=redis",
        "--output",
        "jsonpath={.items[0].metadata.name}",
    ])?;
    if pod.is_empty() {
        Err("redis_pod_missing".into())
    } else {
        Ok(pod)
    }
}

fn flush_redis() -> Result<(), String> {
    let pod = redis_pod()?;
    kubectl(&[
        "exec",
        "--namespace",
        "web-bot-auth-rate-limit",
        &pod,
        "--",
        "redis-cli",
        "FLUSHALL",
    ])?;
    Ok(())
}

fn rate_limit_deployment() -> Result<String, String> {
    let deployments = kubectl(&[
        "get",
        "deployment",
        "--namespace",
        EG_NAMESPACE,
        "--output",
        "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
    ])?;
    deployments
        .lines()
        .find(|name| name.to_ascii_lowercase().contains("ratelimit"))
        .map(str::to_owned)
        .ok_or("rate_limit_deployment_missing".into())
}

fn restart_gateway(replicas: Option<u16>) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(180);
    let deployment = gateway_deployment()?;
    if let Some(replicas) = replicas {
        kubectl(&[
            "scale",
            "deployment",
            &deployment,
            "--namespace",
            EG_NAMESPACE,
            &format!("--replicas={replicas}"),
        ])?;
    }
    restart_rollout_with_deadline(&deployment, deadline)?;
    wait_for_deployment_ready_with_deadline(
        EG_NAMESPACE,
        &deployment,
        replicas.map(u64::from),
        deadline,
        "gateway_rollout_failed",
    )?;
    if let Some(replicas) = replicas {
        wait_for_gateway_pods(replicas as usize)?;
    }
    Ok(())
}

fn resolver_pod() -> Result<String, String> {
    resolver_pod_identity().map(|(name, _)| name)
}

fn resolver_pod_identity() -> Result<(String, String), String> {
    let mut identity = None;
    wait_until(
        Duration::from_secs(60),
        "fixture_resolver_pod_missing",
        || {
            identity = find_resolver_pod_identity()?;
            Ok(identity.is_some())
        },
    )?;
    identity.ok_or_else(|| "fixture_resolver_pod_missing".into())
}

fn find_resolver_pod_identity() -> Result<Option<(String, String)>, String> {
    let pods = kubectl(&[
        "get",
        "pods",
        "--namespace",
        EG_NAMESPACE,
        "--selector",
        SELECTOR,
        "--field-selector=status.phase=Running",
        "--output",
        "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
    ])?;
    for pod in pods.lines() {
        let deleting = kubectl(&[
            "get",
            "pod",
            "--namespace",
            EG_NAMESPACE,
            pod,
            "--output",
            "jsonpath={.metadata.deletionTimestamp}",
        ])?;
        if !deleting.is_empty() {
            continue;
        }
        if kubectl(&[
            "wait",
            "--namespace",
            EG_NAMESPACE,
            "--for=condition=Ready",
            &format!("pod/{pod}"),
            "--timeout=5s",
        ])
        .is_err()
        {
            continue;
        }
        let mut command = Command::new("kubectl");
        command.arg("--kubeconfig").arg(kubeconfig()).args([
            "exec",
            "--namespace",
            EG_NAMESPACE,
            pod,
            "--container",
            "web-bot-auth-resolver",
            "--",
            "/web-bot-auth-resolver",
            "probe",
            "--socket=/run/wba/resolver.sock",
            "--timeout-ms=250",
        ]);
        let status = run_command(command, Duration::from_secs(5), "resolver_probe_failed")
            .ok()
            .is_some_and(|output| output.status.success());
        if status {
            let uid = kubectl(&[
                "get",
                "pod",
                "--namespace",
                EG_NAMESPACE,
                pod,
                "--output",
                "jsonpath={.metadata.uid}",
            ])?;
            if !uid.is_empty() {
                return Ok(Some((pod.to_owned(), uid)));
            }
        }
    }
    Ok(None)
}

pub(crate) fn resolver_restart_count(pod: &str) -> Result<u64, String> {
    let document = kubectl(&[
        "get",
        "pod",
        "--namespace",
        EG_NAMESPACE,
        pod,
        "--output",
        "json",
    ])?;
    let document = serde_json::from_str::<serde_json::Value>(&document)
        .map_err(|_| "resolver_pod_json_invalid".to_owned())?;
    document
        .get("status")
        .and_then(|status| status.get("containerStatuses"))
        .and_then(serde_json::Value::as_array)
        .and_then(|containers| {
            containers.iter().find(|container| {
                container.get("name").and_then(serde_json::Value::as_str)
                    == Some("web-bot-auth-resolver")
            })
        })
        .and_then(|container| container.get("restartCount"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "resolver_restart_count_missing".into())
}

pub(crate) fn restart_resolver_container(pod: &str) -> Result<(), String> {
    let status = Command::new("kubectl")
        .arg("--kubeconfig")
        .arg(kubeconfig())
        .args([
            "debug",
            &format!("pod/{pod}"),
            "--namespace",
            EG_NAMESPACE,
            "--target=web-bot-auth-resolver",
            "--image=busybox:1.37.0",
            "--profile=general",
            "--",
            "sh",
            "-c",
            "kill -TERM 1",
        ])
        .status()
        .map_err(|_| "resolver_debug_start_failed".to_owned())?;
    if status.success() {
        Ok(())
    } else {
        record_failure(
            "resolver_container_restart_failed",
            "the debug container could not signal the resolver process",
        );
        Err("resolver_container_restart_failed".into())
    }
}

pub(crate) fn wait_for_resolver_restart(pod: &str, previous_count: u64) -> Result<(), String> {
    wait_until(
        Duration::from_secs(180),
        "resolver_container_restart_not_observed",
        || {
            let count = match resolver_restart_count(pod) {
                Ok(count) => count,
                Err(_) => return Ok(false),
            };
            if count <= previous_count {
                return Ok(false);
            }
            Ok(Command::new("kubectl")
                .arg("--kubeconfig")
                .arg(kubeconfig())
                .args([
                    "exec",
                    "--namespace",
                    EG_NAMESPACE,
                    pod,
                    "--container",
                    "web-bot-auth-resolver",
                    "--",
                    "/web-bot-auth-resolver",
                    "probe",
                    "--socket=/run/wba/resolver.sock",
                    "--timeout-ms=250",
                ])
                .status()
                .is_ok_and(|status| status.success()))
        },
    )
}

pub(crate) fn reset_fixture(mode: &str) -> Result<(), String> {
    let mut pod = String::new();
    wait_until(
        Duration::from_secs(60),
        "fixture_resolver_not_ready",
        || match resolver_pod() {
            Ok(value) => {
                pod = value;
                Ok(true)
            }
            Err(_) => Ok(false),
        },
    )?;
    let status = Command::new("kubectl")
        .arg("--kubeconfig")
        .arg(kubeconfig())
        .args([
            "exec",
            "--namespace",
            EG_NAMESPACE,
            &pod,
            "--container",
            "web-bot-auth-resolver",
            "--",
            "/web-bot-auth-resolver",
            "fixture-control",
            "--socket=/run/wba/resolver.sock",
            "--mode",
            mode,
            "--reset=true",
            "--timeout-ms=500",
        ])
        .status()
        .map_err(|_| "fixture_control_start_failed".to_owned())?;
    status.success().then_some(()).ok_or_else(|| {
        record_failure("fixture_control_failed", "fixture control command failed");
        "fixture_control_failed".into()
    })
}

fn service() -> Result<String, String> {
    let service = kubectl(&[
        "get",
        "service",
        "--namespace",
        EG_NAMESPACE,
        "--selector",
        SELECTOR,
        "--output",
        "jsonpath={.items[0].metadata.name}",
    ])?;
    if service.is_empty() {
        Err("gateway_service_missing".into())
    } else {
        Ok(service)
    }
}

fn spawn_forward(
    target: &str,
    remote_port: u16,
    start_error: &'static str,
) -> Result<PortForward, String> {
    let output = Arc::new(Mutex::new(String::new()));
    let mut child = Command::new("kubectl")
        .arg("--kubeconfig")
        .arg(kubeconfig())
        .args([
            "port-forward",
            "--namespace",
            EG_NAMESPACE,
            target,
            &format!("0:{remote_port}"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| start_error.to_owned())?;
    if let Some(stdout) = child.stdout.take() {
        capture_forward_output(stdout, Arc::clone(&output));
    }
    if let Some(stderr) = child.stderr.take() {
        capture_forward_output(stderr, Arc::clone(&output));
    }
    Ok(PortForward {
        child,
        local_port: 0,
        output,
    })
}

async fn start_forward() -> Result<PortForward, String> {
    let service = service()?;
    let mut forward = spawn_forward(
        &format!("service/{service}"),
        80,
        "port_forward_start_failed",
    )?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| "port_forward_client_failed".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(port) = reported_forward_port(&forward.output()) {
            forward.local_port = port;
            if let Ok(response) = client.get(format!("{BASE_URL}:{port}/")).send().await
                && READY_STATUSES.contains(&response.status().as_u16())
            {
                return Ok(forward);
            }
        }
        if forward.child.try_wait().ok().flatten().is_some() {
            let output = forward.output();
            record_failure("port_forward_exited", &output);
            return Err("port_forward_exited".into());
        }
        if Instant::now() >= deadline {
            let output = forward.output();
            record_failure("port_forward_not_ready", &output);
            return Err("port_forward_not_ready".into());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn status(port: u16, headers: &[(&str, &str)]) -> Result<reqwest::Response, String> {
    status_at(port, "/", headers).await
}

async fn status_at(
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<reqwest::Response, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| "request_client_failed".to_owned())?;
    let mut request = client.get(format!("{BASE_URL}:{port}{path}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request
        .send()
        .await
        .map_err(|_| "gateway_request_failed".to_owned())
}

async fn start_pod_forward(pod: &str) -> Result<PortForward, String> {
    let mut forward = spawn_forward(
        &format!("pod/{pod}"),
        10080,
        "pod_port_forward_start_failed",
    )?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| "request_client_failed".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(port) = reported_forward_port(&forward.output()) {
            forward.local_port = port;
            if let Ok(response) = client.get(format!("{BASE_URL}:{port}/")).send().await
                && READY_STATUSES.contains(&response.status().as_u16())
            {
                return Ok(forward);
            }
        }
        if forward.child.try_wait().ok().flatten().is_some() {
            let output = forward.output();
            record_failure("pod_port_forward_exited", &output);
            return Err("pod_port_forward_exited".into());
        }
        if Instant::now() >= deadline {
            let output = forward.output();
            record_failure("pod_port_forward_not_ready", &output);
            return Err("pod_port_forward_not_ready".into());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn assert_client_assertions_are_removed(port: u16, mode: Mode) -> Result<(), String> {
    let response = status(
        port,
        &[
            ("x-web-bot-auth-status", "verified"),
            ("x-web-bot-auth-identity", "https://attacker.invalid"),
            ("x-web-bot-auth-keyid", "attacker-key"),
        ],
    )
    .await?;
    if matches!(mode, Mode::Required) {
        if response.status().as_u16() != 403 {
            return Err("forged_header_status_mismatch".into());
        }
        return Ok(());
    }
    let body = response
        .text()
        .await
        .map_err(|_| "forged_header_body_failed".to_owned())?;
    let body: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| "forged_header_body_invalid".to_owned())?;
    if body.get("status").and_then(serde_json::Value::as_str) != Some("not-present")
        || body.get("identity").and_then(serde_json::Value::as_str) != Some("")
        || body.get("key_id").and_then(serde_json::Value::as_str) != Some("")
    {
        return Err("forged_header_forwarded".into());
    }
    Ok(())
}

fn signed_status(port: u16, expected: u16, key: &str, extra: &[&str]) -> Result<(), String> {
    signed_status_at(
        port,
        "/",
        key,
        "https://fixture.web-bot-auth.test",
        expected,
        extra,
    )
}

fn signed_status_checked(
    port: u16,
    expected: ExpectedResponse,
    key: &str,
    extra: &[&str],
) -> Result<(), String> {
    signed_status_at_checked(
        port,
        "/",
        key,
        "https://fixture.web-bot-auth.test",
        expected,
        extra,
    )
}

fn signed_status_at(
    port: u16,
    path: &str,
    key: &str,
    agent: &str,
    expected: u16,
    extra: &[&str],
) -> Result<(), String> {
    signed_status_at_checked(
        port,
        path,
        key,
        agent,
        ExpectedResponse {
            status: expected,
            challenge: false,
            trusted_status: "",
            identity: None,
            key_id: None,
            client_assertion_absent: false,
        },
        extra,
    )
}

fn signed_status_at_checked(
    port: u16,
    path: &str,
    key: &str,
    agent: &str,
    expected: ExpectedResponse,
    extra: &[&str],
) -> Result<(), String> {
    let mut command = Command::new("cargo");
    let url = format!("{BASE_URL}:{port}{path}");
    let expected_status = expected.status.to_string();
    let key = repository_path(key);
    command.args([
        "run",
        "--quiet",
        "--features",
        "kind-fixtures",
        "--bin",
        "wba-kind-request",
        "--",
        "--url",
        &url,
        "--key",
        key.to_str().ok_or("fixture_key_path_invalid")?,
        "--agent",
        agent,
        "--expect-status",
        &expected_status,
    ]);
    if !expected.trusted_status.is_empty() {
        command.args(["--expect-trusted-status", expected.trusted_status]);
        if let Some(identity) = expected.identity {
            command.args(["--expect-identity", identity]);
        }
        if let Some(key_id) = expected.key_id {
            command.args(["--expect-key-id", key_id]);
        }
        if expected.client_assertion_absent {
            command.arg("--expect-client-assertions-absent");
        }
    }
    command.args(extra);
    command
        .status()
        .map_err(|_| "signed_request_start_failed".to_owned())?
        .success()
        .then_some(())
        .ok_or("signed_request_failed".into())
}

#[cfg(test)]
mod tests {
    use super::{
        deployment_is_ready, reported_forward_port, rollout_restart_was_triggered_too_soon,
    };

    fn deployment(
        generation: u64,
        observed_generation: u64,
        replicas: u64,
        available: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "metadata": {"generation": generation},
            "spec": {"replicas": replicas},
            "status": {
                "observedGeneration": observed_generation,
                "availableReplicas": available,
                "replicas": replicas,
                "updatedReplicas": replicas
            }
        })
    }

    #[test]
    fn parses_kubectl_forward_port() {
        assert_eq!(
            reported_forward_port("Forwarding from 127.0.0.1:43127 -> 80\n"),
            Some(43127)
        );
    }

    #[test]
    fn ignores_unusable_forward_output() {
        assert_eq!(reported_forward_port("Handling connection for 0\n"), None);
        assert_eq!(
            reported_forward_port("Forwarding from 127.0.0.1:0 -> 80\n"),
            None
        );
    }

    #[test]
    fn recognizes_only_the_rollout_restart_rate_guard() {
        assert!(rollout_restart_was_triggered_too_soon(
            "error: failed to create patch for deployment/web-bot-auth: if restart has already been triggered within the past second, please wait before attempting to trigger another\n"
        ));
        assert!(!rollout_restart_was_triggered_too_soon(
            "error: failed to create patch for deployment/web-bot-auth: the object has been modified\n"
        ));
        assert!(!rollout_restart_was_triggered_too_soon(
            "error: failed to create patch for deployment/web-bot-auth: if restart has already been triggered within the past second, please wait before attempting to trigger another\nextra detail\n"
        ));
        assert!(!rollout_restart_was_triggered_too_soon(
            "Error from server: if restart has already been triggered within the past second, please wait before attempting to trigger another\n"
        ));
    }

    #[test]
    fn deployment_readiness_uses_observed_generation_and_desired_replicas() {
        assert!(deployment_is_ready(&deployment(4, 4, 2, 2), None));
        assert!(!deployment_is_ready(&deployment(4, 3, 2, 2), None));
        assert!(!deployment_is_ready(&deployment(4, 4, 2, 1), None));
    }

    #[test]
    fn deployment_readiness_rejects_stale_replica_count() {
        let mut document = deployment(4, 4, 2, 2);
        document["status"]["replicas"] = serde_json::json!(1);
        assert!(!deployment_is_ready(&document, None));
    }

    #[test]
    fn deployment_readiness_rejects_incomplete_updated_replicas() {
        let mut document = deployment(4, 4, 2, 2);
        document["status"]["updatedReplicas"] = serde_json::json!(1);
        assert!(!deployment_is_ready(&document, None));
    }

    #[test]
    fn deployment_readiness_checks_explicit_scale_target() {
        assert!(deployment_is_ready(&deployment(4, 4, 1, 1), Some(1)));
        assert!(!deployment_is_ready(&deployment(4, 4, 2, 2), Some(1)));
        assert!(!deployment_is_ready(&deployment(4, 3, 1, 1), Some(1)));
    }

    #[test]
    fn zero_scale_accepts_omitted_status_counts() {
        let mut document = deployment(4, 4, 0, 0);
        let status = document["status"]
            .as_object_mut()
            .expect("test deployment status is an object");
        status.remove("replicas");
        status.remove("updatedReplicas");
        status.remove("availableReplicas");

        assert!(deployment_is_ready(&document, Some(0)));
    }
}
