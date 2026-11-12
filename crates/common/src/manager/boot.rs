/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{backup::BackupParams, console::store_console, sandbox::SandboxPaths};
use crate::{
    BuildServer, Caches, Core, Data, IPC_CHANNEL_BUFFER, Inner, Ipc,
    config::{
        network::AsnGeoLookupConfig,
        server::{Listeners, listener::recovery_mode_port},
        storage::Storage,
        telemetry::Telemetry,
    },
    ipc::{BroadcastEvent, PushEvent, QueueEvent, ReportingEvent, TrainTaskController},
    manager::defaults::BootstrapDefaults,
};
use arc_swap::ArcSwap;
use compact_str::CompactString;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
};
use store::{RegistryStore, registry::bootstrap::Bootstrap};
use tokio::sync::{Notify, mpsc};
use utils::{UnwrapFailure, failed, runtime};

pub struct BootManager {
    pub bootstrap: Bootstrap,
    pub inner: Arc<Inner>,
    pub servers: Listeners,
    pub ipc_rxs: IpcReceivers,
    /// OpenBSD 沙箱（其它平台上是空操作）
    pub sandbox: SandboxPaths,
}

pub struct IpcReceivers {
    pub push_rx: Option<mpsc::Receiver<PushEvent>>,
    pub queue_rx: Option<mpsc::Receiver<QueueEvent>>,
    pub report_rx: Option<mpsc::Receiver<ReportingEvent>>,
    pub broadcast_rx: Option<mpsc::Receiver<BroadcastEvent>>,
}

const HELP: &str = concat!(
    "Stalwart Server v",
    env!("CARGO_PKG_VERSION"),
    r#"

Usage: stalwart [OPTIONS]

Options:
  -c, --config <PATH>              Start server with the specified configuration file
  -e, --export <PATH>              Export all store data to a specific path
  -i, --import <PATH>              Import store data from a specific path
  -o, --console                    Open the store console
  --sandbox-check                  Verify that the OpenBSD sandbox (unveil/pledge) applies
  -h, --help                       Print help
  -V, --version                    Print version
"#
);

#[derive(PartialEq, Eq)]
enum StoreOp {
    Export(BackupParams),
    Import(PathBuf),
    Console,
    None,
}

impl BootManager {
    pub async fn init() -> Self {
        let mut config_path = std::env::var("CONFIG_PATH").ok();
        let mut import_export = StoreOp::None;

        if config_path.is_none() {
            let mut args = std::env::args().skip(1);

            while let Some(arg) = args.next().and_then(|arg| {
                arg.strip_prefix("--")
                    .or_else(|| arg.strip_prefix('-'))
                    .map(|arg| arg.to_string())
            }) {
                let (key, value) = if let Some((key, value)) = arg.split_once('=') {
                    (key.to_string(), Some(value.trim().to_string()))
                } else {
                    (arg, args.next())
                };

                match (key.as_str(), value) {
                    ("help" | "h", _) => {
                        eprintln!("{HELP}");
                        std::process::exit(0);
                    }
                    ("version" | "V", _) => {
                        println!("{}", env!("CARGO_PKG_VERSION"));
                        std::process::exit(0);
                    }
                    ("config" | "c", Some(value)) => {
                        config_path = Some(value);
                    }
                    ("export" | "e", Some(value)) => {
                        import_export = StoreOp::Export(BackupParams::new(value.into()));
                    }
                    ("import" | "i", Some(value)) => {
                        import_export = StoreOp::Import(value.into());
                    }
                    ("console" | "o", None) => {
                        import_export = StoreOp::Console;
                    }
                    (_, None) => {
                        failed(&format!("Unrecognized command '{key}', try '--help'."));
                    }
                    (_, Some(_)) => failed(&format!(
                        "Missing value for argument '{key}', try '--help'."
                    )),
                }
            }

            if config_path.is_none() {
                if import_export == StoreOp::None {
                    eprintln!("{HELP}");
                } else {
                    eprintln!("Missing '--config' argument for import/export.")
                }
                std::process::exit(0);
            }
        }

        // OpenBSD 沙箱第一步：chroot（可选）。必须在读配置文件、打开存储之前，
        // 因为 chroot 之后 `-c` 和配置里的所有路径都按 **jail 内** 的绝对路径解释
        // （宿主的 -c 路径在 jail 里不存在）。store 是在 RegistryStore::init 里打开的，
        // 所以 chroot 不能晚于它，否则会拿宿主路径去开 jail 内的库。
        let mut sandbox = SandboxPaths::from_env();
        if import_export == StoreOp::None && sandbox.is_enabled() {
            if let Err(err) = sandbox.enter_chroot() {
                failed(&format!("OpenBSD sandbox: {err}"));
            }
        }

        // 配置文件所在目录：运行时改配置会写回这里，沙箱要放行。
        // 配置路径本身可以是相对路径（相对启动 cwd），这里统一解析成绝对路径，
        // 否则会被后面「只接受绝对路径」的过滤丢掉。
        let config_dir = config_path.as_deref().and_then(|path| {
            let parent = std::path::Path::new(path).parent()?;
            let parent = if parent.as_os_str().is_empty() {
                std::path::Path::new(".")
            } else {
                parent
            };
            let absolute = if parent.is_absolute() {
                parent.to_path_buf()
            } else {
                std::env::current_dir().ok()?.join(parent)
            };
            Some(absolute.to_string_lossy().into_owned())
        });

        // Initialize registry
        let registry = RegistryStore::init(
            PathBuf::from(config_path.unwrap()),
            import_export == StoreOp::None,
        )
        .await
        .failed("⚠️ Startup failed");
        let mut bootstrap = Bootstrap::new(registry).await;

        // Add safe defaults if missing
        if import_export == StoreOp::None {
            bootstrap.insert_safe_defaults().await;
        }

        // OpenBSD 沙箱第二步：按组件登记各自的目录，然后 unveil 并锁定。
        // 必须在绑定端口、放弃 root 权限之前完成；chroot 已在上面做过。
        if import_export == StoreOp::None && sandbox.is_enabled() {
            collect_sandbox_paths(&mut bootstrap, config_dir.as_deref(), &mut sandbox).await;
            if let Err(err) = sandbox.lock_filesystem() {
                failed(&format!("OpenBSD sandbox: {err}"));
            }
            eprintln!("OpenBSD sandbox: {}", sandbox.describe());
        }

        // Start listeners
        let mut servers = Listeners::parse(&mut bootstrap).await;
        servers.bind_and_drop_priv(&mut bootstrap);

        // Parse storage
        let storage = Storage::parse(&mut bootstrap).await;
        let (ipc, ipc_rxs) = build_ipc(!storage.coordinator.is_none());

        // Parse telemetry
        let telemetry = Telemetry::parse(&mut bootstrap, &storage, ipc.index_queue_notify()).await;

        match import_export {
            StoreOp::None => {
                // Parse components
                let core = Core::parse(&mut bootstrap, storage).await;
                let data = Data::parse(&mut bootstrap).await;
                let (cache, swap_rx) = Caches::parse(&mut bootstrap, &core.storage).await;

                // Enable telemetry

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                telemetry.enable(core.is_enterprise_edition());
                // SPDX-SnippetEnd

                #[cfg(not(feature = "enterprise"))]
                telemetry.enable(false);

                if bootstrap.registry.is_bootstrap_mode() {
                    trc::event!(
                        Server(trc::ServerEvent::BootstrapMode),
                        Hostname = CompactString::from(bootstrap.registry.local_hostname()),
                        Details = format!(
                            "No configuration file was found. Port {} is open for initial setup.",
                            recovery_mode_port()
                        ),
                        Version = env!("CARGO_PKG_VERSION"),
                    );
                } else if bootstrap.registry.is_recovery_mode() {
                    trc::event!(
                        Server(trc::ServerEvent::RecoveryMode),
                        Details = format!(
                            "Port {} is open for troubleshooting and recovery.",
                            recovery_mode_port()
                        ),
                        Hostname = CompactString::from(bootstrap.registry.local_hostname()),
                        Version = env!("CARGO_PKG_VERSION"),
                    );
                } else {
                    trc::event!(
                        Server(trc::ServerEvent::Startup),
                        Hostname = CompactString::from(bootstrap.registry.local_hostname()),
                        Version = env!("CARGO_PKG_VERSION"),
                    );
                }

                if core.storage.coordinator.is_enabled() {
                    trc::event!(
                        Cluster(trc::ClusterEvent::Startup),
                        NodeId = bootstrap.registry.node_id(),
                        Type = CompactString::from(
                            bootstrap.registry.cluster_role().unwrap_or("[default]")
                        ),
                        Details = bootstrap.registry.cluster_push_shard()
                    );
                }

                // Build shared inner
                let has_remote_asn = matches!(
                    core.network.asn_geo_lookup,
                    AsnGeoLookupConfig::Resource { .. }
                );
                let inner = Arc::new(Inner {
                    shared_core: ArcSwap::new(Arc::from(core)),
                    data,
                    ipc,
                    cache,
                });

                if !bootstrap.registry.is_recovery_mode() {
                    // Start the cache swap tier writer
                    crate::cache::swap::SwapTier::start(&inner, swap_rx);

                    // Load spam model
                    if let Err(err) = inner.build_server().spam_model_reload().await {
                        trc::error!(
                            err.details("Failed to load spam filter model")
                                .caused_by(trc::location!())
                        );
                    }

                    // Fetch ASN database
                    if has_remote_asn {
                        inner
                            .build_server()
                            .lookup_asn_country(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
                            .await;
                    }
                }

                // Parse TCP acceptors
                servers
                    .parse_tcp_acceptors(&mut bootstrap, inner.clone())
                    .await;

                // OpenBSD 沙箱第二步：端口已绑定、权限已放弃，上 pledge
                if let Err(err) = sandbox.apply_pledge() {
                    failed(&format!("OpenBSD sandbox: {err}"));
                }

                BootManager {
                    inner,
                    bootstrap,
                    servers,
                    ipc_rxs,
                    sandbox,
                }
            }
            StoreOp::Export(path) => {
                // Enable telemetry
                telemetry.enable(false);

                // Parse settings and backup
                Core::parse(&mut bootstrap, storage)
                    .await
                    .backup(path)
                    .await;
                drop(bootstrap);
                runtime::exit(0);
            }
            StoreOp::Import(path) => {
                // Enable telemetry
                telemetry.enable(false);

                // Parse settings and restore
                Core::parse(&mut bootstrap, storage)
                    .await
                    .restore(path)
                    .await;
                drop(bootstrap);
                runtime::exit(0);
            }
            StoreOp::Console => {
                // Store console
                store_console(Core::parse(&mut bootstrap, storage).await.storage.data).await;
                drop(bootstrap);
                runtime::exit(0);
            }
        }
    }
}

/// 按组件收集 OpenBSD 沙箱需要的路径。
///
/// 只登记“运行时会写入”的位置：各存储后端、cache swap、tracer 日志、ACME 工作目录、
/// 配置文件所在目录，外加 /tmp。其余位置在沙箱里一律只读（unveil "/" r），
/// 因为配置里的路径可以是任意位置，逐个枚举并不现实。
async fn collect_sandbox_paths(
    bp: &mut Bootstrap,
    config_dir: Option<&str>,
    sandbox: &mut SandboxPaths,
) {
    use registry::schema::structs as cfg;

    // 注意：不要读 cfg::Bootstrap —— 它是 OBJ_NOT_STORED（只在 API 层出现、不落库），
    // 运行时读出来永远是默认值，等于什么都没收集到。要按组件一个个读：
    // DataStore 走 RegistryStore::get 对 ObjectType::DataStore 的特殊分支（读配置文件），
    // BlobStore / SearchStore 是 OBJ_SINGLETON 落库对象，Tracer 是列表对象。
    match bp.setting_infallible::<cfg::DataStore>().await {
        cfg::DataStore::RocksDb(store) => sandbox.allow_write(&store.path),
        cfg::DataStore::Sqlite(store) => sandbox.allow_write(&store.path),
        _ => {}
    }
    if let cfg::BlobStore::FileSystem(store) = bp.setting_infallible::<cfg::BlobStore>().await {
        sandbox.allow_write(&store.path);
    }
    // 企业版的 BlobStore::Sharded 可以带多个 FileSystem 分片（每个分片一个目录）；
    // 只登记顶层变体会把分片目录漏掉，写 blob 时就 EACCES。
    #[cfg(feature = "enterprise")]
    if let cfg::BlobStore::Sharded(sharded) = bp.setting_infallible::<cfg::BlobStore>().await {
        for base in sharded.stores.iter() {
            if let cfg::BlobStoreBase::FileSystem(store) = base {
                sandbox.allow_write(&store.path);
            }
        }
    }
    // 搜索后端（Elasticsearch / Meilisearch / SQL / FoundationDB）都是网络服务，没有本地路径
    for tracer in bp.list_infallible::<cfg::Tracer>().await {
        if let cfg::Tracer::Log(tracer) = &tracer.object {
            sandbox.allow_write(&tracer.path);
        }
    }

    // cache 的本地溢出目录。
    // 注意：CacheSwap::BlobStore 用的是 BlobSwapStore，v1.1.0 里它没有 FileSystem
    // 变体（只有 Default/S3/Azure/FoundationDb/SQL），本地文件系统只能通过
    // CacheSwap::LocalFile。
    let cache = bp.setting_infallible::<cfg::Cache>().await;
    if let cfg::CacheSwap::LocalFile(swap) = &cache.swap {
        sandbox.allow_write(&swap.path);
    }

    // 目录（认证）后端里用 SQLite 的
    for directory in bp.list_infallible::<cfg::Directory>().await {
        if let cfg::Directory::Sql(sql) = &directory.object {
            if let cfg::SqlAuthStore::Sqlite(store) = &sql.store {
                sandbox.allow_write(&store.path);
            }
        }
    }

    // store 型 lookup（HTTP/webhook 之外的那类）里用 SQLite 的
    for lookup in bp.list_infallible::<cfg::StoreLookup>().await {
        if let cfg::LookupStore::Sqlite(store) = &lookup.object.store {
            sandbox.allow_write(&store.path);
        }
    }

    // v1.1.0 的 Keep 协调器可以引用本地 TLS 文件（集群 mTLS）：
    // 这些是只读路径，但要能读到（严格模式下尤其重要）。
    if let cfg::Coordinator::Keep(keep) = bp.setting_infallible::<cfg::Coordinator>().await {
        match &keep.tls {
            cfg::KeepTls::Authority(auth) => {
                sandbox.allow_read(&auth.ca_path);
                sandbox.allow_read(&auth.cert_path);
                sandbox.allow_read(&auth.key_path);
            }
            cfg::KeepTls::RawPublicKeys(keys) => {
                sandbox.allow_read(&keys.key_path);
                sandbox.allow_read(&keys.server_keys_path);
            }
            cfg::KeepTls::Disabled => {}
        }
    }

    // WebUI 包会解压到 unpackDirectory（未配置时落在临时目录）
    for app in bp.list_infallible::<cfg::Application>().await {
        if let Some(dir) = &app.object.unpack_directory {
            sandbox.allow_write(dir);
        }
    }

    // 注意：AcmeProvider.directory 是 ACME 服务端的 **URL**
    // （如 https://acme-v02.api.letsencrypt.org/directory），不是本地目录。
    // ACME 的账户/证书都存进 data/blob store，所以这里不该登记任何路径。

    // 配置里还有一批「值可以写成 @type: File」的密钥/证书字段
    // （DKIM 私钥、TLS 证书与私钥、OIDC 签名密钥、DNS TSIG 密钥、
    //  JMAP WebPush 密钥、NATS 凭据、FoundationDB 的 cluster 文件）。
    // 默认策略下读本来就不受限，这些登记是给 STALWART_UNVEIL_STRICT=on 用的；
    // 严格模式下漏登记会让对应功能在运行时读不到文件。
    // 注意这是**显式枚举**：没有统一的扫描接口，以后新增这类字段要在这里补一行。
    for signature in bp.list_infallible::<cfg::DkimSignature>().await {
        if let cfg::SecretText::File(file) = signature.object.private_key() {
            sandbox.allow_read(&file.file_path);
        }
    }
    for cert in bp.list_infallible::<cfg::Certificate>().await {
        if let cfg::PublicText::File(file) = &cert.object.certificate {
            sandbox.allow_read(&file.file_path);
        }
        if let cfg::SecretText::File(file) = &cert.object.private_key {
            sandbox.allow_read(&file.file_path);
        }
    }
    let oidc = bp.setting_infallible::<cfg::OidcProvider>().await;
    if let cfg::SecretText::File(file) = &oidc.signature_key {
        sandbox.allow_read(&file.file_path);
    }
    if let cfg::SecretKey::File(file) = &oidc.encryption_key {
        sandbox.allow_read(&file.file_path);
    }
    for server in bp.list_infallible::<cfg::DnsServer>().await {
        // 只有 TSIG 用本地文件；其余服务商是 API 凭据，走 Value/Env。
        if let cfg::DnsServer::Tsig(tsig) = &server.object
            && let cfg::SecretKey::File(file) = &tsig.key
        {
            sandbox.allow_read(&file.file_path);
        }
    }
    let jmap = bp.setting_infallible::<cfg::Jmap>().await;
    if let cfg::SecretTextOptional::File(file) = &jmap.web_push_key {
        sandbox.allow_read(&file.file_path);
    }
    if let cfg::Coordinator::Nats(nats) = bp.setting_infallible::<cfg::Coordinator>().await {
        if let cfg::SecretKeyOptional::File(file) = &nats.auth_secret {
            sandbox.allow_read(&file.file_path);
        }
        if let cfg::SecretTextOptional::File(file) = &nats.credentials {
            sandbox.allow_read(&file.file_path);
        }
    }
    // FoundationDB 的 cluster_file 是本地路径（集群描述文件）
    if let cfg::DataStore::FoundationDb(store) = bp.setting_infallible::<cfg::DataStore>().await
        && let Some(file) = &store.cluster_file
    {
        sandbox.allow_read(file);
    }
    if let cfg::BlobStore::FoundationDb(store) = bp.setting_infallible::<cfg::BlobStore>().await
        && let Some(file) = &store.cluster_file
    {
        sandbox.allow_read(file);
    }

    if let Some(dir) = config_dir {
        sandbox.allow_write(dir);
    }

    // 临时文件（std::env::temp_dir()，尊重 TMPDIR）与 unix socket
    sandbox.allow_write(std::env::temp_dir().to_string_lossy());
    sandbox.allow_read("/etc/ssl");

    // 一个写路径都没收集到说明配置没读出来，运行时会到处 EACCES，直接说清楚
    if sandbox.write_paths().is_empty() {
        eprintln!(
            "OpenBSD sandbox: warning: no writable path was collected from the configuration, \
             runtime writes will likely fail. Set STALWART_UNVEIL_EXTRA=\"/your/data:rwc\" \
             or STALWART_SANDBOX=off."
        );
    }
}

pub fn build_ipc(has_pubsub: bool) -> (Ipc, IpcReceivers) {
    // Build ipc receivers
    let (push_tx, push_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (queue_tx, queue_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (report_tx, report_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (broadcast_tx, broadcast_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    (
        Ipc {
            push_tx,
            push_subscribers: Default::default(),
            queue_tx,
            report_tx,
            broadcast_tx: has_pubsub.then_some(broadcast_tx),
            task_tx: Default::default(),
            index_tx: Arc::new(Notify::new()),
            train_task_controller: Arc::new(TrainTaskController::default()),
        },
        IpcReceivers {
            push_rx: Some(push_rx),
            queue_rx: Some(queue_rx),
            report_rx: Some(report_rx),
            broadcast_rx: has_pubsub.then_some(broadcast_rx),
        },
    )
}
