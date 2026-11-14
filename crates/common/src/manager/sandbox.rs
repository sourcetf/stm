//! OpenBSD 沙箱：unveil(2) + pledge(2)，以及可选的 chroot(2)。
//!
//! 路径不是一份全局配置，而是由各组件在启动时登记自己的目录（见
//! `BootManager` 里对 data/blob/search 存储、cache swap、tracer 日志、
//! ACME 工作目录的收集）。默认对整个文件系统只给读权限——配置里的路径可以
//! 是任意位置，逐个枚举并不现实；写权限只给上面登记过的目录。
//!
//! 环境变量：
//!   STALWART_SANDBOX=off                 完全关闭沙箱（默认开启）
//!   STALWART_CHROOT=/jail                先 chroot（要求配置里的路径都在 jail 内，
//!                                        且必须在放弃 root 权限前调用）。
//!                                        `-c` 与配置里的路径都按 **jail 内** 解释：
//!                                        宿主的 /jail/etc/config.json 在 jail 里就是
//!                                        /etc/config.json，启动时要写成
//!                                        `STALWART_CHROOT=/jail stalwart -c /etc/config.json`。
//!   STALWART_PLEDGE="stdio rpath ..."    自定义 pledge 承诺集
//!   STALWART_UNVEIL_EXTRA="/opt/x:rx,/srv/y:rwc"
//!                                        追加 unveil 条目，权限用 r/w/c/d/x 表示
//!   STALWART_UNVEIL_STRICT=on            严格模式：连“读”也只放行标准清单
//!                                        （默认是 / 只读，见下面「已知限制」）
//!
//! 注意：pledge 之后进程只能使用承诺集里的系统调用，越界会被内核直接杀掉。
//! 默认承诺集刻意给得比较宽（含 exec、proc 等，脚本插件要用），需要收紧时
//! 用 STALWART_PLEDGE 覆盖并自行验证。
//!
//! 已知限制（unveil 一旦锁定就不能再放开，这是内核行为）：
//!   * 默认策略下**读是不受限的**（unveil "/" r）：配置里的路径可以在任意位置，
//!     逐个枚举并不现实。要收紧就读侧也白名单化：STALWART_UNVEIL_STRICT=on
//!     （只放行 /etc/ssl、/etc/resolv.conf、/etc/passwd、zoneinfo、/dev 等标准清单
//!     ＋登记过的读路径；缺什么它会报权限错误，用 STALWART_UNVEIL_EXTRA 补）。
//!     严格模式会先 `unveil("/", "")` 建立默认拒绝的基线，因此不会出现“一条
//!     unveil 都没成功、内核根本没管”的静默失效。
//!   * 写权限是按**配置里登记的路径**给的：目录已存在时只登记目录本身，父目录
//!     不再连带放开；只有目标还不存在（首次安装）时才会退到最近存在的祖先。
//!     代价是这种回退会把祖先整棵子树放开，属于一次性的启动期让步。
//!   * unveil 条目有上限（UNVEIL_MAX_VNODES 与 UNVEIL_MAX_NAMES 都是 128）。
//!     超过后内核返回 E2BIG，这里只告警不拒绝启动：少管几个路径比邮件服务器
//!     起不来好，但请优先登记上层目录，而不是堆一长串子目录。
//!   * 通过 Web 控制台把存储/日志等**改成新的目录**时，新目录要等重启进程后
//!     才可写；运行中会报权限错误。改配置后重启即可，或临时用
//!     STALWART_UNVEIL_EXTRA 把它加进来。
//!   * 脚本插件的 `exec` 需要被执行的文件带 `x` 权限，而命令是脚本里动态指定的，
//!     无法预先枚举：要用它请显式登记，例如
//!     STALWART_UNVEIL_EXTRA="/bin/sh:rx,/usr/local/bin/your-tool:rx"。
//!     **另注意**：execve 之后新程序不带任何 unveil（内核语义），被执行的脚本/
//!     程序自身不受沙箱约束；父进程的 pledge 也不会以 execpromises 的形式传下去
//!     （这里 pledge 的第二个参数是 NULL），所以 exec 是沙箱的一处已知缺口。
//!   * chroot 需自行保证配置里的路径在 jail 内（相对路径按**进 jail 之后**的
//!     cwd 解析，也就是 "/"）。jail 里至少要能读到配置文件、写数据目录；
//!     DNS 解析要 /etc/resolv.conf（以及 /etc/hosts），读随机数要 /dev/urandom。
//!   * jail 里还要有 CA 信任锚（OpenBSD 上是 /etc/ssl/cert.pem）。启动流程在没有
//!     CA 时会直接失败而不是降级：hickory 的 `ResolverBuilder::build()` 总是构造
//!     TLS 上下文（`TlsConfig::new()` → `client_config()` → rustls-platform-verifier），
//!     UDP 解析器也一样要，所以 DNS/DNSSEC 解析器和出站 TLS 连接器都建不起来。
//!     jail 里缺这个文件时报的是 "No CA certificates were loaded from the system"。
//!   * **为什么不能靠 unveil 解决 chroot 的缺文件问题**：unveil 是「限制」清单，
//!     不是「授权」清单——它只决定进程**能不能碰**某个路径，不会把任何东西变出来。
//!     chroot 已经把 `/` 换成 jail，`/etc/ssl/cert.pem` 在 jail 内就是
//!     `<jail>/etc/ssl/cert.pem`；这个文件不存在时，unveil 里登记 `/etc/ssl`
//!     也读不到东西。两者解决的是不同维度的问题：
//!       - 不 chroot 时：读路径本来就走宿主 `/etc/ssl`，`allow_read("/etc/ssl")`
//!         （以及严格模式的 STANDARD_READ_PATHS）已经覆盖，无需额外登记；
//!       - chroot 时：必须由部署方把 CA（以及 /etc/resolv.conf、/etc/passwd 等）
//!         拷进 jail，或把 `SSL_CERT_FILE` 指向 jail 内的一份拷贝
//!         （openssl-probe 只在文件存在时才认这个变量）。

use std::fmt;

/// 默认 pledge 承诺集：覆盖邮件服务器的常见需求（文件、网络、DNS、UNIX socket、
/// 读取用户/组信息、fork/exec 脚本插件、伪终端、进程/内存信息）。
/// 逐一在 OpenBSD 7.9 上验证过：这些名字都被内核接受（`tmppath` 已被移除，
/// 7.9 上 pledge 会报 EINVAL，不要加）。
pub const DEFAULT_PLEDGE: &str =
    "stdio rpath wpath cpath dpath fattr flock inet unix dns getpw id proc exec tty ps vminfo";

#[derive(Debug, Default, Clone)]
#[cfg_attr(not(target_os = "openbsd"), allow(dead_code))]
pub struct SandboxPaths {
    enabled: bool,
    /// 严格模式：不再对整个文件系统给读权限，只 unveil 下面这份标准清单 + 登记过的读路径
    strict: bool,
    read: Vec<String>,
    write: Vec<String>,
    exec: Vec<String>,
    chroot: Option<String>,
    pledge: Option<String>,
}

/// 严格模式下放行的标准只读路径：跑一个邮件服务器绕不开的那些。
#[cfg_attr(not(target_os = "openbsd"), allow(dead_code))]
const STANDARD_READ_PATHS: &[&str] = &[
    "/etc/ssl",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/services",
    "/etc/protocols",
    "/etc/passwd",
    "/etc/group",
    "/etc/localtime",
    "/etc/mail",
    "/usr/share/zoneinfo",
    "/dev/urandom",
    "/dev/random",
    "/dev/null",
];

/// unveil(2) 的权限位。用位集而不是字符串，是为了把同一路径的多份登记合并成
/// 一次调用——同一路径重复 unveil 时后一次会整体替换前一次，直接按清单顺序调用
/// 会把先前给的权限弄丢。
#[cfg_attr(not(target_os = "openbsd"), allow(dead_code))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Perms(u8);

#[cfg_attr(not(target_os = "openbsd"), allow(dead_code))]
impl Perms {
    const READ: Perms = Perms(1);
    const WRITE: Perms = Perms(2);
    const CREATE: Perms = Perms(4);
    const EXEC: Perms = Perms(8);

    fn insert(&mut self, other: Perms) {
        self.0 |= other.0;
    }

    fn is_writable(&self) -> bool {
        self.0 & (Self::WRITE.0 | Self::CREATE.0) != 0
    }

    fn is_executable(&self) -> bool {
        self.0 & Self::EXEC.0 != 0
    }

    fn as_str(&self) -> String {
        let mut out = String::with_capacity(4);
        if self.0 & Self::READ.0 != 0 {
            out.push('r');
        }
        if self.0 & Self::WRITE.0 != 0 {
            out.push('w');
        }
        if self.0 & Self::CREATE.0 != 0 {
            out.push('c');
        }
        if self.0 & Self::EXEC.0 != 0 {
            out.push('x');
        }
        out
    }
}

#[cfg_attr(not(target_os = "openbsd"), allow(dead_code))]
impl std::ops::BitOr for Perms {
    type Output = Perms;

    fn bitor(self, rhs: Perms) -> Perms {
        Perms(self.0 | rhs.0)
    }
}

impl SandboxPaths {
    /// 从环境变量构造。默认启用；非 OpenBSD 平台上登记路径是无害的空操作。
    pub fn from_env() -> Self {
        let enabled = cfg!(target_os = "openbsd")
            && !matches!(
                std::env::var("STALWART_SANDBOX").as_deref(),
                Ok("off") | Ok("0") | Ok("false") | Ok("no")
            );

        let mut sb = Self {
            enabled,
            ..Default::default()
        };

        if !enabled {
            return sb;
        }

        sb.chroot = var("STALWART_CHROOT");
        sb.pledge = var("STALWART_PLEDGE");
        sb.strict = matches!(
            std::env::var("STALWART_UNVEIL_STRICT").as_deref(),
            Ok("on") | Ok("1") | Ok("true") | Ok("yes")
        );

        if let Some(extra) = var("STALWART_UNVEIL_EXTRA") {
            for entry in extra.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let (path, perms) = entry.split_once(':').unwrap_or((entry, "r"));
                for perm in perms.trim().chars() {
                    match perm {
                        'r' => sb.allow_read(path),
                        // d（unveil 里已无对应语义，历史写法）与 w/c 等价
                        'w' | 'c' | 'd' => sb.allow_write(path),
                        'x' => sb.allow_exec(path),
                        _ => {}
                    }
                }
            }
        }

        sb
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 严格模式（读侧也白名单化）。默认模式下读不受限，不必登记只读路径。
    pub fn is_strict(&self) -> bool {
        self.enabled && self.strict
    }

    /// 已登记的可写路径（用于启动时的自检/告警）。
    pub fn write_paths(&self) -> &[String] {
        &self.write
    }

    /// 登记一个只读路径（例如配置文件、证书）。
    pub fn allow_read(&mut self, path: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        push_unique(&mut self.read, path.as_ref());
    }

    /// 登记一个可写路径。
    ///
    /// 目标已存在且是**目录**时只登记目录本身，不再顺带把父目录也放开：
    /// 父目录一旦拿到 `c`，进程就能在父目录里创建/删除任意条目（例如把
    /// `/etc/passwd` 改名再放一个假的进去），这是实打实的越权。已有目录本身
    /// 就能建子项，不需要父目录的创建权限。
    ///
    /// 目标是**文件**（或者还不存在）时，父目录必须一并给 `rwc`：
    /// * 文件本身还不存在，创建它要父目录的创建权限；
    /// * 有些组件会在父目录里创建“兄弟文件”（mkstemp 的临时文件、SQLite 的
    ///   `-wal`/`-journal`、原子写用的 rename 目标），这些都要能写；
    /// * unveil 对同一路径是“最后一次调用覆盖前面的”，所以父目录不能只给 `c`：
    ///   一旦某个更宽的登记把父目录降级，前面给的权限就没了（实测会让 mkstemp
    ///   和多级缺失目录的写入一起失败）。
    pub fn allow_write(&mut self, path: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        // 先规范化再取父目录：配置里的路径可以是相对的，而
        // `Path::parent()` 对 "var/lib/db.sqlite" 返回的是相对串 "var/lib"，
        // 那个 `parent.starts_with('/')` 判断会把它丢掉——于是相对路径的配置
        // 拿不到父目录的 rwc（默认场景能拿到、相对路径场景拿不到，矩阵日志里
        // 的 rwc 列表差一项就是这个）。
        let Some(path) = normalize_path(path.as_ref()) else {
            return;
        };
        if is_existing_dir(&path) {
            push_unique(&mut self.write, &path);
            return;
        }
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let parent = parent.to_string_lossy().into_owned();
            if parent != "/" && !parent.is_empty() {
                push_unique(&mut self.write, &parent);
            }
        }
        push_unique(&mut self.write, &path);
    }

    /// 登记一个可执行路径（只会被 exec 的东西才需要）。
    pub fn allow_exec(&mut self, path: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        push_unique(&mut self.exec, path.as_ref());
    }

    /// 进入 chroot（若配置了）。**必须在读取配置、打开存储之前调用**：
    /// chroot 之后，配置文件与所有数据路径都按 jail 内的绝对路径解释。
    pub fn enter_chroot(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(target_os = "openbsd")]
        {
            if let Some(jail) = &self.chroot {
                let jail_c = cstr(jail)?;
                if unsafe { libc::chroot(jail_c.as_ptr()) } != 0 {
                    return Err(format!(
                        "chroot({jail}): {}",
                        std::io::Error::last_os_error()
                    ));
                }
                let root = cstr("/")?;
                if unsafe { libc::chdir(root.as_ptr()) } != 0 {
                    return Err(format!(
                        "chdir(/) after chroot: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
        }

        self.check_jail();

        Ok(())
    }

    /// chroot 之后的自检：jail 里缺关键文件时，对应功能会在启动或运行时失败。
    ///
    /// 只能告警不能自动修——unveil 是**限制**而不是授权：它只能在 jail 的命名空间里
    /// 收紧可见范围，无法把 jail 外的文件“放进来”。所以这些文件必须由部署方在
    /// chroot 之前拷进 jail 目录，否则进程进 jail 后根本看不到它们。
    pub fn check_jail(&self) {
        if !self.enabled || self.chroot.is_none() {
            return;
        }

        #[cfg(target_os = "openbsd")]
        for (path, why) in [
            (
                "/etc/ssl/cert.pem",
                "outbound TLS and DNS resolution need a CA bundle",
            ),
            ("/etc/resolv.conf", "DNS server list"),
            ("/etc/passwd", "user lookup / dropping privileges"),
            ("/etc/group", "group lookup / dropping privileges"),
            ("/dev/urandom", "random number source"),
        ] {
            if !std::path::Path::new(path).exists() {
                eprintln!(
                    "OpenBSD sandbox: warning: jail is missing {path} ({why}); \
                     copy it into the jail or the matching feature will fail."
                );
            }
        }
    }

    /// unveil 并锁定（chroot 已在 [`enter_chroot`] 里完成）。
    /// 必须在放弃 root 权限、打开存储之前调用。
    ///
    /// 每个路径只 unveil 一次，权限取所有登记方式的并集。必须这样做：
    /// **同一路径后一次的 unveil 会整体替换前一次的权限**，如果按
    /// 读/写/执行三份清单依次调用，`STALWART_UNVEIL_EXTRA="/x:rwc,/x:rx"`
    /// 这种写法会把 `c` 弄丢（最后那次只有 `rx`）。
    pub fn lock_filesystem(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(target_os = "openbsd")]
        {
            // 必须在**任何 unveil 生效之前**把路径表算好。resolved_paths() 要用
            // `Path::exists()` 判断“目标是否已存在、要不要退到祖先”，而 unveil
            // 一旦生效这个判断就不可信了：严格模式第一条就是 unveil("/", "")，
            // 之后连 /etc 都 stat 不到，所有登记项都会被误判成“不存在”而丢掉，
            // 沙箱反而变成全拒——CI 上就是这么暴露的
            // （stat /etc (unveiled) in strict mode: No such file or directory）。
            let resolved = self.resolved_paths();

            if self.strict {
                // 默认拒绝的基线：unveil("/", "") 不给任何权限，但它是**第一次**
                // 调用，会把整个文件系统从其它系统调用里摘掉。没有这一句时，
                // 如果严格模式下所有标准读路径都不存在（例如 chroot 的 jail 里
                // 什么都还没拷），一次成功的 unveil 都没有，内核根本不会限制
                // 任何访问——沙箱就静默地失效了。
                unveil("/", "")?;
                // 严格模式：只放行标准清单 + 登记过的路径。
                // 清单里 jail 内不存在的条目（例如没拷 /etc/mail）不能当致命错误。
                for path in STANDARD_READ_PATHS {
                    unveil_tolerant(path, "r")?;
                }
            } else {
                // 默认：其余位置一律只读——配置里的路径可以是任意位置，逐个枚举不现实
                unveil("/", "r")?;
            }

            for (path, perms) in resolved {
                unveil_tolerant(&path, &perms.as_str())?;
            }

            if unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) } != 0 {
                return Err(format!("unveil lock: {}", std::io::Error::last_os_error()));
            }
        }

        Ok(())
    }

    /// 把三份登记清单合并成「路径 -> 权限并集」。
    ///
    /// unveil 对同一路径是**后一次整体替换前一次**，所以同一个路径必须只调用一次，
    /// 权限取并集：`STALWART_UNVEIL_EXTRA="/x:rwc,/x:rx"` 这种写法不能把 `c` 弄丢。
    #[cfg_attr(not(target_os = "openbsd"), allow(dead_code))]
    fn merged_perms(&self) -> std::collections::BTreeMap<String, Perms> {
        let mut merged: std::collections::BTreeMap<String, Perms> =
            std::collections::BTreeMap::new();
        for path in &self.read {
            merged.entry(path.clone()).or_default().insert(Perms::READ);
        }
        for path in &self.write {
            // 目录的读也要给：unveil 的 r/w/c 是三个独立位，"rwc" 里的 r 不是
            // 可省的——存储要读回自己写的数据。
            merged
                .entry(path.clone())
                .or_default()
                .insert(Perms::READ | Perms::WRITE | Perms::CREATE);
        }
        for path in &self.exec {
            merged
                .entry(path.clone())
                .or_default()
                .insert(Perms::READ | Perms::EXEC);
        }
        merged
    }

    /// 在合并后的基础上，把还不存在的写路径退到最近存在的祖先
    /// （unveil 要求除最后一段外父路径都存在）。
    ///
    /// 只对**写**路径做祖先替换：只读路径不存在就是“可选文件不在”，不该因此
    /// 把它的祖先放开成可写。
    #[cfg_attr(not(target_os = "openbsd"), allow(dead_code))]
    fn resolved_paths(&self) -> std::collections::BTreeMap<String, Perms> {
        let mut resolved: std::collections::BTreeMap<String, Perms> =
            std::collections::BTreeMap::new();
        for (path, perms) in self.merged_perms() {
            if std::path::Path::new(&path).exists() {
                resolved.entry(path).or_default().insert(perms);
                continue;
            }
            if perms.is_writable()
                && let Some(ancestor) = nearest_existing_ancestor(&path)
            {
                // 中间目录还没建（首次安装很常见）：给最近存在的祖先整棵子树
                // 读写。只给祖先 c 不够——目录能建出来，但写不进去。
                eprintln!(
                    "OpenBSD sandbox: note: {path} does not exist yet; \
                     granting its ancestor {ancestor} read/write instead."
                );
                resolved.entry(ancestor).or_default().insert(perms);
                continue;
            }
            if perms.is_writable() {
                eprintln!(
                    "OpenBSD sandbox: warning: {path} has no existing ancestor, \
                     it will not be writable. Set STALWART_UNVEIL_EXTRA to fix."
                );
            } else if perms.is_executable() {
                eprintln!("OpenBSD sandbox: warning: exec path {path} does not exist, skipped");
            }
        }
        resolved
    }

    /// 上 pledge。调用点要在启动流程走完之后（监听已绑定、权限已放弃）。
    pub fn apply_pledge(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(target_os = "openbsd")]
        {
            let promises = cstr(self.pledge.as_deref().unwrap_or(DEFAULT_PLEDGE))?;
            if unsafe { libc::pledge(promises.as_ptr(), std::ptr::null()) } != 0 {
                return Err(format!("pledge: {}", std::io::Error::last_os_error()));
            }
        }

        Ok(())
    }

    /// 用于启动日志：列出实际登记的路径，便于确认“按组件收集”真的生效了。
    pub fn describe(&self) -> String {
        if !self.enabled {
            return "disabled".to_string();
        }
        let mut out = format!(
            "unveil({} r + {} rwc + {} rx), pledge({})",
            self.read.len(),
            self.write.len(),
            self.exec.len(),
            self.pledge.as_deref().unwrap_or(DEFAULT_PLEDGE)
        );
        if self.strict {
            out.push_str(", strict");
        }
        if let Some(jail) = &self.chroot {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!(", chroot({jail})"));
        }
        // 默认模式下读不受限（unveil "/" r），列出来没意义；严格模式下列出来
        // 才好排查“某个证书文件为什么读不到”。
        let read_list: &[String] = if self.strict { &self.read } else { &[] };
        for (label, list) in [("r", read_list), ("rwc", &self.write), ("rx", &self.exec)] {
            if !list.is_empty() {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!(
                        "
  {label}: {}",
                        list.join(" ")
                    ),
                );
            }
        }
        out
    }
}

impl fmt::Display for SandboxPaths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// `stalwart --sandbox-check`：验证当前系统上 unveil/pledge 真的生效，
/// 而且拦的是该拦的、放的是该放的。供 CI 在 OpenBSD VM 里冒烟测试。
///
/// 只验证「调用返回 0」不够——unveil 一次都没成功时内核根本不限制访问，
/// 那种静默失效会被放过。所以这里做正负两类断言：
/// * 登记过的目录：能读、能建文件、能写、能删；
/// * 没登记的目录：读不到、写不进。
///
/// 默认模式下读是全开的（`unveil("/", "r")`），读侧的负向断言只能在严格
/// 模式下做；而 unveil 一旦锁定就不可重来，所以严格模式那部分交给子进程
/// （`--sandbox-check-strict`）验证。
pub fn self_check() -> Result<(), String> {
    #[cfg(target_os = "openbsd")]
    {
        // 严格模式的读侧断言要另起一个进程（unveil 一旦锁定就不能在本进程重来）。
        // 必须**在**本进程 unveil/pledge 之前 spawn：unveil 的 x 权限没给二进制
        // 自己，锁定之后 execve 会被拒。
        let exe = std::env::current_exe()
            .map_err(|err| format!("cannot locate own binary for strict check: {err}"))?;
        let output = std::process::Command::new(exe)
            .arg("--sandbox-check-strict")
            .output()
            .map_err(|err| format!("cannot spawn strict sandbox check: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "strict-mode read enforcement failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let base =
            std::env::temp_dir().join(format!("stalwart-sandbox-check-{}", std::process::id()));
        let allowed = base.join("allowed");
        std::fs::create_dir_all(&allowed)
            .map_err(|err| format!("cannot create {}: {err}", allowed.display()))?;

        let mut sb = SandboxPaths {
            enabled: true,
            ..Default::default()
        };
        sb.allow_write(allowed.to_string_lossy().as_ref());

        sb.lock_filesystem()?;
        sb.apply_pledge()?;

        // 已登记：目录可读、可建文件、可写、可删
        let probe = allowed.join("probe");
        std::fs::read_dir(&allowed)
            .map_err(|err| format!("readdir {} after pledge: {err}", allowed.display()))?;
        std::fs::write(&probe, b"ok").map_err(|err| format!("write {}: {err}", probe.display()))?;
        std::fs::read(&probe).map_err(|err| format!("read {}: {err}", probe.display()))?;
        std::fs::remove_file(&probe).map_err(|err| format!("unlink {}: {err}", probe.display()))?;

        // 未登记：写必须被拒。父目录（base）没被登记成可写，所以新建文件应当
        // 报 EACCES/ENOENT，而不是悄悄成功。
        let blocked = base.join("blocked");
        if std::fs::write(&blocked, b"x").is_ok() {
            return Err(format!(
                "unveil is not enforcing writes: created {} although its directory \
                 was never unveiled",
                blocked.display()
            ));
        }

        // base 和 allowed 都是空目录，但删不掉它们（删除需要在 base 上有 c 权限，
        // 那是我们刚刚断言不该有的）。留给系统的临时目录清理。
        Ok(())
    }

    #[cfg(not(target_os = "openbsd"))]
    {
        Ok(())
    }
}

/// 严格模式的读侧断言：没登记过的可读文件（这里用 /bin/sh，权限 0555）必须读不到。
/// 由 [`self_check`] 以子进程方式调用。
pub fn self_check_strict() -> Result<(), String> {
    #[cfg(target_os = "openbsd")]
    {
        let mut sb = SandboxPaths {
            enabled: true,
            strict: true,
            ..Default::default()
        };
        sb.allow_read("/etc");

        sb.lock_filesystem()?;

        std::fs::metadata("/etc")
            .map_err(|err| format!("stat /etc (unveiled) in strict mode: {err}"))?;

        match std::fs::read("/bin/sh") {
            Ok(bytes) => Err(format!(
                "strict mode is not enforcing reads: read /bin/sh succeeded ({} bytes) \
                 although only /etc was unveiled",
                bytes.len()
            )),
            Err(_) => Ok(()),
        }
    }

    #[cfg(not(target_os = "openbsd"))]
    {
        Ok(())
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// 路径是否是一个**已存在的目录**（只有这种情况才不需要父目录的创建权限）。
fn is_existing_dir(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
}

/// 把路径规范化成绝对路径（相对路径按当前 cwd 解析，去掉末尾斜杠）。
/// 无法解析或为空时返回 None。
fn normalize_path(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }

    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path).to_string_lossy().into_owned(),
            Err(_) => {
                eprintln!("OpenBSD sandbox: cannot resolve relative path {path:?}, skipping");
                return None;
            }
        }
    };

    let path = path.trim_end_matches('/');
    Some(if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    })
}

/// 登记前把路径规范化成绝对路径：配置里可以写相对路径（相对于启动时的 cwd），
/// unveil(2) 只接受绝对路径，静默丢掉会导致运行时写入被拒。
fn push_unique(list: &mut Vec<String>, path: &str) {
    if let Some(path) = normalize_path(path)
        && !list.iter().any(|existing| existing == &path)
    {
        list.push(path);
    }
}

/// 从路径往上找第一个存在的目录（不含 "/"）。用于“中间目录还没建”时决定
/// 该给哪一级创建权限。
#[cfg_attr(not(target_os = "openbsd"), allow(dead_code))]
fn nearest_existing_ancestor(path: &str) -> Option<String> {
    let mut current = std::path::Path::new(path).to_path_buf();
    // 去掉末尾斜杠再逐级向上
    if current.is_file() || current.is_dir() {
        return None;
    }
    while let Some(parent) = current.parent() {
        if parent == std::path::Path::new("/") {
            return None;
        }
        if parent.is_dir() {
            return Some(parent.to_string_lossy().into_owned());
        }
        current = parent.to_path_buf();
    }
    None
}

#[cfg(target_os = "openbsd")]
fn cstr(value: &str) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(value).map_err(|_| format!("path contains a NUL byte: {value:?}"))
}

#[cfg(target_os = "openbsd")]
fn unveil_raw(path: &str, perms: &str) -> Result<(), std::io::Error> {
    let path_c = cstr_io(path)?;
    let perms_c = cstr_io(perms)?;
    if unsafe { libc::unveil(path_c.as_ptr(), perms_c.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "openbsd")]
fn unveil(path: &str, perms: &str) -> Result<(), String> {
    unveil_raw(path, perms).map_err(|err| format!("unveil({path}, {perms}): {err}"))
}

/// 登记单个条目，把“不该让服务器起不来”的失败降级成告警：
///
/// * ENOENT：路径不存在（可选证书、jail 里没拷的文件、两步之间被删掉的目录）。
///   写路径在 [`SandboxPaths::resolved_paths`] 里已经退到最近存在的祖先，
///   走到这里说明连祖先都没了。
/// * E2BIG：unveil 表满了（UNVEIL_MAX_VNODES / UNVEIL_MAX_NAMES 都是 128）。
///   沙箱比配置少管几个路径，比邮件服务器起不来强；但要让运维看得见。
///
/// 其它错误（EINVAL 权限串写错、ENAMETOOLONG 等）仍然是致命错误——那说明
/// 代码或配置有问题，继续跑只会得到一个半开的沙箱。
#[cfg(target_os = "openbsd")]
fn unveil_tolerant(path: &str, perms: &str) -> Result<(), String> {
    match unveil_raw(path, perms) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if perms != "r" {
                eprintln!(
                    "OpenBSD sandbox: warning: {path} does not exist, its {perms} permissions \
                     were not registered (runtime writes there will fail)"
                );
            }
            Ok(())
        }
        Err(err) if err.raw_os_error() == Some(libc::E2BIG) => {
            eprintln!(
                "OpenBSD sandbox: warning: unveil table is full (128 entries), {path} ({perms}) \
                 was NOT registered; prefer higher-level directories over long lists of \
                 subdirectories."
            );
            Ok(())
        }
        Err(err) => Err(format!("unveil({path}, {perms}): {err}")),
    }
}

#[cfg(target_os = "openbsd")]
fn cstr_io(value: &str) -> Result<std::ffi::CString, std::io::Error> {
    std::ffi::CString::new(value)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> SandboxPaths {
        SandboxPaths {
            enabled: true,
            ..Default::default()
        }
    }

    /// 相对路径也必须拿到父目录的 rwc：以前 `Path::parent()` 返回相对串
    /// （"var/lib"），被 `starts_with('/')` 判断丢掉，父目录就漏登记了。
    #[test]
    fn relative_write_path_registers_parent() {
        let mut sb = sandbox();
        sb.allow_write("var/lib/stalwart/db.sqlite");
        let paths = sb.write_paths();
        assert_eq!(paths.len(), 2, "{paths:?}");
        let (parent, child) = (&paths[0], &paths[1]);
        assert_eq!(
            std::path::Path::new(child).parent().unwrap(),
            std::path::Path::new(parent)
        );
        assert!(parent.ends_with("var/lib/stalwart"), "{paths:?}");
    }

    #[cfg(unix)]
    #[test]
    fn absolute_write_path_registers_parent_without_trailing_slash() {
        let root = std::env::temp_dir().join(format!("stalwart-abs-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let root = root.to_string_lossy().into_owned();
        // 目标目录还不存在 → 父目录必须一并登记
        let target = format!("{root}/data/");

        let mut sb = sandbox();
        sb.allow_write(&target);
        assert_eq!(sb.write_paths(), [root.clone(), format!("{root}/data")]);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 顶层路径没有父目录，不能把 "/" 登记成可写。
    #[test]
    fn root_level_path_has_no_writable_parent() {
        let mut sb = sandbox();
        sb.allow_write("/tmp");
        assert_eq!(sb.write_paths(), ["/tmp"]);
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_registrations_are_collapsed() {
        let root = std::env::temp_dir().join(format!("stalwart-dup-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let root = root.to_string_lossy().into_owned();
        let target = format!("{root}/data/db");

        let mut sb = sandbox();
        sb.allow_write(&target);
        sb.allow_write(format!("{target}/"));
        assert_eq!(sb.write_paths(), [format!("{root}/data"), target]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn blank_path_is_ignored() {
        let mut sb = sandbox();
        sb.allow_write("");
        sb.allow_write("   ");
        assert!(sb.write_paths().is_empty());
    }

    /// 已经存在的目录只登记它自己：父目录拿到 `c` 就意味着可以在父目录里
    /// 创建/删除任意条目（把 /etc/passwd 改名再放一个假的进去），是实打实的越权。
    #[cfg(unix)]
    #[test]
    fn existing_directory_does_not_unveil_its_parent() {
        // 造一个两级目录，只登记里层
        let base = std::env::temp_dir().join(format!("stalwart-sb-{}", std::process::id()));
        let data = base.join("var/lib");
        std::fs::create_dir_all(&data).unwrap();

        let mut sb = sandbox();
        let data = data.to_string_lossy().into_owned();
        sb.allow_write(&data);
        assert_eq!(sb.write_paths(), [data.as_str()]);

        let _ = std::fs::remove_dir_all(&base);
    }

    /// 同一路径的多份登记要合并成「权限并集」再 unveil：
    /// `STALWART_UNVEIL_EXTRA="/x:rwc,/x:rx"` 这种写法不能把 `c` 弄丢。
    #[test]
    fn permissions_are_merged_per_path() {
        let mut sb = sandbox();
        let path = "/srv/stalwart-merge";
        sb.allow_read(path);
        sb.allow_write(path);
        sb.allow_exec(path);

        let merged = sb.merged_perms();
        assert_eq!(merged[path].as_str(), "rwcx", "{merged:?}");
    }

    /// 读路径不存在时不该退到祖先（那会把祖先放开成可读，甚至可写）。
    #[test]
    fn missing_read_path_is_not_remapped_to_ancestor() {
        let mut sb = sandbox();
        sb.allow_read("/nonexistent-stalwart-read/stalwart.pem");
        assert!(sb.resolved_paths().is_empty());
    }

    #[test]
    fn disabled_sandbox_registers_nothing() {
        let mut sb = SandboxPaths::default();
        sb.allow_write("/srv/data");
        assert!(sb.write_paths().is_empty());
    }
}
