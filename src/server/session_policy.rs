// [rd-sharp] 被控端会话策略锁
//
// 背景：RustDesk 的「只读 / view-only」只是主控端本地的一个开关
// （见 src/client.rs 的 get_toggle_option("view-only")），被控端没有任何
// 机制去校验它。也就是说，主控端只要不勾选（或用改过的客户端），
// 就能在被控端声明「只允许查看」的情况下继续注入鼠标键盘事件。
// 这与 CVE-2026-57850 属于同一类问题：缺少服务端授权校验。
//
// 本模块补上这个缺口：策略由被控端本机的配置文件决定，主控端无法影响，
// 且在所有输入 / 剪贴板 / 音频 / 文件传输的判定入口生效。
//
// 配置文件：RustDesk 配置目录下 session-policy.conf（与其它配置文件同级）
//   Windows: %APPDATA%\RustDesk\config\session-policy.conf
//   Linux:   ~/.config/rustdesk/session-policy.conf
//   macOS:   ~/Library/Preferences/com.carriez.RustDesk/session-policy.conf
//
// 格式为 key=value，值为 Y / N，以 # 或 ; 开头的行为注释。缺省（文件不存在）
// 时全部为关闭，即与原生行为完全一致 —— 不改变任何默认行为。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use hbb_common::config::Config;
use hbb_common::log;

const POLICY_FILE: &str = "session-policy.conf";
/// 最快多久重新读一次配置（秒）。避免每个鼠标事件都做一次 stat。
const RELOAD_INTERVAL_SECS: u64 = 2;

#[derive(Clone, Copy, Default, Debug)]
pub struct Policy {
    /// 只读：丢弃主控端发来的所有鼠标 / 键盘事件
    pub view_only: bool,
    /// 禁止剪贴板同步（双向）
    pub disable_clipboard: bool,
    /// 禁止文件传输
    pub disable_file_transfer: bool,
    /// 禁止音频
    pub disable_audio: bool,
}

struct Cached {
    mtime: Option<SystemTime>,
    policy: Policy,
}

fn cache() -> &'static RwLock<Cached> {
    static CACHE: OnceLock<RwLock<Cached>> = OnceLock::new();
    CACHE.get_or_init(|| {
        RwLock::new(Cached {
            mtime: None,
            policy: Policy::default(),
        })
    })
}

fn parse(text: &str) -> Policy {
    let mut map: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            // 统一成正斜线风格：view_only / VIEW-ONLY 都归一为 view-only
            let key = k.trim().to_lowercase().replace('_', "-");
            let val = v.trim().to_lowercase();
            map.insert(key, val);
        }
    }
    let on = |k: &str| -> bool {
        matches!(
            map.get(k).map(|s| s.as_str()),
            Some("y") | Some("yes") | Some("true") | Some("1") | Some("on")
        )
    };
    Policy {
        // view-only 与 disable-input 等价，两个名字都接受
        view_only: on("view-only") || on("disable-input") || on("read-only"),
        disable_clipboard: on("disable-clipboard"),
        disable_file_transfer: on("disable-file-transfer"),
        disable_audio: on("disable-audio"),
    }
}

/// 上次重新读取配置的时间戳（秒）
static LAST_CHECK: AtomicU64 = AtomicU64::new(0);

/// 读取当前生效的策略。带 2 秒节流，改配置后无需重启被控端。
pub fn current() -> Policy {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let last = LAST_CHECK.load(Ordering::Relaxed);
    if now.saturating_sub(last) < RELOAD_INTERVAL_SECS {
        return cache()
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .policy;
    }
    LAST_CHECK.store(now, Ordering::Relaxed);

    let path = Config::path(POLICY_FILE);
    let mtime = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok());

    {
        let c = cache().read().unwrap_or_else(|e| e.into_inner());
        if c.mtime == mtime {
            return c.policy;
        }
    }

    let policy = match std::fs::read_to_string(&path) {
        Ok(text) => {
            let p = parse(&text);
            log::info!("[rd-sharp] 会话策略已加载: {:?}", p);
            p
        }
        Err(_) => Policy::default(),
    };

    let mut c = cache().write().unwrap_or_else(|e| e.into_inner());
    c.mtime = mtime;
    c.policy = policy;
    policy
}

#[inline]
pub fn view_only() -> bool {
    current().view_only
}

#[inline]
pub fn clipboard_locked() -> bool {
    current().disable_clipboard
}

#[inline]
pub fn file_transfer_locked() -> bool {
    current().disable_file_transfer
}

#[inline]
pub fn audio_locked() -> bool {
    current().disable_audio
}
