use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::fs::OpenOptions;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use base64::{engine::general_purpose, Engine as _};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use sha2::{Digest, Sha256};

const ROOT: &str = "ROOT";
const MDNS_SERVICE: &str = "_earth._tcp.local.";

const TEXT_EXTS: &[&str] = &[
    "txt", "c", "h", "cpp", "hpp", "rs", "py", "md", "json", "toml", "yaml", "yml", "js", "ts",
    "html", "css", "sh", "java", "go",
];

const IGNORED_DIR_NAMES: &[&str] = &[
    ".earth", ".git", ".hg", ".svn",
];

const IGNORED_EXACT_FILE_NAMES: &[&str] = &[
    "4913", ".DS_Store", "Thumbs.db", "desktop.ini",
];

fn is_ignored_component_name(name: &str, is_dir: bool) -> bool {
    if is_dir && IGNORED_DIR_NAMES.contains(&name) { return true; }
    if IGNORED_EXACT_FILE_NAMES.contains(&name) { return true; }

    // Vim backups: file.txt~, test.txu~, etc. Vim increments backup suffixes
    // when a prior backup exists, which is what creates test.txu~/test.txv~...
    if name.ends_with('~') { return true; }

    // Vim swap files: .file.swp, .file.swo, .file.swn, etc.
    if name.starts_with('.') {
        if let Some(ext) = Path::new(name).extension().and_then(|e| e.to_str()) {
            let ext = ext.to_ascii_lowercase();
            if ext.len() == 3 && ext.starts_with("sw") { return true; }
        }
    }

    // Emacs autosave/lock files: #file#, .#file
    if name.starts_with('#') && name.ends_with('#') { return true; }
    if name.starts_with(".#") { return true; }

    // Common editor/partial temporary files. Keep this conservative so normal
    // project files are not accidentally skipped.
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".tmp") || lower.ends_with(".temp") || lower.ends_with(".part") || lower.ends_with(".crdownload") {
        return true;
    }

    false
}

fn is_ignored_path(path: &Path, is_dir: bool) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|name| is_ignored_component_name(name, is_dir))
        .unwrap_or(false)
}

fn is_ignored_rel(rel: &str) -> bool {
    Path::new(rel).components().any(|c| {
        let name = c.as_os_str().to_string_lossy();
        is_ignored_component_name(&name, false) || IGNORED_DIR_NAMES.contains(&name.as_ref())
    })
}

#[derive(Clone, Debug)]
struct Config {
    user: String,
    device: String,
    password_hash: String,
    account_id: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct Share {
    id: String,
    name: String,
    root: PathBuf,
}

#[derive(Clone, Debug)]
struct ManifestEntry {
    path: String,
    kind: String, // text or blob
    object: String, // crdt filename or blob hash
    mtime: u64,
    size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Line {
    id: String,
    parent: String,
    tombstone: bool,
    text: String,
}

#[derive(Clone, Debug)]
struct TextDoc {
    clock: u64,
    lines: BTreeMap<String, Line>,
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        return Ok(());
    }
    ensure_global_dirs()?;

    match args[1].as_str() {
        "login" => {
            let user = args.get(2).cloned().unwrap_or_else(|| prompt("username: ").unwrap_or_default());
            let password = opt_value(&args, "--password")
                .or_else(|| env::var("EARTH_PASSWORD").ok())
                .unwrap_or_else(|| rpassword::prompt_password("password: ").unwrap_or_default());
            let explicit_port = opt_value(&args, "--port").and_then(|v| v.parse::<u16>().ok());
            let cfg = login(&user, &password, explicit_port)?;

            // Starting the account daemon is the default. Use --no-start for one-shot login only.
            if !has_flag(&args, "--no-start") {
                ensure_daemon_running(&cfg)?;
            }

            // Login also discovers peers/shares by default, unless explicitly disabled.
            if !has_flag(&args, "--no-discover") {
                let timeout = opt_value(&args, "--discover-timeout")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(10);
                post_login_discovery(timeout)?;
            }
        }
        "use" => {
            let account = args.get(2).ok_or_else(|| err("usage: earth use <user-or-account-id>"))?;
            select_account(Some(account.clone()))?;
            let cfg = load_config()?;
            set_active_account(&cfg)?;
            println!("active account: {}", cfg.user);
        }
        "whoami" => {
            select_account(opt_value(&args, "--account"))?;
            let cfg = load_config()?;
            println!("{}", cfg.user);
        }
        "init" => {
            select_account(opt_value(&args, "--account"))?;
            ensure_dirs()?;
            let path = args.get(2).ok_or_else(|| err("usage: earth init <path> [--account user]"))?;
            cmd_init(Path::new(path))?;
        }
        "list" => {
            select_account(opt_value(&args, "--account"))?;
            ensure_dirs()?;
            let peer = opt_value(&args, "--peer");
            let discover = has_flag(&args, "--discover");
            cmd_list(peer.as_deref(), discover)?;
        }
        "peers" => {
            select_account(opt_value(&args, "--account"))?;
            let timeout = opt_value(&args, "--timeout").and_then(|v| v.parse().ok()).unwrap_or(5);
            cmd_peers(timeout)?;
        }
        "clone" => {
            select_account(opt_value(&args, "--account"))?;
            ensure_dirs()?;
            if args.len() < 4 {
                return Err(err("usage: earth clone <share-name> <path> [--peer host:port | --discover] [--account user]"));
            }
            let peer = resolve_peer(&args)?;
            cmd_clone(&args[2], Path::new(&args[3]), &peer)?;
        }
        "daemon" => {
            select_account(opt_value(&args, "--account"))?;
            ensure_dirs()?;
            let cfg = load_config()?;
            let default_bind = format!("0.0.0.0:{}", cfg.port);
            let bind = opt_value(&args, "--bind").unwrap_or(default_bind);
            let peers = all_opt_values(&args, "--peer");
            let discover = !has_flag(&args, "--no-discover") || has_flag(&args, "--discover");
            cmd_daemon(&bind, peers, discover)?;
        }
        "sync" => {
            select_account(opt_value(&args, "--account"))?;
            ensure_dirs()?;
            let peer = resolve_peer(&args)?;
            scan_all()?;
            sync_peer(&peer)?;
            render_all()?;
        }
        "status" => {
            cmd_status(opt_value(&args, "--account"))?;
        }
        "stop" => {
            cmd_stop(opt_value(&args, "--account"), has_flag(&args, "--all"))?;
        }
        _ => usage(),
    }
    Ok(())
}

fn usage() {
    eprintln!(
        "earth\n\n  login <user> [--password pass] [--port port] [--no-start] [--discover-timeout seconds] [--no-discover]\n  use <user-or-account-id>\n  whoami [--account user]\n  init <path> [--account user]\n  list [--peer host:port | --discover] [--account user]\n  peers [--timeout seconds] [--account user]\n  clone <share-name> <path> [--peer host:port | --discover] [--account user]\n  daemon [--account user] [--bind host:port] [--peer host:port ...] [--discover|--no-discover]\n  sync [--peer host:port | --discover] [--account user]\n  status [--account user]\n  stop [--account user | --all]\n\nSet PROGRAM_HOME to isolate devices for tests. Set EARTH_PASSWORD for noninteractive login.\nLogin starts the account daemon by default; use --no-start to disable."
    );
}

fn err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.to_string())
}

fn global_home() -> PathBuf {
    if let Ok(v) = env::var("PROGRAM_HOME") {
        return PathBuf::from(v);
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".earth")
}

fn ensure_global_dirs() -> io::Result<()> {
    fs::create_dir_all(global_home().join("accounts"))?;
    fs::create_dir_all(global_home().join("global"))?;
    Ok(())
}

fn account_dir_for_id(account_id: &str) -> PathBuf {
    global_home().join("accounts").join(safe_account_component(account_id))
}

fn safe_account_component(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn program_home() -> PathBuf {
    if let Ok(v) = env::var("EARTH_ACCOUNT_DIR") {
        return PathBuf::from(v);
    }
    if let Ok(v) = env::var("EARTH_ACCOUNT") {
        if let Ok(dir) = find_account_dir(&v) { return dir; }
    }
    if let Ok((id, _user, _port)) = read_active_account() {
        return account_dir_for_id(&id);
    }
    global_home().join("accounts").join("unselected")
}

fn ensure_dirs() -> io::Result<()> {
    ensure_global_dirs()?;
    let h = program_home();
    for p in ["shares", "crdts", "blobs", "logs"] {
        fs::create_dir_all(h.join(p))?;
    }
    Ok(())
}

fn config_path() -> PathBuf { program_home().join("config.tsv") }
fn shares_path() -> PathBuf { program_home().join("shares.tsv") }
fn manifests_dir() -> PathBuf { program_home().join("shares") }
fn crdts_dir() -> PathBuf { program_home().join("crdts") }
fn blobs_dir() -> PathBuf { program_home().join("blobs") }
fn lock_path() -> PathBuf { program_home().join("account.lock") }
fn active_account_path() -> PathBuf { global_home().join("global").join("active_account.tsv") }
fn port_allocations_path() -> PathBuf { global_home().join("global").join("port_allocations.tsv") }

fn select_account(account: Option<String>) -> io::Result<()> {
    ensure_global_dirs()?;
    if let Some(a) = account.or_else(|| env::var("EARTH_ACCOUNT").ok()) {
        let dir = find_account_dir(&a)?;
        env::set_var("EARTH_ACCOUNT_DIR", dir);
        return Ok(());
    }
    if let Ok((id, _, _)) = read_active_account() {
        env::set_var("EARTH_ACCOUNT_DIR", account_dir_for_id(&id));
        return Ok(());
    }
    Err(err("no active account; run earth login <user>"))
}

fn find_account_dir(user_or_id: &str) -> io::Result<PathBuf> {
    let accounts = global_home().join("accounts");
    let direct = accounts.join(safe_account_component(user_or_id));
    if direct.join("config.tsv").exists() { return Ok(direct); }
    if accounts.exists() {
        for ent in fs::read_dir(accounts)? {
            let dir = ent?.path();
            if !dir.is_dir() { continue; }
            let cfgp = dir.join("config.tsv");
            if !cfgp.exists() { continue; }
            let cfg = parse_config_file(&cfgp)?;
            if cfg.user == user_or_id || cfg.account_id == user_or_id {
                return Ok(dir);
            }
        }
    }
    Err(err(&format!("account not found: {user_or_id}; run earth login {user_or_id}")))
}

fn set_active_account(cfg: &Config) -> io::Result<()> {
    ensure_global_dirs()?;
    write_string(active_account_path(), &format!("{}\t{}\t{}\n", esc(&cfg.account_id), esc(&cfg.user), cfg.port))
}

fn read_active_account() -> io::Result<(String, String, u16)> {
    let p = active_account_path();
    if !p.exists() { return Err(err("no active account")); }
    let lines = read_lines(&p)?;
    let line = lines.first().ok_or_else(|| err("bad active account file"))?;
    let cols: Vec<_> = line.split('\t').collect();
    if cols.len() < 3 { return Err(err("bad active account file")); }
    Ok((unesc(cols[0]), unesc(cols[1]), cols[2].parse().unwrap_or(7878)))
}

fn prompt(s: &str) -> io::Result<String> {
    print!("{s}");
    io::stdout().flush()?;
    let mut out = String::new();
    io::stdin().read_line(&mut out)?;
    Ok(out.trim().to_string())
}

fn opt_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn all_opt_values(args: &[String], flag: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut i = 0;
    while i + 1 < args.len() {
        if args[i] == flag {
            v.push(args[i + 1].clone());
            i += 2;
        } else { i += 1; }
    }
    v
}

fn has_flag(args: &[String], flag: &str) -> bool { args.iter().any(|a| a == flag) }

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

fn stable_hash(s: &str) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn file_hash(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        buf[..n].hash(&mut h);
    }
    Ok(format!("{:016x}", h.finish()))
}

fn bytes_hash(data: &[u8]) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn path_content_equals(path: &Path, data: &[u8]) -> io::Result<bool> {
    if !path.exists() { return Ok(false); }
    let meta = fs::metadata(path)?;
    if meta.len() != data.len() as u64 { return Ok(false); }
    let disk_hash = file_hash(path)?;
    Ok(disk_hash == bytes_hash(data))
}

fn login(user: &str, password: &str, explicit_port: Option<u16>) -> io::Result<Config> {
    if user.trim().is_empty() { return Err(err("username cannot be empty")); }
    if password.len() < 8 { return Err(err("password must be at least 8 characters")); }

    ensure_global_dirs()?;

    if let Ok(dir) = find_account_dir(user) {
        env::set_var("EARTH_ACCOUNT_DIR", &dir);
        ensure_dirs()?;
        let mut cfg = load_config_unverified()?;
        verify_password(password, &cfg.password_hash)?;
        if let Some(port) = explicit_port {
            cfg.port = port;
            save_config(&cfg)?;
            save_port_allocation(&cfg.account_id, port)?;
        }
        set_active_account(&cfg)?;
        println!("unlocked account {} on device {}", cfg.user, cfg.device);
        return Ok(cfg);
    }

    let device = format!("{}-{}", hostname(), now_ms());
    let password_hash = hash_password(password)?;
    let account_id = derive_account_id(user, password);
    let account_dir = account_dir_for_id(&account_id);
    env::set_var("EARTH_ACCOUNT_DIR", &account_dir);
    ensure_dirs()?;
    let port = explicit_port.unwrap_or(get_or_assign_port(&account_id)?);
    let cfg = Config { user: user.to_string(), device, password_hash, account_id, port };
    save_config(&cfg)?;
    save_port_allocation(&cfg.account_id, cfg.port)?;
    set_active_account(&cfg)?;
    println!("created password-backed account for {}; device {}; assigned daemon port {}", cfg.user, cfg.device, cfg.port);
    Ok(cfg)
}

fn save_config(cfg: &Config) -> io::Result<()> {
    write_string(
        config_path(),
        &format!(
            "user\t{}\ndevice\t{}\npassword_hash\t{}\naccount_id\t{}\nport\t{}\n",
            esc(&cfg.user), esc(&cfg.device), esc(&cfg.password_hash), esc(&cfg.account_id), cfg.port
        ),
    )
}

fn get_or_assign_port(account_id: &str) -> io::Result<u16> {
    if let Some(p) = load_port_allocations()?.get(account_id).cloned() { return Ok(p); }
    let used: BTreeSet<u16> = load_port_allocations()?.values().cloned().collect();
    for port in 7878..7978 {
        if used.contains(&port) { continue; }
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            save_port_allocation(account_id, port)?;
            return Ok(port);
        }
    }
    Err(err("could not find a free daemon port in 7878..7978"))
}

fn load_port_allocations() -> io::Result<BTreeMap<String, u16>> {
    let p = port_allocations_path();
    if !p.exists() { return Ok(BTreeMap::new()); }
    let mut m = BTreeMap::new();
    for line in read_lines(&p)? {
        let cols: Vec<_> = line.split('\t').collect();
        if cols.len() >= 2 { m.insert(unesc(cols[0]), cols[1].parse().unwrap_or(7878)); }
    }
    Ok(m)
}

fn save_port_allocation(account_id: &str, port: u16) -> io::Result<()> {
    let mut m = load_port_allocations()?;
    m.insert(account_id.to_string(), port);
    let mut s = String::new();
    for (id, p) in m { s.push_str(&format!("{}\t{}\n", esc(&id), p)); }
    write_string(port_allocations_path(), &s)
}

fn daemon_addr(cfg: &Config) -> String { format!("127.0.0.1:{}", cfg.port) }

fn ensure_daemon_running(cfg: &Config) -> io::Result<()> {
    let addr = daemon_addr(cfg);
    if let Ok(resp) = rpc(&addr, "PING\n") {
        if resp.contains(&format!("account\t{}", cfg.account_id)) || resp.starts_with("PONG") {
            println!("daemon already running for {} on {}", cfg.user, addr);
            return Ok(());
        }
    }

    // If an old lock exists but no daemon answers, assume it is stale.
    let _ = fs::remove_file(lock_path());

    let exe = env::current_exe()?;
    Command::new(exe)
        .arg("daemon")
        .arg("--account").arg(&cfg.user)
        .arg("--bind").arg(format!("0.0.0.0:{}", cfg.port))
        .arg("--discover")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(150));
        if let Ok(resp) = rpc(&addr, "PING\n") {
            if resp.starts_with("PONG") {
                println!("started daemon for {} on {}", cfg.user, addr);
                return Ok(());
            }
        }
    }
    Err(err("started daemon process, but it did not become ready within 5s"))
}



fn post_login_discovery(timeout_secs: u64) -> io::Result<()> {
    println!("searching for earth peers for {timeout_secs}s...");
    let peers = discover_peers(Duration::from_secs(timeout_secs))?;
    if peers.is_empty() {
        println!("no earth peers discovered");
        println!("hint: on another device, run: earth daemon --bind 0.0.0.0:7878 --discover");
        return Ok(());
    }

    println!("discovered peers:");
    for peer in &peers {
        println!("  {peer}");
    }

    println!("available remote shares:");
    let mut any_share = false;
    for peer in &peers {
        match rpc(peer, "GET_SHARES\n") {
            Ok(resp) => {
                let lines: Vec<_> = resp.lines().filter(|l| !l.trim().is_empty()).collect();
                if lines.is_empty() {
                    println!("  {peer}: no shares");
                } else {
                    any_share = true;
                    println!("  from {peer}:");
                    for line in lines {
                        let cols: Vec<_> = line.split('\t').collect();
                        if cols.len() >= 2 {
                            println!("    {}", unesc(cols[1]));
                        } else {
                            println!("    {line}");
                        }
                    }
                }
            }
            Err(e) => println!("  {peer}: could not list shares: {e}"),
        }
    }
    if !any_share {
        println!("  none found yet");
    }
    Ok(())
}

fn hash_password(password: &str) -> io::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| err(&format!("argon2 hash failed: {e}")))
}

fn verify_password(password: &str, encoded_hash: &str) -> io::Result<()> {
    let parsed = PasswordHash::new(encoded_hash).map_err(|e| err(&format!("bad password hash: {e}")))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| err("wrong password"))
}

fn derive_account_id(user: &str, password: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"earth-account-v1\0");
    h.update(user.as_bytes());
    h.update(b"\0");
    h.update(password.as_bytes());
    let digest = h.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

fn hostname() -> String {
    env::var("HOSTNAME").unwrap_or_else(|_| "device".to_string())
}

fn load_config() -> io::Result<Config> { load_config_unverified() }

fn load_config_unverified() -> io::Result<Config> {
    parse_config_file(&config_path())
}

fn parse_config_file(p: &Path) -> io::Result<Config> {
    if !p.exists() { return Err(err("not logged in; run earth login <user>")); }
    let mut user = String::new();
    let mut device = String::new();
    let mut password_hash = String::new();
    let mut account_id = String::new();
    let mut port: u16 = 7878;
    for line in read_lines(p)? {
        let parts: Vec<_> = line.splitn(2, '\t').collect();
        if parts.len() == 2 {
            if parts[0] == "user" { user = unesc(parts[1]); }
            if parts[0] == "device" { device = unesc(parts[1]); }
            if parts[0] == "password_hash" { password_hash = unesc(parts[1]); }
            if parts[0] == "account_id" { account_id = unesc(parts[1]); }
            if parts[0] == "port" { port = parts[1].parse().unwrap_or(7878); }
        }
    }
    if user.is_empty() || device.is_empty() || account_id.is_empty() { return Err(err("bad config; run login again")); }
    Ok(Config { user, device, password_hash, account_id, port })
}



fn cmd_init(root: &Path) -> io::Result<()> {
    let cfg = load_config()?;
    if !root.exists() || !root.is_dir() {
        return Err(err("path must be an existing directory for init; use clone for remote shares"));
    }
    let abs = root.canonicalize()?;
    let name = abs.file_name().unwrap_or_default().to_string_lossy().to_string();
    let id = format!("{}-{}", stable_hash(&(cfg.user.clone() + &name)), now_ms());
    let share = Share { id: id.clone(), name: name.clone(), root: abs };
    let mut shares = load_shares()?;
    shares.push(share.clone());
    save_shares(&shares)?;
    fs::create_dir_all(crdts_dir().join(&id))?;
    scan_share(&share)?;
    println!("initialized share '{name}' as {id}");
    Ok(())
}

fn cmd_list(peer: Option<&str>, discover: bool) -> io::Result<()> {
    println!("local shares:");
    for s in load_shares()? {
        println!("  {}	{}	{}", s.id, s.name, s.root.display());
    }
    let mut peers = Vec::new();
    if let Some(addr) = peer { peers.push(addr.to_string()); }
    if discover { peers.extend(discover_peers(Duration::from_secs(5))?); }
    peers.sort();
    peers.dedup();
    for addr in peers {
        println!("remote shares from {addr}:");
        match rpc(&addr, "GET_SHARES
") {
            Ok(resp) => print_indented(&resp),
            Err(e) => println!("  ERR {e}"),
        }
    }
    Ok(())
}

fn cmd_peers(timeout_secs: u64) -> io::Result<()> {
    let peers = discover_peers(Duration::from_secs(timeout_secs))?;
    if peers.is_empty() { println!("no earth peers discovered"); }
    for p in peers { println!("{p}"); }
    Ok(())
}

fn resolve_peer(args: &[String]) -> io::Result<String> {
    if let Some(peer) = opt_value(args, "--peer") { return Ok(peer); }
    if has_flag(args, "--discover") {
        let peers = discover_peers(Duration::from_secs(5))?;
        return peers.into_iter().next().ok_or_else(|| err("no mDNS peers found for this account"));
    }
    Err(err("requires --peer host:port or --discover"))
}

fn cmd_clone(name: &str, root: &Path, peer: &str) -> io::Result<()> {
    if root.exists() { return Err(err("clone target already exists")); }
    let list = rpc(peer, "GET_SHARES\n")?;
    let mut found: Option<(String, String)> = None;
    for line in list.lines() {
        let cols: Vec<_> = line.split('\t').collect();
        if cols.len() >= 2 && cols[1] == name {
            found = Some((cols[0].to_string(), cols[1].to_string()));
            break;
        }
    }
    let (share_id, share_name) = found.ok_or_else(|| err("remote share not found"))?;
    fs::create_dir_all(root)?;
    let share = Share { id: share_id.clone(), name: share_name, root: root.canonicalize()? };
    let mut shares = load_shares()?;
    if !shares.iter().any(|s| s.id == share.id) {
        shares.push(share.clone());
        save_shares(&shares)?;
    }
    let snapshot = rpc(peer, &format!("EXPORT {}\n", share_id))?;
    import_snapshot(&snapshot)?;
    render_share(&share)?;
    println!("cloned {name} into {}", root.display());
    Ok(())
}

struct DaemonLock { path: PathBuf }
impl Drop for DaemonLock {
    fn drop(&mut self) { let _ = fs::remove_file(&self.path); }
}

fn acquire_daemon_lock() -> io::Result<DaemonLock> {
    let path = lock_path();
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut f) => {
            let cfg = load_config()?;
            writeln!(f, "pid\t{}", std::process::id())?;
            writeln!(f, "account\t{}", cfg.account_id)?;
            writeln!(f, "user\t{}", cfg.user)?;
            Ok(DaemonLock { path })
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(err("daemon already appears to be running for this account; use earth status or remove stale account.lock")),
        Err(e) => Err(e),
    }
}

fn cmd_daemon(bind: &str, static_peers: Vec<String>, discover: bool) -> io::Result<()> {
    let cfg = load_config()?;
    let _lock = acquire_daemon_lock()?;
    let _mdns = register_mdns(bind)?;
    let state = Arc::new(Mutex::new(()));
    let shutdown = Arc::new(Mutex::new(false));
    let bind_addr = bind.to_string();
    let server_state = Arc::clone(&state);
    let server_shutdown = Arc::clone(&shutdown);
    thread::spawn(move || {
        if let Err(e) = serve(&bind_addr, server_state, server_shutdown) {
            eprintln!("server error: {e}");
        }
    });
    println!("daemon for {} listening on {bind}; static peers: {:?}; mDNS discovery: {discover}", cfg.user, static_peers);
    loop {
        if *shutdown.lock().unwrap() { break; }
        {
            let _g = state.lock().unwrap();
            // Local scan must not immediately render the same files back to disk.
            // That causes editors like Vim to see an external modification and can
            // race saves with E949. Rendering is done after remote/import activity.
            if let Err(e) = scan_all() {
                eprintln!("scan error: {e}");
            }
        }
        let mut peers = static_peers.clone();
        if discover {
            match discover_peers(Duration::from_secs(2)) {
                Ok(found) => peers.extend(found),
                Err(e) => eprintln!("mDNS discovery failed: {e}"),
            }
        }
        peers.sort();
        peers.dedup();
        for p in &peers {
            let _g = state.lock().unwrap();
            if let Err(e) = sync_peer(p) {
                eprintln!("sync {p} failed: {e}");
            }
            if let Err(e) = render_all() {
                eprintln!("render after sync failed: {e}");
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
    println!("daemon for {} stopped", cfg.user);
    Ok(())
}

fn serve(bind: &str, state: Arc<Mutex<()>>, shutdown: Arc<Mutex<bool>>) -> io::Result<()> {
    let listener = TcpListener::bind(bind)?;
    listener.set_nonblocking(true)?;
    loop {
        if *shutdown.lock().unwrap() { break; }
        match listener.accept() {
            Ok((s, _addr)) => {
                let st = Arc::clone(&state);
                let sd = Arc::clone(&shutdown);
                thread::spawn(move || {
                    let _g = st.lock().unwrap();
                    if let Err(e) = handle_client(s, sd) { eprintln!("client error: {e}"); }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(100)),
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, shutdown: Arc<Mutex<bool>>) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut auth = String::new();
    let mut command = String::new();
    reader.read_line(&mut auth)?;
    reader.read_line(&mut command)?;
    verify_auth_line(auth.trim_end())?;
    let cfg = load_config()?;
    let cmd = command.trim_end().to_string();
    if cmd == "PING" {
        writeln!(stream, "PONG")?;
        writeln!(stream, "user\t{}", cfg.user)?;
        writeln!(stream, "account\t{}", cfg.account_id)?;
        writeln!(stream, "port\t{}", cfg.port)?;
    } else if cmd == "STATUS" {
        writeln!(stream, "status\trunning")?;
        writeln!(stream, "user\t{}", cfg.user)?;
        writeln!(stream, "account\t{}", cfg.account_id)?;
        writeln!(stream, "port\t{}", cfg.port)?;
        writeln!(stream, "shares\t{}", load_shares()?.len())?;
    } else if cmd == "SHUTDOWN" {
        // Localhost-only protection for lifecycle control.
        if stream.peer_addr().map(|a| !a.ip().is_loopback()).unwrap_or(true) {
            writeln!(stream, "ERR shutdown only allowed from localhost")?;
        } else {
            *shutdown.lock().unwrap() = true;
            writeln!(stream, "OK shutting down")?;
        }
    } else if cmd == "GET_SHARES" {
        for s in load_shares()? {
            writeln!(stream, "{}\t{}", s.id, s.name)?;
        }
    } else if let Some(id) = cmd.strip_prefix("EXPORT ") {
        let snap = export_snapshot(Some(id))?;
        stream.write_all(snap.as_bytes())?;
    } else if cmd == "GET_SNAPSHOT" {
        let snap = export_snapshot(None)?;
        stream.write_all(snap.as_bytes())?;
    } else if cmd == "IMPORT_SNAPSHOT" {
        let mut data = String::new();
        reader.read_to_string(&mut data)?;
        import_snapshot(&data)?;
        // Incoming import is remote activity, so render merged state to visible
        // folders. The renderer is hash-guarded and editor-aware, so it will not
        // fight Vim or rewrite unchanged files.
        render_all()?;
        stream.write_all(b"OK\n")?;
    } else {
        writeln!(stream, "ERR unknown command")?;
    }
    Ok(())
}

fn cmd_status(account: Option<String>) -> io::Result<()> {
    ensure_global_dirs()?;
    if let Some(a) = account {
        select_account(Some(a))?;
        print_account_status()?;
        return Ok(());
    }
    let accounts = global_home().join("accounts");
    if !accounts.exists() { println!("no accounts"); return Ok(()); }
    for ent in fs::read_dir(accounts)? {
        let dir = ent?.path();
        if !dir.join("config.tsv").exists() { continue; }
        env::set_var("EARTH_ACCOUNT_DIR", &dir);
        print_account_status()?;
    }
    Ok(())
}

fn print_account_status() -> io::Result<()> {
    let cfg = load_config()?;
    let addr = daemon_addr(&cfg);
    println!("{}", cfg.user);
    println!("  account: {}", cfg.account_id);
    println!("  port: {}", cfg.port);
    match rpc(&addr, "STATUS\n") {
        Ok(resp) => {
            println!("  status: running");
            for line in resp.lines() { println!("  {line}"); }
        }
        Err(_) => println!("  status: stopped"),
    }
    println!("  shares: {}", load_shares().map(|s| s.len()).unwrap_or(0));
    Ok(())
}

fn cmd_stop(account: Option<String>, all: bool) -> io::Result<()> {
    if all {
        let accounts = global_home().join("accounts");
        if accounts.exists() {
            for ent in fs::read_dir(accounts)? {
                let dir = ent?.path();
                if !dir.join("config.tsv").exists() { continue; }
                env::set_var("EARTH_ACCOUNT_DIR", &dir);
                let _ = stop_current_account();
            }
        }
        return Ok(());
    }
    select_account(account)?;
    stop_current_account()
}

fn stop_current_account() -> io::Result<()> {
    let cfg = load_config()?;
    let addr = daemon_addr(&cfg);
    match rpc(&addr, "SHUTDOWN\n") {
        Ok(resp) => print!("{resp}"),
        Err(e) => println!("{} daemon not running or unreachable: {e}", cfg.user),
    }
    Ok(())
}



fn rpc(addr: &str, msg: &str) -> io::Result<String> {
    let mut s = TcpStream::connect(addr)?;
    s.write_all(auth_line()?.as_bytes())?;
    s.write_all(msg.as_bytes())?;
    s.shutdown(std::net::Shutdown::Write).ok();
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    Ok(out)
}

fn auth_line() -> io::Result<String> {
    let cfg = load_config()?;
    Ok(format!("AUTH	{}	{}	{}
", esc(&cfg.user), esc(&cfg.account_id), esc(&cfg.device)))
}

fn verify_auth_line(line: &str) -> io::Result<()> {
    let cfg = load_config()?;
    let cols: Vec<_> = line.split('\t').collect();
    if cols.len() < 4 || cols[0] != "AUTH" { return Err(err("missing AUTH header")); }
    let remote_user = unesc(cols[1]);
    let remote_account = unesc(cols[2]);
    if remote_user != cfg.user || remote_account != cfg.account_id {
        return Err(err("peer is not authenticated for this account"));
    }
    Ok(())
}

fn sync_peer(addr: &str) -> io::Result<()> {
    let remote = rpc(addr, "GET_SNAPSHOT\n")?;
    import_snapshot(&remote)?;
    let mine = export_snapshot(None)?;
    let mut s = TcpStream::connect(addr)?;
    s.write_all(auth_line()?.as_bytes())?;
    s.write_all(b"IMPORT_SNAPSHOT\n")?;
    s.write_all(mine.as_bytes())?;
    s.shutdown(std::net::Shutdown::Write).ok();
    let mut resp = String::new();
    s.read_to_string(&mut resp)?;
    Ok(())
}


fn register_mdns(bind: &str) -> io::Result<Option<ServiceDaemon>> {
    let cfg = load_config()?;
    let port = bind.parse::<SocketAddr>().map(|a| a.port()).unwrap_or_else(|_| {
        bind.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(7878)
    });
    let mdns = ServiceDaemon::new().map_err(|e| err(&format!("mDNS daemon failed: {e}")))?;
    let host = format!("{}.local.", cfg.device.replace('_', "-").replace(' ', "-"));
    let instance = format!("{}-{}", cfg.user, cfg.device);
    let props = [
        ("user", cfg.user.as_str()),
        ("account", cfg.account_id.as_str()),
        ("device", cfg.device.as_str()),
        ("proto", "earth-v1"),
    ];
    let info = ServiceInfo::new(MDNS_SERVICE, &instance, &host, "0.0.0.0", port, &props[..])
        .map_err(|e| err(&format!("mDNS service info failed: {e}")))?
        .enable_addr_auto();
    mdns.register(info).map_err(|e| err(&format!("mDNS register failed: {e}")))?;
    Ok(Some(mdns))
}

fn discover_peers(timeout: Duration) -> io::Result<Vec<String>> {
    let cfg = load_config()?;
    let mdns = ServiceDaemon::new().map_err(|e| err(&format!("mDNS daemon failed: {e}")))?;
    let receiver = mdns.browse(MDNS_SERVICE).map_err(|e| err(&format!("mDNS browse failed: {e}")))?;
    let deadline = Instant::now() + timeout;
    let mut peers = BTreeSet::new();
    while Instant::now() < deadline {
        let left = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(left.min(Duration::from_millis(250))) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let remote_account = info.get_property_val_str("account").unwrap_or_default();
                let remote_device = info.get_property_val_str("device").unwrap_or_default();
                if remote_account != cfg.account_id || remote_device == cfg.device { continue; }
                let port = info.get_port();
                for ip in info.get_addresses() {
                    if ip.is_loopback() { continue; }
                    peers.insert(format!("{}:{}", ip, port));
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let _ = mdns.shutdown();
    Ok(peers.into_iter().collect())
}

fn load_shares() -> io::Result<Vec<Share>> {
    let p = shares_path();
    if !p.exists() { return Ok(Vec::new()); }
    let mut out = Vec::new();
    for line in read_lines(&p)? {
        let cols: Vec<_> = line.split('\t').collect();
        if cols.len() >= 3 {
            out.push(Share { id: unesc(cols[0]), name: unesc(cols[1]), root: PathBuf::from(unesc(cols[2])) });
        }
    }
    Ok(out)
}

fn save_shares(shares: &[Share]) -> io::Result<()> {
    let mut s = String::new();
    for sh in shares {
        s.push_str(&format!("{}\t{}\t{}\n", esc(&sh.id), esc(&sh.name), esc(&sh.root.display().to_string())));
    }
    write_string(shares_path(), &s)
}

fn manifest_path(share_id: &str) -> PathBuf { manifests_dir().join(format!("{share_id}.manifest")) }

fn load_manifest(share_id: &str) -> io::Result<BTreeMap<String, ManifestEntry>> {
    let p = manifest_path(share_id);
    if !p.exists() { return Ok(BTreeMap::new()); }
    let mut m = BTreeMap::new();
    for line in read_lines(&p)? {
        let cols: Vec<_> = line.split('\t').collect();
        if cols.len() >= 5 {
            let path = unesc(cols[0]);
            m.insert(path.clone(), ManifestEntry {
                path,
                kind: unesc(cols[1]),
                object: unesc(cols[2]),
                mtime: cols[3].parse().unwrap_or(0),
                size: cols[4].parse().unwrap_or(0),
            });
        }
    }
    Ok(m)
}

fn save_manifest(share_id: &str, m: &BTreeMap<String, ManifestEntry>) -> io::Result<()> {
    let mut s = String::new();
    for e in m.values() {
        s.push_str(&format!("{}\t{}\t{}\t{}\t{}\n", esc(&e.path), esc(&e.kind), esc(&e.object), e.mtime, e.size));
    }
    write_string(manifest_path(share_id), &s)
}

fn scan_all() -> io::Result<()> {
    for s in load_shares()? { scan_share(&s)?; }
    Ok(())
}

fn scan_share(share: &Share) -> io::Result<()> {
    fs::create_dir_all(crdts_dir().join(&share.id))?;
    let mut manifest = load_manifest(&share.id)?;
    // Drop editor temp/backup files from the manifest so older versions stop
    // advertising them after the next scan. This does not delete the user
    // local temp files; it only prevents syncing/rendering them.
    manifest.retain(|rel, _| !is_ignored_rel(rel));

    let mut files = Vec::new();
    collect_files(&share.root, &share.root, &mut files)?;
    let mut seen = BTreeSet::new();

    for path in files {
        let rel = path.strip_prefix(&share.root).unwrap().to_string_lossy().replace('\\', "/");
        seen.insert(rel.clone());

        // If an editor has this file open, do not import half-written state.
        // Vim creates .file.swp/.swo/etc.; remote renders are also deferred while
        // those files exist.
        if has_active_editor_marker(&path) { continue; }

        // Avoid racing editor save cycles. Editors often write, rename, chmod,
        // and touch within a short window. Wait until the file is stable before
        // importing it into CRDT/blob state.
        let meta = fs::metadata(&path)?;
        if !is_file_stable(&meta, Duration::from_millis(1200)) { continue; }

        let mtime = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        let size = meta.len();
        let is_text = is_text_path(&path);
        if is_text {
            let object = format!("{}.crdt", stable_hash(&rel));
            let changed = manifest.get(&rel).map(|e| e.mtime != mtime || e.size != size).unwrap_or(true);
            if changed {
                let text = fs::read_to_string(&path).unwrap_or_else(|_| String::new());
                let doc_path = crdts_dir().join(&share.id).join(&object);
                let mut doc = load_doc(&doc_path)?;
                let cfg = load_config()?;
                doc.apply_local_text(&text, &cfg.device);
                save_doc(&doc_path, &doc)?;
            }
            manifest.insert(rel.clone(), ManifestEntry { path: rel, kind: "text".into(), object, mtime, size });
        } else {
            let hash = file_hash(&path)?;
            let blob_path = blobs_dir().join(&hash);
            if !blob_path.exists() { fs::copy(&path, blob_path)?; }
            manifest.insert(rel.clone(), ManifestEntry { path: rel, kind: "blob".into(), object: hash, mtime, size });
        }
    }

    // Basic delete support: if a file vanished locally, stop advertising it.
    // Tombstones would be better long-term, but this prevents deleted files from
    // being recreated by local render loops.
    manifest.retain(|rel, _| seen.contains(rel) || is_ignored_rel(rel));
    manifest.retain(|rel, _| !is_ignored_rel(rel));

    save_manifest(&share.id, &manifest)?;
    Ok(())
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let p = ent.path();
        if p.is_dir() {
            if is_ignored_path(&p, true) { continue; }
            collect_files(root, &p, out)?;
        } else if p.is_file() {
            if is_ignored_path(&p, false) { continue; }
            out.push(p);
        }
    }
    let _ = root;
    Ok(())
}

fn is_text_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| TEXT_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

fn is_file_stable(meta: &fs::Metadata, quiet_for: Duration) -> bool {
    match meta.modified() {
        Ok(modified) => SystemTime::now()
            .duration_since(modified)
            .map(|age| age >= quiet_for)
            .unwrap_or(true),
        Err(_) => true,
    }
}

fn has_active_editor_marker(path: &Path) -> bool {
    let Some(parent) = path.parent() else { return false; };
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return false; };

    // Vim swap files for test.txt are usually .test.txt.swp, .test.txt.swo, ...
    for suffix in ["swp", "swo", "swn", "swm", "swl", "swk", "swj", "swi", "swh", "swg", "swf", "swe", "swd", "swc", "swb", "swa"] {
        if parent.join(format!(".{name}.{suffix}")).exists() { return true; }
    }

    // Emacs lock file.
    if parent.join(format!(".#{name}")).exists() { return true; }

    false
}

fn write_visible_bytes(path: &Path, data: &[u8]) -> io::Result<()> {
    if is_ignored_rel(&path.to_string_lossy()) { return Ok(()); }

    if has_active_editor_marker(path) {
        eprintln!("defer render while editor is active: {}", path.display());
        return Ok(());
    }

    if path_content_equals(path, data)? {
        return Ok(());
    }

    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = path.parent().unwrap_or_else(|| Path::new(".")).join(format!(".{name}.earth.tmp"));
    fs::write(&tmp, data)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn render_all() -> io::Result<()> {
    for s in load_shares()? { render_share(&s)?; }
    Ok(())
}

fn render_share(share: &Share) -> io::Result<()> {
    let manifest = load_manifest(&share.id)?;
    for e in manifest.values() {
        if is_ignored_rel(&e.path) { continue; }
        let out_path = share.root.join(&e.path);
        if let Some(parent) = out_path.parent() { fs::create_dir_all(parent)?; }
        if e.kind == "text" {
            let doc = load_doc(&crdts_dir().join(&share.id).join(&e.object))?;
            write_visible_bytes(&out_path, doc.render().as_bytes())?;
        } else if e.kind == "blob" {
            let src = blobs_dir().join(&e.object);
            if src.exists() {
                let bytes = fs::read(src)?;
                write_visible_bytes(&out_path, &bytes)?;
            }
        }
    }
    Ok(())
}

fn export_snapshot(only_share: Option<&str>) -> io::Result<String> {
    let mut out = String::new();
    out.push_str("SNAPSHOT 1\n");
    for s in load_shares()? {
        if only_share.map(|id| id != s.id).unwrap_or(false) { continue; }
        out.push_str(&format!("SHARE\t{}\t{}\n", esc(&s.id), esc(&s.name)));
        let man = manifest_path(&s.id);
        if man.exists() { add_file_record(&mut out, "MANIFEST", &s.id, &man)?; }
        let cdir = crdts_dir().join(&s.id);
        if cdir.exists() {
            for ent in fs::read_dir(cdir)? {
                let p = ent?.path();
                if p.is_file() { add_file_record(&mut out, "CRDT", &s.id, &p)?; }
            }
        }
    }
    for ent in fs::read_dir(blobs_dir())? {
        let p = ent?.path();
        if p.is_file() { add_file_record(&mut out, "BLOB", "_", &p)?; }
    }
    out.push_str("END\n");
    Ok(out)
}

fn add_file_record(out: &mut String, kind: &str, share: &str, p: &Path) -> io::Result<()> {
    let name = p.file_name().unwrap_or_default().to_string_lossy();
    let bytes = fs::read(p)?;
    out.push_str(&format!("FILE\t{}\t{}\t{}\t{}\n", kind, esc(share), esc(&name), hex(&bytes)));
    Ok(())
}

fn import_snapshot(data: &str) -> io::Result<()> {
    let mut remote_shares: Vec<(String, String)> = Vec::new();
    for line in data.lines() {
        if line == "SNAPSHOT 1" || line == "END" || line.is_empty() { continue; }
        let cols: Vec<_> = line.split('\t').collect();
        if cols.is_empty() { continue; }
        match cols[0] {
            "SHARE" if cols.len() >= 3 => remote_shares.push((unesc(cols[1]), unesc(cols[2]))),
            "FILE" if cols.len() >= 5 => {
                let kind = cols[1];
                let share = unesc(cols[2]);
                let name = unesc(cols[3]);
                let bytes = unhex(cols[4])?;
                match kind {
                    "MANIFEST" => {
                        let path = manifest_path(&share);
                        if path.exists() {
                            let local = fs::read_to_string(&path)?;
                            let remote = String::from_utf8_lossy(&bytes).to_string();
                            let merged = merge_manifests_text(&local, &remote);
                            write_string(path, &merged)?;
                        } else { write_bytes(path, &bytes)?; }
                    }
                    "CRDT" => {
                        let path = crdts_dir().join(&share).join(&name);
                        fs::create_dir_all(path.parent().unwrap())?;
                        if path.exists() {
                            let mut a = load_doc(&path)?;
                            let b = parse_doc(&String::from_utf8_lossy(&bytes));
                            a.merge(&b);
                            save_doc(&path, &a)?;
                        } else { write_bytes(path, &bytes)?; }
                    }
                    "BLOB" => {
                        let path = blobs_dir().join(&name);
                        if !path.exists() { write_bytes(path, &bytes)?; }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    // Remember remote share names without overwriting local paths. Clone creates the local mapping.
    let mut known = load_remote_shares()?;
    for (id, name) in remote_shares { known.insert(id, name); }
    save_remote_shares(&known)?;
    Ok(())
}

fn remote_shares_path() -> PathBuf { program_home().join("remote_shares.tsv") }

fn load_remote_shares() -> io::Result<BTreeMap<String, String>> {
    let p = remote_shares_path();
    if !p.exists() { return Ok(BTreeMap::new()); }
    let mut m = BTreeMap::new();
    for line in read_lines(&p)? {
        let cols: Vec<_> = line.split('\t').collect();
        if cols.len() >= 2 { m.insert(unesc(cols[0]), unesc(cols[1])); }
    }
    Ok(m)
}

fn save_remote_shares(m: &BTreeMap<String, String>) -> io::Result<()> {
    let mut s = String::new();
    for (id, name) in m { s.push_str(&format!("{}\t{}\n", esc(id), esc(name))); }
    write_string(remote_shares_path(), &s)
}

fn merge_manifests_text(a: &str, b: &str) -> String {
    let mut rows: BTreeMap<String, String> = BTreeMap::new();
    for line in a.lines().chain(b.lines()) {
        let key = line.split('\t').next().unwrap_or("").to_string();
        if !key.is_empty() { rows.insert(key, line.to_string()); }
    }
    let mut out = String::new();
    for (_, row) in rows { out.push_str(&row); out.push('\n'); }
    out
}

impl TextDoc {
    fn empty() -> Self { Self { clock: 0, lines: BTreeMap::new() } }

    fn render_lines_with_ids(&self) -> Vec<(String, String)> {
        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for id in self.lines.keys() {
            let parent = self.lines[id].parent.clone();
            children.entry(parent).or_default().push(id.clone());
        }
        for v in children.values_mut() { v.sort(); }
        let mut out = Vec::new();
        fn walk(id: &str, children: &BTreeMap<String, Vec<String>>, lines: &BTreeMap<String, Line>, out: &mut Vec<(String, String)>) {
            if let Some(kids) = children.get(id) {
                for kid in kids {
                    if let Some(line) = lines.get(kid) {
                        if !line.tombstone { out.push((line.id.clone(), line.text.clone())); }
                        walk(kid, children, lines, out);
                    }
                }
            }
        }
        walk(ROOT, &children, &self.lines, &mut out);
        out
    }

    fn render(&self) -> String {
        let lines: Vec<String> = self.render_lines_with_ids().into_iter().map(|(_, t)| t).collect();
        if lines.is_empty() { String::new() } else { format!("{}\n", lines.join("\n")) }
    }

    fn apply_local_text(&mut self, new_text: &str, device: &str) {
        let old = self.render_lines_with_ids();
        let old_text: Vec<String> = old.iter().map(|(_, t)| t.clone()).collect();
        let mut new_lines: Vec<String> = new_text.split('\n').map(|s| s.to_string()).collect();
        if new_lines.last().map(|s| s.is_empty()).unwrap_or(false) { new_lines.pop(); }
        let pairs = lcs_pairs(&old_text, &new_lines);
        let matched_old: BTreeSet<usize> = pairs.iter().map(|(i, _)| *i).collect();
        let matched_new: BTreeSet<usize> = pairs.iter().map(|(_, j)| *j).collect();
        for (i, (id, _)) in old.iter().enumerate() {
            if !matched_old.contains(&i) {
                if let Some(line) = self.lines.get_mut(id) { line.tombstone = true; }
            }
        }
        let mut new_to_prev_id: HashMap<usize, String> = HashMap::new();
        let mut prev = ROOT.to_string();
        let mut pi = 0;
        for j in 0..new_lines.len() {
            if let Some((oi, _)) = pairs.iter().find(|(_, jj)| *jj == j) {
                prev = old[*oi].0.clone();
                pi += 1;
            } else {
                new_to_prev_id.insert(j, prev.clone());
            }
            let _ = pi;
        }
        for j in 0..new_lines.len() {
            if matched_new.contains(&j) { continue; }
            self.clock += 1;
            let id = format!("{:020}@{}", self.clock, device);
            let parent = new_to_prev_id.get(&j).cloned().unwrap_or_else(|| ROOT.to_string());
            let line = Line { id: id.clone(), parent, tombstone: false, text: new_lines[j].clone() };
            self.lines.insert(id.clone(), line);
            // Chain consecutive insertions in local order.
            for k in (j+1)..new_lines.len() {
                if !matched_new.contains(&k) {
                    new_to_prev_id.insert(k, id.clone());
                    break;
                } else { break; }
            }
        }
    }

    fn merge(&mut self, other: &TextDoc) {
        self.clock = self.clock.max(other.clock);
        for (id, line) in &other.lines {
            match self.lines.get_mut(id) {
                Some(l) => l.tombstone = l.tombstone || line.tombstone,
                None => { self.lines.insert(id.clone(), line.clone()); }
            }
        }
    }
}

fn lcs_pairs(a: &[String], b: &[String]) -> Vec<(usize, usize)> {
    let n = a.len();
    let m = b.len();
    let mut dp = vec![vec![0u16; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] { dp[i + 1][j + 1] + 1 } else { dp[i + 1][j].max(dp[i][j + 1]) };
        }
    }
    let mut i = 0; let mut j = 0; let mut out = Vec::new();
    while i < n && j < m {
        if a[i] == b[j] { out.push((i, j)); i += 1; j += 1; }
        else if dp[i + 1][j] >= dp[i][j + 1] { i += 1; }
        else { j += 1; }
    }
    out
}

fn load_doc(path: &Path) -> io::Result<TextDoc> {
    if !path.exists() { return Ok(TextDoc::empty()); }
    let s = fs::read_to_string(path)?;
    Ok(parse_doc(&s))
}

fn parse_doc(s: &str) -> TextDoc {
    let mut doc = TextDoc::empty();
    for line in s.lines() {
        let cols: Vec<_> = line.split('\t').collect();
        if cols.is_empty() { continue; }
        if cols[0] == "clock" && cols.len() >= 2 { doc.clock = cols[1].parse().unwrap_or(0); }
        if cols[0] == "line" && cols.len() >= 5 {
            let id = unesc(cols[1]);
            doc.lines.insert(id.clone(), Line {
                id,
                parent: unesc(cols[2]),
                tombstone: cols[3] == "1",
                text: String::from_utf8(unhex(cols[4]).unwrap_or_default()).unwrap_or_default(),
            });
        }
    }
    doc
}

fn save_doc(path: &Path, doc: &TextDoc) -> io::Result<()> {
    if let Some(p) = path.parent() { fs::create_dir_all(p)?; }
    let mut s = format!("clock\t{}\n", doc.clock);
    for line in doc.lines.values() {
        s.push_str(&format!("line\t{}\t{}\t{}\t{}\n", esc(&line.id), esc(&line.parent), if line.tombstone {"1"} else {"0"}, hex(line.text.as_bytes())));
    }
    write_string(path, &s)
}

fn read_lines(path: &Path) -> io::Result<Vec<String>> {
    Ok(fs::read_to_string(path)?.lines().map(|s| s.to_string()).collect())
}

fn write_string<P: AsRef<Path>>(path: P, data: &str) -> io::Result<()> { write_bytes(path, data.as_bytes()) }
fn write_bytes<P: AsRef<Path>>(path: P, data: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    if path_content_equals(path, data).unwrap_or(false) { return Ok(()); }
    if let Some(p) = path.parent() { fs::create_dir_all(p)?; }
    let tmp = path.with_extension("tmp-earth");
    fs::write(&tmp, data)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn esc(s: &str) -> String { s.replace('%', "%25").replace('\t', "%09").replace('\n', "%0A") }
fn unesc(s: &str) -> String { s.replace("%0A", "\n").replace("%09", "\t").replace("%25", "%") }
fn hex(bytes: &[u8]) -> String {
    const CH: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len()*2);
    for &b in bytes { out.push(CH[(b>>4) as usize] as char); out.push(CH[(b&0xf) as usize] as char); }
    out
}
fn unhex(s: &str) -> io::Result<Vec<u8>> {
    if s.len() % 2 != 0 { return Err(err("bad hex")); }
    let mut out = Vec::new();
    let bs = s.as_bytes();
    for i in (0..s.len()).step_by(2) {
        let hi = hexval(bs[i])?; let lo = hexval(bs[i+1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}
fn hexval(b: u8) -> io::Result<u8> {
    match b { b'0'..=b'9' => Ok(b-b'0'), b'a'..=b'f' => Ok(b-b'a'+10), b'A'..=b'F' => Ok(b-b'A'+10), _ => Err(err("bad hex digit")) }
}

fn print_indented(s: &str) {
    for line in s.lines() { println!("  {line}"); }
}
