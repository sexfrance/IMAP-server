use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tracing::{debug, error, info, warn};
use tracing_subscriber;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use dotenv::dotenv;

/// Supabase config holder
#[derive(Clone)]
struct Config {
    url: String,
    key: String,
    use_bans: bool,
    use_domains: bool,
}

// SupabaseUser / ImapToken structs were the JSON shapes returned by
// the old REST-based verify_user. Now that verify_user uses a direct
// SQL JOIN and returns a plain tuple, neither struct has any
// consumer left — removed to keep the type surface honest.

#[derive(Debug, Deserialize, Clone, sqlx::FromRow)]
struct Inbox {
    email_address: String,
}

#[derive(Debug, Deserialize, Clone, sqlx::FromRow)]
struct Domain {
    domain: String,
    user_id: String,
    active: bool,
    cloudflare_domain: bool,
}

/// Cache structure for domains
#[derive(Clone)]
struct DomainsCache {
    pool: PgPool,
    config: Config,
    domains: Arc<Mutex<Vec<Domain>>>,
    last_updated: Arc<Mutex<SystemTime>>,
}

impl DomainsCache {
    fn new(pool: PgPool, config: Config) -> Self {
        Self {
            pool,
            config,
            domains: Arc::new(Mutex::new(Vec::new())),
            last_updated: Arc::new(Mutex::new(SystemTime::UNIX_EPOCH)),
        }
    }

    async fn get_domains(&self) -> Result<Vec<Domain>> {
        let mut domains_guard = self.domains.lock().await;
        let mut last_updated_guard = self.last_updated.lock().await;

        if last_updated_guard.elapsed().unwrap_or(Duration::from_secs(61)) > Duration::from_secs(60)
        {
            info!("🔄 Domains cache is stale, refreshing...");

            match fetch_all_domains(&self.config, &self.pool).await {
                Ok(new_domains) => {
                    *domains_guard = new_domains;
                    *last_updated_guard = SystemTime::now();
                    info!("✅ Domains cache refreshed with {} domains", domains_guard.len());
                }
                Err(e) => {
                    error!("❌ Failed to refresh domains cache: {}", e);
                    if domains_guard.is_empty() {
                        return Err(e);
                    }
                    info!("🔄 Using stale cache due to refresh failure");
                }
            }
        } else {
            debug!("✅ Using cached domains data ({} domains)", domains_guard.len());
        }

        Ok(domains_guard.clone())
    }
}

/// Check for an active email ban
async fn is_email_banned(config: &Config, pool: &PgPool, email: &str) -> bool {
    if config.use_bans {
        let client = reqwest::Client::new();
        let url = format!("{}/rest/v1/bans?scope=eq.email&value=eq.{}&status=eq.active", config.url, email);
        match client
            .get(&url)
            .header("apikey", &config.key)
            .header("Authorization", format!("Bearer {}", config.key))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<Vec<serde_json::Value>>().await {
                        Ok(rows) => return !rows.is_empty(),
                        Err(_) => return false,
                    }
                }
                false
            }
            Err(_) => false,
        }
    } else {
        // Local PostgreSQL
        let result: Result<Vec<(String, String)>, _> = sqlx::query_as(
            "SELECT value, match_type FROM bans WHERE status = 'active' AND scope = 'email'",
        )
        .fetch_all(pool)
        .await;
        match result {
            Ok(bans) => {
                let email_lower = email.to_lowercase();
                for (value, match_type) in bans {
                    let v_lower = value.to_lowercase();
                    if match_type == "contains" {
                        if email_lower.contains(&v_lower) {
                            return true;
                        }
                    } else {
                        if email_lower == v_lower {
                            return true;
                        }
                    }
                }
                false
            }
            Err(_) => false,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    tracing_subscriber::fmt::init();
    info!("starting IMAP server...");

    let bind_addr = std::env::var("IMAP_BIND").unwrap_or_else(|_| "0.0.0.0:143".to_string());

    let _: SocketAddr = bind_addr
        .parse()
        .context("IMAP_BIND must be in format IP:PORT (e.g., 0.0.0.0:143)")?;

    // Supabase config is now optional. The auth-critical path
    // (`verify_user`) talks directly to Postgres; the remaining
    // Supabase REST callers (bans, domains, sender-bans) already
    // have Postgres fallback paths gated on USE_SUPABASE_BANS /
    // USE_SUPABASE_DOMAINS. Defaulting both flags to "false" so a
    // fresh deploy without any SUPABASE_* env vars set is fully
    // self-hosted by default — old deploys that have the vars set
    // still work unchanged.
    let supabase_config = Config {
        url: std::env::var("SUPABASE_URL").unwrap_or_default(),
        key: std::env::var("SUPABASE_SERVICE_KEY")
            .or_else(|_| std::env::var("SUPABASE_KEY"))
            .unwrap_or_default(),
        use_bans: std::env::var("USE_SUPABASE_BANS").unwrap_or_else(|_| "false".to_string()) == "true",
        use_domains: std::env::var("USE_SUPABASE_DOMAINS").unwrap_or_else(|_| "false".to_string()) == "true",
    };
    if supabase_config.use_bans || supabase_config.use_domains {
        if supabase_config.url.is_empty() || supabase_config.key.is_empty() {
            anyhow::bail!(
                "USE_SUPABASE_BANS / USE_SUPABASE_DOMAINS is set but SUPABASE_URL or \
                 SUPABASE_SERVICE_KEY is missing. Either populate both or set both \
                 USE_SUPABASE_* flags to false to use Postgres-only mode.",
            );
        }
    } else {
        info!("✓ Self-hosted Postgres mode (Supabase REST disabled for bans + domains)");
    }

    let database_url = std::env::var("DATABASE_URL")?;

    let pool = PgPool::connect(&database_url).await.context("Failed to connect to database")?;
    info!("connected to database");

    let listener = TcpListener::bind(&bind_addr).await.with_context(|| format!("Failed to bind to {}", bind_addr))?;
    info!("IMAP server listening on {}", bind_addr);

    let global_state = Arc::new(Mutex::new(HashMap::<String, u64>::new()));

    let domains_cache = DomainsCache::new(pool.clone(), supabase_config.clone());

    loop {
        let (stream, addr) = listener.accept().await?;
        let pool = pool.clone();
        let supabase_config = supabase_config.clone();
        let global_state = Arc::clone(&global_state);
        let domains_cache = domains_cache.clone();

        info!("New connection from {}", addr);

        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, addr, pool, supabase_config.clone(), global_state, domains_cache).await {
                error!("connection error from {}: {:?}", addr, e);
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    addr: SocketAddr,
    pool: PgPool,
    config: Config,
    _global_state: Arc<Mutex<HashMap<String, u64>>>,
    domains_cache: DomainsCache,
) -> Result<()> {
    let peer = format!("{}", addr);
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();

    // Initial OK greeting
    w.write_all(b"* OK Rust IMAP server ready\r\n").await?;
    w.flush().await?;

    let mut authenticated_user: Option<String> = None;
    let mut selected_mailbox: Option<String> = None;
    let mut user_id: Option<String> = None;

    let mut seen_valid_imap = false;

    loop {
        line.clear();
        let n = match reader.read_line(&mut line).await {
            Ok(n) => n,
            Err(e) => {
                if e.to_string().contains("UTF-8") {
                    info!("[{}] client sent non-UTF-8 data, closing connection", peer);
                    return Ok(());
                }
                return Err(e.into());
            }
        };
        if n == 0 {
            info!("[{}] client disconnected", peer);
            return Ok(());
        }

        let received_raw = line.trim_end().to_string();
        if received_raw.is_empty() {
            continue;
        }

        info!(%peer, %received_raw, "recv");

        // Some clients or middleboxes may echo server responses back into the stream;
        // these typically start with "OK ", "NO ", or "BAD ". Ignore them to avoid
        // parsing them as commands.
        let trimmed = received_raw.trim();
        if !seen_valid_imap {
            if trimmed.starts_with("GET ")
                || trimmed.starts_with("POST ")
                || trimmed.starts_with("PUT ")
                || trimmed.starts_with("DELETE ")
                || trimmed.starts_with("HEAD ")
                || trimmed.starts_with("OPTIONS ")
                || trimmed.starts_with("HTTP/")
            {
                info!("[{}] rejecting HTTP request, closing connection", peer);
                w.write_all(b"* BAD This is an IMAP server, not HTTP\r\n").await?;
                w.flush().await?;
                return Ok(());
            }
        }

        // Ignore echoed server responses
        if trimmed.starts_with("OK ") || trimmed.starts_with("NO ") || trimmed.starts_with("BAD ") {
            info!(%peer, echoed=%trimmed, "ignoring echoed server response from client");
            continue;
        }

        let mut parts = trimmed.splitn(3, ' ');
        let tag = parts.next().unwrap_or("").to_string();
        let cmd = parts.next().unwrap_or("").to_uppercase();
        let args = parts.next().unwrap_or("").to_string();

        info!(%peer, tag=%tag, cmd=%cmd, args=%args, "parsed_command");

        match cmd.as_str() {
            "" => {
                w.write_all(format!("{} BAD Empty command\r\n", tag).as_bytes()).await?;
            }
            "CAPABILITY" => {
                seen_valid_imap = true;
                w.write_all(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS MOVE IDLE LITERAL+\r\n").await?;
                w.write_all(format!("{} OK CAPABILITY completed\r\n", tag).as_bytes()).await?;
            }
            "NOOP" => {
                seen_valid_imap = true;
                w.write_all(format!("{} OK NOOP completed\r\n", tag).as_bytes()).await?;
            }
            "LOGOUT" => {
                w.write_all(b"* BYE IMAP server logging out\r\n").await?;
                w.write_all(format!("{} OK LOGOUT completed\r\n", tag).as_bytes()).await?;
                w.flush().await?;
                info!("[{}] client logged out", peer);
                return Ok(());
            }
            "LOGIN" => {
                seen_valid_imap = true;
                if authenticated_user.is_some() {
                    w.write_all(format!("{} NO Already authenticated\r\n", tag).as_bytes()).await?;
                    continue;
                }

                let login_args: Vec<&str> = args.split_whitespace().collect();
                info!(%peer, login_args=?login_args, "login_args");

                if login_args.len() < 2 {
                    w.write_all(format!("{} BAD LOGIN requires user and password\r\n", tag).as_bytes()).await?;
                    continue;
                }
                let user = login_args[0].trim_matches('"').to_string();
                let pass = login_args[1].trim_matches('"').to_string();

                info!(%peer, user=%user, "attempting login");
                match verify_user(&pool, &user, &pass).await {
                    Ok((user_id_result, user_email)) => {
                        authenticated_user = Some(user_email.clone());
                        user_id = Some(user_id_result);
                        w.write_all(format!("{} OK LOGIN completed\r\n", tag).as_bytes()).await?;
                        info!(%peer, user=%user, "login success");
                    }
                    Err(e) => {
                        w.write_all(format!("{} NO LOGIN failed: {}\r\n", tag, e).as_bytes()).await?;
                        info!(%peer, user=%user, error=%e, "login failed");
                    }
                }
            }
            "LIST" => {
                seen_valid_imap = true;
                if authenticated_user.is_none() || user_id.is_none() {
                    w.write_all(format!("{} NO Not authenticated\r\n", tag).as_bytes()).await?;
                    continue;
                }

                info!("🔍 Fetching inboxes for user_id: {}", user_id.as_ref().unwrap());

                // Get ONLY the user's inboxes from Supabase
                let inboxes = get_user_inboxes(&config, &pool, user_id.as_ref().unwrap()).await;
                match inboxes {
                    Ok(user_inboxes) => {
                        info!("📧 Found {} inboxes for user", user_inboxes.len());

                        if user_inboxes.is_empty() {
                            info!("[{}] No inboxes found for user", peer);
                            w.write_all(b"* LIST (\\NoInferiors) \"/\" \"INBOX\"\r\n").await?;
                        } else {
                            for inbox in user_inboxes {
                                info!("📬 Listing inbox: {}", inbox.email_address);
                                w.write_all(
                                    format!("* LIST (\\HasNoChildren) \"/\" \"{}\"\r\n", inbox.email_address)
                                        .as_bytes(),
                                )
                                .await?;
                            }
                        }
                        w.write_all(format!("{} OK LIST completed\r\n", tag).as_bytes()).await?;
                    }
                    Err(e) => {
                        error!("Failed to get user inboxes from Supabase: {}", e);
                        w.write_all(format!("{} NO Failed to get mailboxes\r\n", tag).as_bytes()).await?;
                    }
                }
            }
            "SELECT" => {
                seen_valid_imap = true;
                if authenticated_user.is_none() {
                    w.write_all(format!("{} NO Not authenticated\r\n", tag).as_bytes()).await?;
                    continue;
                }

                let mailbox_name = args.trim().trim_matches('"').to_string();
                if mailbox_name.is_empty() {
                    w.write_all(format!("{} BAD SELECT requires mailbox name\r\n", tag).as_bytes()).await?;
                    continue;
                }

                info!(%peer, mailbox=%mailbox_name, "attempting to select mailbox");

                // Deny selection if the mailbox address is explicitly banned
                if is_email_banned(&config, &pool, &mailbox_name).await {
                    w.write_all(format!("{} NO Mailbox is banned\r\n", tag).as_bytes()).await?;
                    continue;
                }

                // Get email count from PostgreSQL (can be 0 - that's fine!)
                let email_count = get_email_count(&pool, &mailbox_name).await.unwrap_or(0);
                let unseen_count = get_unseen_count(&pool, &mailbox_name).await.unwrap_or(0);

                w.write_all(format!("* {} EXISTS\r\n", email_count).as_bytes()).await?;
                w.write_all(format!("* {} RECENT\r\n", 0).as_bytes()).await?;
                w.write_all(b"* OK [UNSEEN ").await?;
                w.write_all(unseen_count.to_string().as_bytes()).await?;
                w.write_all(b"]\r\n").await?;
                w.write_all(b"* OK [UIDVALIDITY 1] UIDs valid\r\n").await?;
                w.write_all(b"* OK [UIDNEXT 1000] Predicted next UID\r\n").await?;
                w.write_all(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n").await?;
                w.write_all(format!("{} OK [READ-WRITE] SELECT completed\r\n", tag).as_bytes()).await?;

                selected_mailbox = Some(mailbox_name.clone());
                info!(%peer, mailbox=%mailbox_name, count=%email_count, "mailbox selected successfully");
            }
            "FETCH" => {
                // Support FETCH with various data items: BODY[], BODY.PEEK[TEXT], etc.
                seen_valid_imap = true;
                if authenticated_user.is_none() {
                    w.write_all(format!("{} NO Not authenticated\r\n", tag).as_bytes()).await?;
                    continue;
                }

                if selected_mailbox.is_none() {
                    w.write_all(format!("{} NO No mailbox selected\r\n", tag).as_bytes()).await?;
                    continue;
                }

                let mailbox = selected_mailbox.as_ref().unwrap();
                let emails = get_emails_for_mailbox(&pool, mailbox).await.unwrap_or_default();

                // Fetch active sender/email bans once and reuse for filtering
                let sender_bans = match fetch_active_sender_bans(&config, &pool).await {
                    Ok(b) => b,
                    Err(e) => {
                        error!(%e, "Failed to fetch sender bans from Supabase, proceeding without bans");
                        Vec::new()
                    }
                };

                if emails.is_empty() {
                    w.write_all(format!("{} OK FETCH completed (no emails)\r\n", tag).as_bytes()).await?;
                    continue;
                }

                // Parse FETCH arguments: sequence set and data items
                // Example: "1 (BODY.PEEK[TEXT])" or "1:* (BODY[])"
                let args_trimmed = args.trim();
                if args_trimmed.is_empty() {
                    w.write_all(format!("{} BAD FETCH requires arguments\r\n", tag).as_bytes()).await?;
                    continue;
                }

                // Find the opening parenthesis for data items
                let paren_pos = match args_trimmed.find('(') {
                    Some(pos) => pos,
                    None => {
                        w.write_all(format!("{} BAD FETCH malformed data items\r\n", tag).as_bytes()).await?;
                        continue;
                    }
                };

                let sequence_set = args_trimmed[..paren_pos].trim();
                let data_items_str = &args_trimmed[paren_pos..].trim();

                if !data_items_str.starts_with('(') || !data_items_str.ends_with(')') {
                    w.write_all(format!("{} BAD FETCH malformed data items\r\n", tag).as_bytes()).await?;
                    continue;
                }

                let data_items = &data_items_str[1..data_items_str.len()-1];

                // Parse sequence set (simplified: support single number or 1:*)
                let mut start = 1usize;
                let mut end = emails.len();

                if sequence_set.contains(':') {
                    let parts: Vec<&str> = sequence_set.split(':').collect();
                    if let Ok(s) = parts[0].parse::<usize>() {
                        start = s;
                    }
                    if parts[1] == "*" {
                        end = emails.len();
                    } else if let Ok(eidx) = parts[1].parse::<usize>() {
                        end = eidx;
                    }
                } else if let Ok(single) = sequence_set.parse::<usize>() {
                    start = single;
                    end = single;
                }

                // clamp
                if start == 0 {
                    start = 1;
                }
                if end > emails.len() {
                    end = emails.len();
                }

                for uid in start..=end {
                    if let Some(email) = emails.get(uid - 1) {
                        // Skip emails whose sender is actively banned
                        if is_sender_banned_by_list(&sender_bans, &email.from_addr) {
                            debug!(uid=%uid, from=%email.from_addr, "skipping banned email in FETCH");
                            continue;
                        }
                        // Handle different data items
                        if data_items.to_uppercase().contains("BODY.PEEK[TEXT]") || data_items.to_uppercase().contains("BODY[TEXT]") {
                            // Extract TEXT part from multipart message
                            let text_content = extract_text_part(&email.body);
                            let content_bytes = text_content.as_bytes();
                            let len = content_bytes.len();
                            w.write_all(format!("* {} FETCH (UID {} FLAGS (\\Seen) BODY[TEXT] {{{}}}\r\n", uid, uid, len).as_bytes()).await?;
                            w.write_all(content_bytes).await?;
                            w.write_all(b"\r\n").await?;
                        } else if data_items.to_uppercase().contains("BODY[]") {
                            // Return entire body
                            let body_bytes = email.body.as_bytes();
                            let len = body_bytes.len();
                            w.write_all(format!("* {} FETCH (UID {} FLAGS (\\Seen) BODY[] {{{}}}\r\n", uid, uid, len).as_bytes()).await?;
                            w.write_all(body_bytes).await?;
                            w.write_all(b"\r\n").await?;
                        } else {
                            // Unsupported data item
                            w.write_all(format!("{} BAD FETCH unsupported data item: {}\r\n", tag, data_items).as_bytes()).await?;
                            continue;
                        }
                    }
                }
                w.write_all(format!("{} OK FETCH completed\r\n", tag).as_bytes()).await?;
            }
            "SEARCH" => {
                // Basic SEARCH implementation supporting: ALL, FROM <addr>, SUBJECT <text>
                seen_valid_imap = true;
                if authenticated_user.is_none() {
                    w.write_all(format!("{} NO Not authenticated\r\n", tag).as_bytes()).await?;
                    continue;
                }

                if selected_mailbox.is_none() {
                    w.write_all(format!("{} NO No mailbox selected\r\n", tag).as_bytes()).await?;
                    continue;
                }

                let mailbox = selected_mailbox.as_ref().unwrap();
                let emails = get_emails_for_mailbox(&pool, mailbox).await.unwrap_or_default();

                // Fetch active sender/email bans once and reuse for filtering
                let sender_bans = match fetch_active_sender_bans(&config, &pool).await {
                    Ok(b) => b,
                    Err(e) => {
                        error!(%e, "Failed to fetch sender bans from Supabase, proceeding without bans");
                        Vec::new()
                    }
                };

                let mut matches: Vec<usize> = Vec::new();

                let arg_up = args.to_uppercase();
                if arg_up.trim() == "ALL" {
                    for (i, e) in emails.iter().enumerate() {
                        if is_sender_banned_by_list(&sender_bans, &e.from_addr) {
                            debug!(idx=%i, from=%e.from_addr, "skipping banned email in SEARCH ALL");
                            continue;
                        }
                        matches.push(i + 1);
                    }
                } else if arg_up.starts_with("FROM ") {
                    // original args keep case; extract needle from original args
                    let needle = args[5..].trim().to_lowercase().trim_matches('"').to_string();
                    for (i, e) in emails.iter().enumerate() {
                        if is_sender_banned_by_list(&sender_bans, &e.from_addr) {
                            debug!(idx=%i, from=%e.from_addr, "skipping banned email in SEARCH FROM");
                            continue;
                        }
                        if e.from_addr.to_lowercase().contains(&needle) {
                            matches.push(i + 1);
                        }
                    }
                } else if arg_up.starts_with("SUBJECT ") {
                    let needle = args[8..].trim().to_lowercase().trim_matches('"').to_string();
                    for (i, e) in emails.iter().enumerate() {
                        if is_sender_banned_by_list(&sender_bans, &e.from_addr) {
                            debug!(idx=%i, from=%e.from_addr, "skipping banned email in SEARCH SUBJECT");
                            continue;
                        }
                        if e.subject.to_lowercase().contains(&needle) {
                            matches.push(i + 1);
                        }
                    }
                } else {
                    w.write_all(format!("{} BAD SEARCH unsupported or malformed (supported: ALL, FROM, SUBJECT)\r\n", tag).as_bytes()).await?;
                    continue;
                }

                if matches.is_empty() {
                    w.write_all("* SEARCH\r\n".as_bytes()).await?;
                } else {
                    let list = matches.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(" ");
                    w.write_all(format!("* SEARCH {}\r\n", list).as_bytes()).await?;
                }

                w.write_all(format!("{} OK SEARCH completed\r\n", tag).as_bytes()).await?;
            }
            "STATUS" => {
                // STATUS "mailbox" (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)
                seen_valid_imap = true;
                if authenticated_user.is_none() {
                    w.write_all(format!("{} NO Not authenticated\r\n", tag).as_bytes()).await?;
                    continue;
                }

                let mut arg_parts = args.split_whitespace();
                let mailbox_raw = arg_parts.next().unwrap_or("").trim();
                let mailbox_name = mailbox_raw.trim_matches('"');

                if mailbox_name.is_empty() {
                    w.write_all(format!("{} BAD STATUS requires mailbox name\r\n", tag).as_bytes()).await?;
                    continue;
                }

                let msg_count = get_email_count(&pool, mailbox_name).await.unwrap_or(0);
                let unseen = get_unseen_count(&pool, mailbox_name).await.unwrap_or(0);

                w.write_all(format!("* STATUS \"{}\" (MESSAGES {} RECENT {} UNSEEN {})\r\n", mailbox_name, msg_count, 0, unseen).as_bytes()).await?;
                w.write_all(format!("{} OK STATUS completed\r\n", tag).as_bytes()).await?;
            }
            "CREATE" => {
                seen_valid_imap = true;
                if authenticated_user.is_none() || user_id.is_none() {
                    w.write_all(format!("{} NO Not authenticated\r\n", tag).as_bytes()).await?;
                    continue;
                }

                let new_inbox = args.trim().trim_matches('"').to_string();
                if new_inbox.is_empty() {
                    w.write_all(format!("{} BAD CREATE requires mailbox name\r\n", tag).as_bytes()).await?;
                    continue;
                }

                let domain = match new_inbox.split('@').nth(1) {
                    Some(domain) => domain.to_string(),
                    None => {
                        w.write_all(format!("{} NO Invalid email format. Use: username@domain.com\r\n", tag).as_bytes()).await?;
                        continue;
                    }
                };

                info!(%peer, email=%new_inbox, domain=%domain, "validating domain");

                // Deny creation if the domain is actively banned (global domain ban)
                if is_domain_banned(&config, &pool, &domain).await {
                    w.write_all(format!("{} NO Domain is banned\r\n", tag).as_bytes()).await?;
                    continue;
                }

                // Deny creation if the mailbox address itself is explicitly banned (scope=email)
                if is_email_banned(&config, &pool, &new_inbox).await {
                    w.write_all(format!("{} NO Mailbox is banned\r\n", tag).as_bytes()).await?;
                    continue;
                }

                match validate_domain_cached(&domains_cache, &domain, user_id.as_ref().unwrap()).await {
                    Ok(true) => {
                        // Create inbox in PostgreSQL
                        match create_inbox(&config, &pool, user_id.as_ref().unwrap(), &new_inbox).await {
                            Ok(_) => {
                                w.write_all(format!("{} OK CREATE completed\r\n", tag).as_bytes()).await?;
                                info!(%peer, mailbox=%new_inbox, "mailbox created in Supabase");
                            }
                            Err(e) => {
                                w.write_all(format!("{} NO CREATE failed: {}\r\n", tag, e).as_bytes()).await?;
                            }
                        }
                    }
                    Ok(false) => {
                        w.write_all(format!("{} NO Domain not found or not active. Please add the domain first.\r\n", tag).as_bytes()).await?;
                    }
                    Err(e) => {
                        w.write_all(format!("{} NO Failed to validate domain: {}\r\n", tag, e).as_bytes()).await?;
                    }
                }
            }
            "DELETE" => {
                seen_valid_imap = true;
                if authenticated_user.is_none() || user_id.is_none() {
                    w.write_all(format!("{} NO Not authenticated\r\n", tag).as_bytes()).await?;
                    continue;
                }

                let mailbox_to_delete = args.trim().trim_matches('"').to_string();
                if mailbox_to_delete.is_empty() {
                    w.write_all(format!("{} BAD DELETE requires mailbox name\r\n", tag).as_bytes()).await?;
                    continue;
                }

                if mailbox_to_delete == "INBOX" {
                    w.write_all(format!("{} NO Cannot delete INBOX\r\n", tag).as_bytes()).await?;
                    continue;
                }

                match delete_inbox(&config, &pool, user_id.as_ref().unwrap(), &mailbox_to_delete).await {
                    Ok(_) => {
                        w.write_all(format!("{} OK DELETE completed\r\n", tag).as_bytes()).await?;
                        info!(%peer, mailbox=%mailbox_to_delete, "mailbox deleted from PostgreSQL");
                    }
                    Err(e) => {
                        w.write_all(format!("{} NO DELETE failed: {}\r\n", tag, e).as_bytes()).await?;
                    }
                }
            }
            _ => {
                if seen_valid_imap {
                    warn!(%peer, command=%cmd, "unrecognized IMAP command");
                    w.write_all(format!("{} BAD Unrecognized command: {}\r\n", tag, cmd).as_bytes()).await?;
                } else {
                    info!("[{}] rejecting non-IMAP command: {}", peer, cmd);
                    w.write_all(b"* BAD Invalid IMAP command\r\n").await?;
                    w.flush().await?;
                    return Ok(());
                }
            }
        }

        w.flush().await?;
    }
}

/// Check for an active domain ban
async fn is_domain_banned(config: &Config, pool: &PgPool, domain: &str) -> bool {
    if config.use_bans {
        let client = reqwest::Client::new();
        let url = format!("{}/rest/v1/bans?scope=eq.domain&value=eq.{}&status=eq.active", config.url, domain);
        match client
            .get(&url)
            .header("apikey", &config.key)
            .header("Authorization", format!("Bearer {}", config.key))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<Vec<serde_json::Value>>().await {
                        Ok(rows) => return !rows.is_empty(),
                        Err(_) => return false,
                    }
                }
                false
            }
            Err(_) => false,
        }
    } else {
        // Local PostgreSQL
        let result: Result<Vec<(String, String)>, _> = sqlx::query_as(
            "SELECT value, match_type FROM bans WHERE status = 'active' AND scope = 'domain'",
        )
        .fetch_all(pool)
        .await;
        match result {
            Ok(bans) => {
                let domain_lower = domain.to_lowercase();
                for (value, match_type) in bans {
                    let v_lower = value.to_lowercase();
                    if match_type == "contains" {
                        if domain_lower.contains(&v_lower) {
                            return true;
                        }
                    } else {
                        if domain_lower == v_lower {
                            return true;
                        }
                    }
                }
                false
            }
            Err(_) => false,
        }
    }
}

/// Fetch active sender/email bans
async fn fetch_active_sender_bans(config: &Config, pool: &PgPool) -> Result<Vec<(String, String)>> {
    if config.use_bans {
        let client = reqwest::Client::new();
        let url = format!("{}/rest/v1/bans?status=eq.active&or=(scope.eq.sender,scope.eq.email)", config.url);

        let resp = client
            .get(&url)
            .header("apikey", &config.key)
            .header("Authorization", format!("Bearer {}", config.key))
            .send()
            .await
            .context("Failed to fetch sender bans from Supabase")?;

        if !resp.status().is_success() {
            anyhow::bail!("Supabase returned status {} when fetching bans", resp.status());
        }

        let rows: Vec<JsonValue> = resp.json().await.context("Failed to parse bans JSON")?;
        let mut out = Vec::new();

        for row in rows {
            let mut value = row.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut match_type = row.get("match_type").and_then(|m| m.as_str()).unwrap_or("").to_string();

            // legacy support: value like "contains:foo" -> normalize
            if value.to_lowercase().starts_with("contains:") {
                value = value["contains:".len()..].to_string();
                match_type = "contains".to_string();
            }

            // default match_type to exact if not specified
            if match_type.is_empty() {
                match_type = "exact".to_string();
            }

            out.push((value, match_type));
        }

        Ok(out)
    } else {
        // Local PostgreSQL
        let result: Result<Vec<(String, String, String)>, _> = sqlx::query_as(
            "SELECT value, match_type, scope FROM bans WHERE status = 'active' AND (scope = 'sender' OR scope = 'email')",
        )
        .fetch_all(pool)
        .await;
        match result {
            Ok(rows) => {
                let mut out = Vec::new();
                for (value, match_type, _) in rows {
                    let mut v = value;
                    let mut mt = match_type;
                    // legacy
                    if v.to_lowercase().starts_with("contains:") {
                        v = v["contains:".len()..].to_string();
                        mt = "contains".to_string();
                    }
                    if mt.is_empty() {
                        mt = "exact".to_string();
                    }
                    out.push((v, mt));
                }
                Ok(out)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Check if a sender is banned by evaluating list of (value, match_type)
fn is_sender_banned_by_list(bans: &Vec<(String, String)>, sender: &str) -> bool {
    if bans.is_empty() {
        return false;
    }
    let sender_l = sender.to_lowercase();
    for (value, match_type) in bans {
        let v_l = value.to_lowercase();
        if match_type == "contains" {
            if sender_l.contains(&v_l) {
                return true;
            }
        } else {
            // exact match
            if sender_l == v_l {
                return true;
            }
        }
    }
    false
}
/// Email structure for PostgreSQL queries
#[derive(Debug, sqlx::FromRow)]
struct Email {
    subject: String,
    body: String,
    from_addr: String,
}

/// Extract TEXT part from multipart email message
fn extract_text_part(full_body: &str) -> String {
    // Simple multipart parser - look for text/plain part
    let body_lower = full_body.to_lowercase();

    // Check if it's multipart
    if !body_lower.contains("content-type: multipart/") {
        // Not multipart, return the whole body (assuming it's text)
        return full_body.to_string();
    }

    // Find the boundary
    let boundary_start = match body_lower.find("boundary=") {
        Some(pos) => {
            let boundary_line = &body_lower[pos..];
            if let Some(quote_pos) = boundary_line.find('"') {
                let boundary_end = boundary_line[quote_pos+1..].find('"').unwrap_or(boundary_line.len());
                boundary_line[quote_pos+1..quote_pos+1+boundary_end].to_string()
            } else {
                // No quotes, find next whitespace
                let end_pos = boundary_line.find(' ').unwrap_or(boundary_line.find('\r').unwrap_or(boundary_line.len()));
                boundary_line[9..9 + end_pos].to_string()
            }
        }
        None => return full_body.to_string(), // No boundary, return whole body
    };

    let boundary = format!("--{}", boundary_start);

    // Split by boundary
    let parts: Vec<&str> = full_body.split(&boundary).collect();

    // Look for text/plain part
    for part in &parts {
        let part_lower = part.to_lowercase();
        if part_lower.contains("content-type: text/plain") {
            // Find the start of content (after headers)
            let content_start = if let Some(empty_line_pos) = part.find("\r\n\r\n") {
                empty_line_pos + 4
            } else if let Some(empty_line_pos) = part.find("\n\n") {
                empty_line_pos + 2
            } else {
                0
            };

            let text_content = &part[content_start..];
            // Decode quoted-printable if needed
            if part_lower.contains("content-transfer-encoding: quoted-printable") {
                return decode_quoted_printable(text_content);
            } else {
                return text_content.to_string();
            }
        }
    }

    // If no text/plain found, try to return the first part's content
    if parts.len() > 1 {
        let first_part = parts[1];
        let content_start = if let Some(empty_line_pos) = first_part.find("\r\n\r\n") {
            empty_line_pos + 4
        } else if let Some(empty_line_pos) = first_part.find("\n\n") {
            empty_line_pos + 2
        } else {
            0
        };
        first_part[content_start..].to_string()
    } else {
        full_body.to_string()
    }
}

/// Simple quoted-printable decoder
fn decode_quoted_printable(input: &str) -> String {
    let mut result = String::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'=' {
            if i + 2 < bytes.len() && bytes[i+1] != b'\r' && bytes[i+1] != b'\n' {
                // Decode hex
                if let (Some(h1), Some(h2)) = (hex_digit(bytes[i+1]), hex_digit(bytes[i+2])) {
                    result.push((h1 * 16 + h2) as char);
                    i += 3;
                    continue;
                }
            } else if i + 1 < bytes.len() && bytes[i+1] == b'\r' && i + 2 < bytes.len() && bytes[i+2] == b'\n' {
                // Soft line break
                i += 3;
                continue;
            } else if i + 1 < bytes.len() && bytes[i+1] == b'\n' {
                // Soft line break (LF only)
                i += 2;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

async fn get_email_count(pool: &PgPool, mailbox: &str) -> Result<i64> {
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM emails WHERE mailbox_owner = $1")
            .bind(mailbox)
            .fetch_one(pool)
            .await?;
    Ok(count.0)
}

async fn get_unseen_count(pool: &PgPool, mailbox: &str) -> Result<i64> {
    // For now we store seen state not implemented; reuse total count as fallback
    get_email_count(pool, mailbox).await
}

async fn get_emails_for_mailbox(pool: &PgPool, mailbox: &str) -> Result<Vec<Email>> {
    let emails = sqlx::query_as::<_, Email>(
        "SELECT subject, body, from_addr FROM emails WHERE mailbox_owner = $1 ORDER BY created_at DESC",
    )
    .bind(mailbox)
    .fetch_all(pool)
    .await?;
    Ok(emails)
}

/// Get ONLY user's inboxes
async fn get_user_inboxes(_config: &Config, pool: &PgPool, user_id: &str) -> Result<Vec<Inbox>> {
    // Always use local PostgreSQL
    let inboxes: Vec<Inbox> = sqlx::query_as(
        "SELECT email_address FROM inbox WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    info!("✅ Successfully fetched {} inboxes for user {} from PostgreSQL", inboxes.len(), user_id);
    Ok(inboxes)
}

/// Verify an IMAP login against Postgres directly.
///
/// Previous implementation made three sequential round-trips to
/// Supabase REST (token lookup → admin /auth/v1/admin/users/<uuid>
/// → users-table lookup for subscription) plus a PATCH for
/// last_used_at. Total ~4 HTTP requests per LOGIN, none cacheable,
/// each one ~50–150ms over the public Supabase hostname. After the
/// rest of the stack moved to self-hosted Postgres, IMAP logins
/// were the only thing still hitting Supabase at all — and once a
/// project's Supabase egress went over plan, IMAP logins started
/// timing out under load.
///
/// New implementation: ONE SQL query that joins `imap_tokens` to
/// `users` and pulls everything we need in a single round-trip. The
/// PATCH for last_used_at stays but goes to the same Postgres pool
/// — no Supabase REST anywhere on this code path.
async fn verify_user(pool: &PgPool, user: &str, token: &str) -> Result<(String, String)> {
    info!("🔍 Verifying IMAP login for {} (token prefix: {})",
          user,
          &token.chars().take(8).collect::<String>());

    // Joined fetch: token row + owning user row, in one shot. The
    // explicit cast of user_id to TEXT lets us return a plain string
    // tuple from sqlx without dragging the uuid feature into types
    // we don't otherwise need here.
    let row: Option<(String, String, String, DateTime<Utc>, Option<String>, Option<DateTime<Utc>>)> =
        sqlx::query_as(
            r#"
            SELECT
                t.id::text                   AS token_id,
                t.user_id::text              AS user_id,
                COALESCE(u.email, '')        AS email,
                t.expires_at                 AS expires_at,
                u.subscription_status        AS subscription_status,
                u.subscription_end_date      AS subscription_end_date
            FROM imap_tokens t
            JOIN users u ON u.id = t.user_id
            WHERE t.token = $1
            LIMIT 1
            "#,
        )
        .bind(token)
        .fetch_optional(pool)
        .await
        .context("Failed to query imap_tokens/users")?;

    let (token_id, user_id, email, expires_at, subscription_status, subscription_end_date) =
        match row {
            Some(r) => r,
            None => {
                info!("❌ No token row matching the credential");
                anyhow::bail!("Invalid IMAP token");
            }
        };

    if expires_at <= Utc::now() {
        info!("❌ Token expired at {}", expires_at);
        anyhow::bail!("IMAP token has expired");
    }

    if email != user {
        info!("❌ Email mismatch: token owner = {}, login claim = {}", email, user);
        anyhow::bail!("Email does not match token owner");
    }

    // Subscription gate. Stays loose enough that a `past_due` user
    // whose period hasn't yet ended can still read their mail —
    // matches the policy the web app uses for getMail / inbox-list.
    let status = subscription_status.as_deref().unwrap_or("inactive");
    let is_active = match status {
        "active" | "trialing" => true,
        "past_due" => subscription_end_date
            .map(|d| d > Utc::now())
            .unwrap_or(false),
        _ => false,
    };

    if !is_active {
        info!("❌ Subscription not active for {} (status: {})", email, status);
        anyhow::bail!("Your subscription is not active. Please renew to use IMAP.");
    }

    // Fire-and-forget last_used_at bump. If this update fails
    // (transient pool exhaustion, table-level lock, etc.) we don't
    // want to fail the login — the user already proved they own
    // the token. Log the error but return OK.
    let updated = sqlx::query("UPDATE imap_tokens SET last_used_at = NOW() WHERE id = $1::uuid")
        .bind(&token_id)
        .execute(pool)
        .await;
    if let Err(e) = updated {
        warn!("⚠ Failed to bump last_used_at for token {}: {}", token_id, e);
    }

    info!("✅ IMAP login authenticated for {} (status: {})", email, status);
    Ok((user_id, email))
}

/// Fetch all domains
async fn fetch_all_domains(config: &Config, pool: &PgPool) -> Result<Vec<Domain>> {
    if config.use_domains {
        let client = reqwest::Client::new();

        let response = client
            .get(&format!("{}/rest/v1/domains", config.url))
            .header("apikey", &config.key)
            .header("Authorization", format!("Bearer {}", config.key))
            .header("Content-Type", "application/json")
            .send()
            .await
            .context("Failed to query domains")?;

        if response.status().is_success() {
            let domains: Vec<Domain> = response.json().await.context("Failed to parse domains response")?;
            Ok(domains)
        } else {
            anyhow::bail!("Failed to query domains: {}", response.status())
        }
    } else {
        // Local PostgreSQL
        let domains: Vec<Domain> = sqlx::query_as(
            "SELECT domain, user_id, active, cloudflare_domain FROM domains",
        )
        .fetch_all(pool)
        .await?;
        Ok(domains)
    }
}

/// Validate domain using cached data (supports subdomains)
async fn validate_domain_cached(
    cache: &DomainsCache,
    domain: &str,
    user_id: &str,
) -> Result<bool> {
    let domains = cache.get_domains().await?;

    if let Some(domain_data) = domains.iter().find(|d| d.domain == domain) {
        info!(
            "🔍 Exact domain match found: {} (active: {}, user_id: {})",
            domain_data.domain, domain_data.active, domain_data.user_id
        );

        if domain_data.active {
            if domain_data.user_id == user_id || domain_data.cloudflare_domain {
                info!("✅ Domain validation passed for user: {}", user_id);
                return Ok(true);
            } else {
                info!("❌ Domain owned by different user: {} != {}", domain_data.user_id, user_id);
                return Ok(false);
            }
        } else {
            info!("❌ Domain is not active: {}", domain_data.domain);
            return Ok(false);
        }
    }

    for domain_data in domains.iter() {
        if domain_data.active && (domain_data.user_id == user_id || domain_data.cloudflare_domain) {
            if domain.ends_with(&format!(".{}", domain_data.domain)) {
                info!(
                    "✅ Subdomain validation passed: {} matches parent domain {} for user: {}",
                    domain, domain_data.domain, user_id
                );
                return Ok(true);
            }
        }
    }

    info!("❌ Domain not found in cache: {}", domain);
    Ok(false)
}

/// Create a new inbox for user
async fn create_inbox(_config: &Config, pool: &PgPool, user_id: &str, email_address: &str) -> Result<()> {
    // Always use local PostgreSQL
    sqlx::query(
        "INSERT INTO inbox (user_id, email_address) VALUES ($1, $2)",
    )
    .bind(user_id)
    .bind(email_address)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete an inbox for user
async fn delete_inbox(_config: &Config, pool: &PgPool, user_id: &str, email_address: &str) -> Result<()> {
    // Always use local PostgreSQL
    sqlx::query(
        "DELETE FROM inbox WHERE user_id = $1 AND email_address = $2",
    )
    .bind(user_id)
    .bind(email_address)
    .execute(pool)
    .await?;
    Ok(())
}