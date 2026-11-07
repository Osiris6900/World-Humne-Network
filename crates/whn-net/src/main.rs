//! JSON-lines CLI for reproducible discovery and local matching runs.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};
use whn_core::{
    card::{CapabilityCard, CapabilityDraft, NeedCard, NeedDraft},
    crypto::Identity,
};
use whn_net::{record::unix_now, Announcement, GossipProfile, Node, NodeConfig, TopicSpec};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Connect {
        address: String,
    },
    Bootstrap,
    Create {
        offers: Vec<String>,
        ttl_seconds: u64,
        #[serde(default)]
        region_hint: Option<String>,
        #[serde(default)]
        capacity_note: Option<String>,
        #[serde(default)]
        contact_hint: Option<String>,
    },
    Publish {
        card: CapabilityCard,
    },
    Resolve {
        tag: String,
        card_id: String,
    },
    CreateNeed {
        needs: Vec<String>,
        urgency: u8,
        ttl_seconds: u64,
        #[serde(default)]
        region_hint: Option<String>,
        #[serde(default)]
        note: Option<String>,
    },
    Subscribe {
        topic: TopicSpec,
    },
    Unsubscribe {
        topic: TopicSpec,
    },
    RegisterNeed {
        category: String,
        card: NeedCard,
    },
    RegisterCapability {
        category: String,
        card: CapabilityCard,
    },
    AnnounceNeed {
        category: String,
        card: NeedCard,
    },
    AnnounceCapability {
        category: String,
        card: CapabilityCard,
    },
    Known {
        category: String,
    },
    Matches {
        category: String,
        need_id: String,
    },
    Stats,
    Shutdown,
}

fn load_identity(path: &Path) -> Result<Identity, Box<dyn std::error::Error>> {
    match fs::read(path) {
        Ok(bytes) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
                    return Err(
                        "identity file must not be readable by other users (chmod 600)".into(),
                    );
                }
            }
            let secret: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "identity file must contain exactly 32 raw bytes")?;
            Ok(Identity::from_secret_bytes(&secret))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let identity = Identity::generate();
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path)?.write_all(&identity.secret_bytes())?;
            Ok(identity)
        }
        Err(err) => Err(err.into()),
    }
}

async fn execute(
    command: Command,
    node: &Node,
    identity: &Identity,
) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(match command {
        Command::Connect { address } => {
            node.connect(address.parse()?).await?;
            json!({"ok": true})
        }
        Command::Bootstrap => {
            node.bootstrap().await?;
            json!({"ok": true})
        }
        Command::Create {
            offers,
            ttl_seconds,
            region_hint,
            capacity_note,
            contact_hint,
        } => {
            let now = unix_now();
            let expires = now.checked_add(ttl_seconds).ok_or("TTL overflow")?;
            let mut draft = CapabilityDraft::new(offers, now, expires);
            draft.region_hint = region_hint;
            draft.capacity_note = capacity_note;
            draft.contact_hint = contact_hint;
            let card = draft.sign(identity)?;
            json!({"ok": true, "card": card})
        }
        Command::Publish { card } => {
            node.publish(&card).await?;
            json!({"ok": true, "card_id": card.id})
        }
        Command::Resolve { tag, card_id } => {
            json!({"ok": true, "card": node.resolve(&tag, &card_id).await?})
        }
        Command::CreateNeed {
            needs,
            urgency,
            ttl_seconds,
            region_hint,
            note,
        } => {
            let now = unix_now();
            let expires = now.checked_add(ttl_seconds).ok_or("TTL overflow")?;
            let mut draft = NeedDraft::new(needs, urgency, now, expires);
            draft.region_hint = region_hint;
            draft.note = note;
            json!({"ok": true, "card": draft.sign(identity)?})
        }
        Command::Subscribe { topic } => {
            json!({"ok": true, "changed": node.subscribe(topic).await?})
        }
        Command::Unsubscribe { topic } => {
            json!({"ok": true, "changed": node.unsubscribe(topic).await?})
        }
        Command::RegisterNeed { category, card } => {
            node.register(&category, Announcement::Need(card)).await?;
            json!({"ok": true})
        }
        Command::RegisterCapability { category, card } => {
            node.register(&category, Announcement::Capability(card))
                .await?;
            json!({"ok": true})
        }
        Command::AnnounceNeed { category, card } => {
            json!({"ok": true, "queued_message_id": node.announce(&category, Announcement::Need(card)).await?})
        }
        Command::AnnounceCapability { category, card } => {
            json!({"ok": true, "queued_message_id": node.announce(&category, Announcement::Capability(card)).await?})
        }
        Command::Known { category } => {
            json!({"ok": true, "cards": node.known_cards(&category).await?})
        }
        Command::Matches { category, need_id } => {
            json!({"ok": true, "candidates": node.matches(&category, &need_id).await?})
        }
        Command::Stats => json!({"ok": true, "stats": node.stats().await?}),
        Command::Shutdown => unreachable!("shutdown handled by main loop"),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = NodeConfig::default();
    let mut identity_path = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                config.listen = args
                    .next()
                    .ok_or("--listen requires a multiaddress")?
                    .parse()?
            }
            "--identity-file" => {
                identity_path = Some(args.next().ok_or("--identity-file requires a path")?)
            }
            "--polite" => config.gossip_profile = GossipProfile::Polite,
            "--help" | "-h" => {
                println!("whn-net [--listen /ip4/127.0.0.1/tcp/0] [--identity-file PATH] [--polite]\nCommands: connect, bootstrap, create, create_need, publish, resolve, subscribe, unsubscribe, register_need, register_capability, announce_need, announce_capability, known, matches, stats, shutdown.\nDefault identity is ephemeral; identity files contain a raw private key.");
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    let identity = match identity_path {
        Some(path) => load_identity(Path::new(&path))?,
        None => Identity::generate(),
    };
    let profile = config.gossip_profile;
    let node = Node::spawn(&identity, config).await?;
    println!(
        "{}",
        json!({"event": "ready", "peer_id": node.peer_id().to_string(), "address": node.address().to_string(), "transport": "tcp-noise-yamux", "gossip_profile": profile})
    );
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let command = match serde_json::from_str::<Command>(&line) {
            Ok(Command::Shutdown) => {
                println!("{}", json!({"ok": true}));
                break;
            }
            Ok(command) => command,
            Err(err) => {
                println!("{}", json!({"ok": false, "error": err.to_string()}));
                continue;
            }
        };
        let response = match execute(command, &node, &identity).await {
            Ok(response) => response,
            Err(err) => json!({"ok": false, "error": err.to_string()}),
        };
        println!("{response}");
    }
    Ok(())
}
