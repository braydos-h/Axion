//! Axion's policy rule engine: compiled CIDR/port/protocol/SNI matching with
//! priorities, allowlist overrides, and confidence-driven auto-blocking.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use ipnet::IpNet;
use serde::Serialize;

use crate::config::{Action, Config, DirectionMatch, RuleConfig};
use crate::flow::Direction;
use crate::packet::IpProtocol;

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub action: Action,
    pub matched_rule: Option<String>,
    pub reason: String,
    pub log: bool,
}

impl Decision {
    pub fn allow() -> Self {
        Self {
            action: Action::Allow,
            matched_rule: None,
            reason: "default allow".to_string(),
            log: false,
        }
    }

    pub fn action(&self) -> Action {
        self.action
    }
}

#[derive(Debug, Clone)]
struct CompiledMatch {
    src_cidrs: Vec<IpNet>,
    dst_cidrs: Vec<IpNet>,
    ports: Vec<u16>,
    src_ports: Vec<u16>,
    transports: Vec<String>,
    protocols: Vec<String>,
    categories: Vec<String>,
    sni: Vec<String>,
    dns: Vec<String>,
    direction: DirectionMatch,
    min_confidence: f32,
    max_confidence: Option<f32>,
    min_bytes: Option<u64>,
    min_duration_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    priority: i32,
    action: Action,
    log: bool,
    matcher: CompiledMatch,
}

#[derive(Debug, Clone)]
pub struct Rules {
    rules: Vec<CompiledRule>,
    views: Vec<RuleConfig>,
    allow_rules_first: bool,
    default_action: Action,
    allowlist: Vec<IpNet>,
    blocklist: Vec<IpNet>,
    auto_block_confidence: f32,
    monitor_confidence: f32,
    detection_enabled: bool,
}

pub struct RuleContext<'a> {
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub transport: IpProtocol,
    pub direction: Direction,
    pub protocols: &'a [String],
    pub categories: &'a std::collections::BTreeMap<String, f32>,
    pub confidence: f32,
    pub sni: Option<&'a str>,
    pub dns_names: &'a [String],
    pub total_bytes: u64,
    pub duration_ms: u64,
    pub proxy_score: f32,
    pub proxy_transport_score: f32,
    pub obfuscation_score: f32,
}

impl Rules {
    pub fn from_config(config: &Config) -> Result<Self> {
        let allowlist = parse_nets(&config.policy.allowlist_cidrs, "policy.allowlist_cidrs")?;
        let blocklist = parse_nets(&config.policy.blocklist_cidrs, "policy.blocklist_cidrs")?;
        let mut rules = Vec::with_capacity(config.rules.len());
        for rule in &config.rules {
            if !rule.enabled {
                continue;
            }
            rules.push(compile_rule(rule)?);
        }
        rules.sort_by_key(|a| std::cmp::Reverse(a.priority));
        Ok(Self {
            rules,
            views: config.rules.clone(),
            allow_rules_first: config.policy.allow_overrides,
            default_action: config.policy.default_action,
            allowlist,
            blocklist,
            auto_block_confidence: config.general.auto_block_confidence,
            monitor_confidence: config.general.monitor_confidence,
            detection_enabled: config.detection.enabled,
        })
    }

    pub fn evaluate(&self, ctx: &RuleContext<'_>) -> Decision {
        if self.matches_any(&self.allowlist, ctx.src, ctx.dst) {
            return Decision {
                action: Action::Allow,
                matched_rule: Some("global:allowlist".to_string()),
                reason: "address matched policy.allowlist_cidrs".to_string(),
                log: true,
            };
        }
        if self.matches_any(&self.blocklist, ctx.src, ctx.dst) {
            return Decision {
                action: Action::Drop,
                matched_rule: Some("global:blocklist".to_string()),
                reason: "address matched policy.blocklist_cidrs".to_string(),
                log: true,
            };
        }

        if self.allow_rules_first {
            for rule in self.rules.iter().filter(|r| r.action == Action::Allow) {
                if rule.matches(ctx) {
                    return decision_for(rule, "ALLOW rule matched");
                }
            }
        }
        for rule in self
            .rules
            .iter()
            .filter(|r| !self.allow_rules_first || r.action != Action::Allow)
        {
            if rule.matches(ctx) {
                return decision_for(rule, "rule matched");
            }
        }

        if self.detection_enabled {
            let strongest = ctx
                .proxy_score
                .max(ctx.proxy_transport_score)
                .max(ctx.obfuscation_score);
            if ctx.proxy_score >= self.auto_block_confidence {
                return Decision {
                    action: Action::Drop,
                    matched_rule: Some("builtin:auto-block-proxy".to_string()),
                    reason: format!(
                        "direct proxy evidence {:.2} >= auto-block threshold {:.2}",
                        ctx.proxy_score, self.auto_block_confidence
                    ),
                    log: true,
                };
            }
            if strongest >= self.monitor_confidence {
                return Decision {
                    action: Action::Monitor,
                    matched_rule: Some("builtin:monitor-suspicion".to_string()),
                    reason: format!(
                        "suspicion score {:.2} >= monitor threshold {:.2}",
                        strongest, self.monitor_confidence
                    ),
                    log: true,
                };
            }
        }

        Decision {
            action: self.default_action,
            matched_rule: None,
            reason: "policy default".to_string(),
            log: false,
        }
    }

    pub fn views(&self) -> &[RuleConfig] {
        &self.views
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn detection_enabled(&self) -> bool {
        self.detection_enabled
    }

    pub fn allowlist_len(&self) -> usize {
        self.allowlist.len()
    }

    pub fn blocklist_len(&self) -> usize {
        self.blocklist.len()
    }

    fn matches_any(&self, nets: &[IpNet], src: std::net::IpAddr, dst: std::net::IpAddr) -> bool {
        nets.iter()
            .any(|net| net.contains(&src) || net.contains(&dst))
    }
}

fn decision_for(rule: &CompiledRule, reason: &str) -> Decision {
    Decision {
        action: rule.action,
        matched_rule: Some(rule.name.clone()),
        reason: format!("{reason}: {}", rule.name),
        log: rule.log,
    }
}

impl CompiledRule {
    fn matches(&self, ctx: &RuleContext<'_>) -> bool {
        let m = &self.matcher;
        let src_ok = m.src_cidrs.is_empty() || m.src_cidrs.iter().any(|n| n.contains(&ctx.src));
        let dst_ok = m.dst_cidrs.is_empty() || m.dst_cidrs.iter().any(|n| n.contains(&ctx.dst));
        if !src_ok || !dst_ok {
            return false;
        }
        if !m.ports.is_empty()
            && !m.ports.contains(&ctx.src_port)
            && !m.ports.contains(&ctx.dst_port)
        {
            return false;
        }
        if !m.src_ports.is_empty() && !m.src_ports.contains(&ctx.src_port) {
            return false;
        }
        if !m.transports.is_empty()
            && !m
                .transports
                .iter()
                .any(|t| t.eq_ignore_ascii_case(ctx.transport.as_str()))
        {
            return false;
        }
        if !m.protocols.is_empty()
            && !ctx
                .protocols
                .iter()
                .any(|p| m.protocols.iter().any(|q| q.eq_ignore_ascii_case(p)))
        {
            return false;
        }
        if !m.categories.is_empty()
            && !m
                .categories
                .iter()
                .any(|c| ctx.categories.get(c).copied().unwrap_or(0.0) > 0.0)
        {
            return false;
        }
        if !m.sni.is_empty() {
            let Some(sni) = ctx.sni else {
                return false;
            };
            if !m.sni.iter().any(|pattern| wildcard_match(pattern, sni)) {
                return false;
            }
        }
        if !m.dns.is_empty()
            && !ctx
                .dns_names
                .iter()
                .any(|name| m.dns.iter().any(|pattern| wildcard_match(pattern, name)))
        {
            return false;
        }
        match m.direction {
            DirectionMatch::Either => {}
            DirectionMatch::ClientToServer => {
                if ctx.direction != Direction::ClientToServer {
                    return false;
                }
            }
            DirectionMatch::ServerToClient => {
                if ctx.direction != Direction::ServerToClient {
                    return false;
                }
            }
        }
        if ctx.confidence < m.min_confidence {
            return false;
        }
        if let Some(max) = m.max_confidence {
            if ctx.confidence > max {
                return false;
            }
        }
        if let Some(min) = m.min_bytes {
            if ctx.total_bytes < min {
                return false;
            }
        }
        if let Some(min) = m.min_duration_ms {
            if ctx.duration_ms < min {
                return false;
            }
        }
        true
    }
}

fn compile_rule(rule: &RuleConfig) -> Result<CompiledRule> {
    let m = &rule.matcher;
    Ok(CompiledRule {
        name: rule.name.clone(),
        priority: rule.priority,
        action: rule.action,
        log: rule.log,
        matcher: CompiledMatch {
            src_cidrs: parse_nets(&m.src_cidrs, &format!("rule {} src_cidrs", rule.name))?,
            dst_cidrs: parse_nets(&m.dst_cidrs, &format!("rule {} dst_cidrs", rule.name))?,
            ports: m.ports.clone(),
            src_ports: m.src_ports.clone(),
            transports: m.transports.iter().map(|s| s.to_lowercase()).collect(),
            protocols: m.protocols.iter().map(|s| s.to_lowercase()).collect(),
            categories: m.categories.iter().map(|s| s.to_lowercase()).collect(),
            sni: m.sni.iter().map(|s| s.to_ascii_lowercase()).collect(),
            dns: m.dns.iter().map(|s| s.to_ascii_lowercase()).collect(),
            direction: m.direction,
            min_confidence: m.min_confidence,
            max_confidence: m.max_confidence,
            min_bytes: m.min_bytes,
            min_duration_ms: m.min_duration_ms,
        },
    })
}

fn parse_nets(values: &[String], field: &str) -> Result<Vec<IpNet>> {
    values
        .iter()
        .map(|value| {
            value
                .parse::<IpNet>()
                .with_context(|| format!("invalid CIDR {value:?} in {field}"))
        })
        .collect()
}

/// Wildcard matching supporting `*` and `?`, case-insensitive. Intended for
/// hostnames; it is deliberately not a regex engine.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star: Option<usize> = None;
    let mut matched = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            matched = ti;
            pi += 1;
        } else if let Some(star_pos) = star {
            pi = star_pos + 1;
            matched += 1;
            ti = matched;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Thread-safe, hot-swappable compiled rule set.
pub struct RuleStore {
    path: PathBuf,
    current: ArcSwap<Rules>,
    version: AtomicU64,
}

impl RuleStore {
    pub fn new(path: PathBuf, config: &Config) -> Result<Arc<Self>> {
        let rules = Rules::from_config(config)?;
        Ok(Arc::new(Self {
            path,
            current: ArcSwap::from_pointee(rules),
            version: AtomicU64::new(1),
        }))
    }

    pub fn current(&self) -> Arc<Rules> {
        self.current.load_full()
    }

    /// Monotonic policy generation, bumped after every successful swap.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-read the complete configuration and atomically swap the policy.
    /// Invalid files leave the existing policy untouched.
    pub fn reload(&self) -> Result<usize> {
        let config =
            Config::load(&self.path).with_context(|| format!("reload {}", self.path.display()))?;
        let rules = Rules::from_config(&config)?;
        let count = rules.rule_count();
        self.current.store(Arc::new(rules));
        self.version.fetch_add(1, Ordering::AcqRel);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;
    use crate::config::{DirectionMatch, MatchConfig, RuleConfig};

    fn config_with_rules(rules: Vec<RuleConfig>) -> Config {
        let mut cfg = Config::default();
        cfg.rules = rules;
        cfg
    }

    fn ctx<'a>(
        protocols: &'a [String],
        categories: &'a std::collections::BTreeMap<String, f32>,
        sni: Option<&'a str>,
    ) -> RuleContext<'a> {
        RuleContext {
            src: "192.0.2.10".parse().unwrap(),
            dst: "198.51.100.20".parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
            transport: IpProtocol::TCP,
            direction: Direction::ClientToServer,
            protocols,
            categories,
            confidence: 0.95,
            sni,
            dns_names: &[],
            total_bytes: 1000,
            duration_ms: 100,
            proxy_score: 0.0,
            proxy_transport_score: 0.0,
            obfuscation_score: 0.0,
        }
    }

    fn rule(name: &str, priority: i32, action: Action, matcher: MatchConfig) -> RuleConfig {
        RuleConfig {
            name: name.to_string(),
            priority,
            action,
            enabled: true,
            matcher,
            ..Default::default()
        }
    }

    #[test]
    fn higher_priority_wins() {
        let mut cfg = config_with_rules(Vec::new());
        cfg.policy.allow_overrides = false;
        let mut low = MatchConfig::default();
        low.ports = vec![443];
        let mut high = MatchConfig::default();
        high.ports = vec![443];
        cfg.rules = vec![
            rule("low", 10, Action::Allow, low),
            rule("high", 100, Action::Drop, high),
        ];
        let rules = Rules::from_config(&cfg).unwrap();
        let protocols = vec![];
        let categories = std::collections::BTreeMap::new();
        let d = rules.evaluate(&ctx(&protocols, &categories, None));
        assert_eq!(d.action, Action::Drop);
        assert_eq!(d.matched_rule.as_deref(), Some("high"));
    }

    #[test]
    fn allow_override_wins_even_with_low_priority() {
        let mut allow = MatchConfig::default();
        allow.sni = vec!["*.trusted.example".to_string()];
        let mut drop = MatchConfig::default();
        drop.ports = vec![443];
        let rules = Rules::from_config(&config_with_rules(vec![
            rule("drop-all", 1000, Action::Drop, drop),
            rule("allow-trusted", 1, Action::Allow, allow),
        ]))
        .unwrap();
        let protocols = vec!["tls".to_string()];
        let categories = std::collections::BTreeMap::new();
        let d = rules.evaluate(&ctx(&protocols, &categories, Some("api.trusted.example")));
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.matched_rule.as_deref(), Some("allow-trusted"));
    }

    #[test]
    fn sni_wildcards() {
        assert!(wildcard_match("*.example.com", "a.example.com"));
        assert!(wildcard_match("*.example.com", "a.b.example.com"));
        assert!(!wildcard_match("*.example.com", "example.com"));
        assert!(wildcard_match("*example*", "my-example.org"));
        assert!(wildcard_match("a?c", "abc"));
    }

    #[test]
    fn auto_blocks_only_direct_proxy_score() {
        let rules = Rules::from_config(&Config::default()).unwrap();
        let protocols = vec![];
        let mut categories = std::collections::BTreeMap::new();
        categories.insert(crate::dpi::CAT_PROXY.to_string(), 0.96f32);
        let mut c = ctx(&protocols, &categories, None);
        c.proxy_score = 0.96;
        let d = rules.evaluate(&c);
        assert_eq!(d.action, Action::Drop);
        assert_eq!(d.matched_rule.as_deref(), Some("builtin:auto-block-proxy"));

        c.proxy_score = 0.0;
        c.obfuscation_score = 0.25;
        let d = rules.evaluate(&c);
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn monitor_mode_decision_is_not_blocking() {
        let mut cfg = Config::default();
        cfg.general.auto_block_confidence = 0.9;
        let rules = Rules::from_config(&cfg).unwrap();
        let protocols = vec![];
        let categories = std::collections::BTreeMap::new();
        let mut c = ctx(&protocols, &categories, None);
        c.proxy_score = 0.7;
        let d = rules.evaluate(&c);
        assert_eq!(d.action, Action::Monitor);
        assert!(!d.action.is_blocking());
    }

    #[test]
    fn global_allowlist_beats_blocklist() {
        let mut cfg = Config::default();
        cfg.policy.allowlist_cidrs = vec!["192.0.2.0/24".into()];
        cfg.policy.blocklist_cidrs = vec!["192.0.2.0/24".into()];
        let rules = Rules::from_config(&cfg).unwrap();
        let protocols = vec![];
        let categories = std::collections::BTreeMap::new();
        let d = rules.evaluate(&ctx(&protocols, &categories, None));
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn dns_and_cidr_matching() {
        let mut m = MatchConfig::default();
        m.dns = vec!["*.tracker.example".into()];
        m.dst_cidrs = vec!["198.51.100.0/24".into()];
        let rules =
            Rules::from_config(&config_with_rules(vec![rule("dns", 10, Action::Drop, m)])).unwrap();
        let protocols = vec!["dns".to_string()];
        let categories = std::collections::BTreeMap::new();
        let dns_names = vec!["ads.tracker.example".to_string()];
        let mut c = ctx(&protocols, &categories, None);
        c.dns_names = &dns_names;
        assert_eq!(rules.evaluate(&c).action, Action::Drop);
        let other = vec!["safe.example".to_string()];
        c.dns_names = &other;
        assert_eq!(rules.evaluate(&c).action, Action::Allow);
    }

    #[test]
    fn direction_filter() {
        let mut m = MatchConfig::default();
        m.direction = DirectionMatch::ServerToClient;
        let rules = Rules::from_config(&config_with_rules(vec![rule(
            "reverse",
            10,
            Action::Drop,
            m,
        )]))
        .unwrap();
        let protocols = vec![];
        let categories = std::collections::BTreeMap::new();
        let d = rules.evaluate(&ctx(&protocols, &categories, None));
        assert_eq!(d.action, Action::Allow);
    }
}
