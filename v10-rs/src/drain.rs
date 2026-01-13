//! Drain-like template mining with whitespace preservation
//!
//! Implements a simplified Drain algorithm for log template extraction.
//! Supports multi-space compression and CR handling for lossless roundtrip.

use crate::config::{StreamingConfig, MULTI_SPACE_PREFIX};
use std::collections::HashMap;
use regex::Regex;
use lazy_static::lazy_static;

const MAX_CLUSTERS: usize = 500;
const SIMILARITY_THRESHOLD: f64 = 0.4;

lazy_static! {
    static ref MULTI_SPACE_RE: Regex = Regex::new(r"  +").unwrap();
    static ref TAB_RE: Regex = Regex::new(&format!(
        r"^{}T(\d){}",
        regex::escape(&MULTI_SPACE_PREFIX.to_string()),
        regex::escape(&MULTI_SPACE_PREFIX.to_string())
    )).unwrap();
    static ref SPACE_RE: Regex = Regex::new(&format!(
        r"{}(\d)",
        regex::escape(&MULTI_SPACE_PREFIX.to_string())
    )).unwrap();
}

/// A log template cluster
#[derive(Clone, Debug)]
pub struct Cluster {
    pub id: usize,
    pub tokens: Vec<Token>,
    pub count: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    Literal(String),
    Variable,
}

impl Cluster {
    /// Get the template string with <*> placeholders
    pub fn get_template(&self) -> String {
        self.tokens
            .iter()
            .map(|t| match t {
                Token::Literal(s) => s.as_str(),
                Token::Variable => "<*>",
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Drain state for cross-chunk template learning
#[derive(Clone)]
pub struct DrainState {
    config: StreamingConfig,
    clusters: Vec<Cluster>,
    /// Index by (first_token, token_count) for O(1) lookup
    index: HashMap<(String, usize), Vec<usize>>,
    /// Template string -> stable template ID
    template_to_id: HashMap<String, u32>,
    next_template_id: u32,
    /// Cluster ID -> index in clusters vec
    cluster_index: HashMap<usize, usize>,
    next_cluster_id: usize,
}

impl DrainState {
    pub fn new(config: StreamingConfig) -> Self {
        Self {
            config,
            clusters: Vec::new(),
            index: HashMap::new(),
            template_to_id: HashMap::new(),
            next_template_id: 0,
            cluster_index: HashMap::new(),
            next_cluster_id: 0,
        }
    }

    /// Add a line and return (template_id, template, variables)
    /// Returns (-1, "", [line]) if no template matches
    pub fn add_line(&mut self, line: &str) -> (i32, String, Vec<String>) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return (-1, String::new(), vec![line.to_string()]);
        }

        // Preprocess for multi-space handling
        let processed = self.preprocess(line);

        // Tokenize
        let tokens: Vec<&str> = processed.split_whitespace().collect();
        if tokens.is_empty() {
            return (-1, String::new(), vec![line.to_string()]);
        }

        // Try to find matching cluster
        // If first token is a variable, use a placeholder for indexing
        let first_token_for_key = if Self::is_variable(tokens[0]) {
            "<*>".to_string()
        } else {
            tokens[0].to_string()
        };
        let key = (first_token_for_key.clone(), tokens.len());

        if let Some(candidates) = self.index.get(&key).cloned() {
            for &cluster_idx in &candidates {
                if let Some((similarity, merged_tokens)) = self.try_merge(&self.clusters[cluster_idx].tokens, &tokens) {
                    if similarity >= SIMILARITY_THRESHOLD {
                        // Update cluster
                        self.clusters[cluster_idx].tokens = merged_tokens;
                        self.clusters[cluster_idx].count += 1;

                        let template = self.clusters[cluster_idx].get_template();
                        let variables = self.extract_variables(&processed, &template);
                        let tid = self.get_or_create_template_id(&template);

                        return (tid as i32, template, variables);
                    }
                }
            }
        }

        // Too many clusters - don't create new ones, but we already tried matching above
        if self.clusters.len() >= MAX_CLUSTERS {
            return (-1, String::new(), vec![processed]);
        }

        // No match - create new cluster
        let cluster_id = self.next_cluster_id;
        self.next_cluster_id += 1;

        let cluster_tokens: Vec<Token> = tokens
            .iter()
            .map(|&t| {
                if Self::is_variable(t) {
                    Token::Variable
                } else {
                    Token::Literal(t.to_string())
                }
            })
            .collect();

        let cluster = Cluster {
            id: cluster_id,
            tokens: cluster_tokens,
            count: 1,
        };

        let cluster_idx = self.clusters.len();
        self.clusters.push(cluster);
        self.cluster_index.insert(cluster_id, cluster_idx);
        self.index.entry(key).or_default().push(cluster_idx);

        let template = self.clusters[cluster_idx].get_template();
        let variables = self.extract_variables(&processed, &template);
        let tid = self.get_or_create_template_id(&template);

        (tid as i32, template, variables)
    }

    fn try_merge(&self, template_tokens: &[Token], line_tokens: &[&str]) -> Option<(f64, Vec<Token>)> {
        if template_tokens.len() != line_tokens.len() {
            return None;
        }

        let mut matches = 0;
        let mut merged = Vec::with_capacity(template_tokens.len());

        for (tmpl_token, &line_token) in template_tokens.iter().zip(line_tokens.iter()) {
            match tmpl_token {
                Token::Literal(s) => {
                    if s == line_token {
                        matches += 1;
                        merged.push(Token::Literal(s.clone()));
                    } else {
                        merged.push(Token::Variable);
                    }
                }
                Token::Variable => {
                    merged.push(Token::Variable);
                }
            }
        }

        let similarity = matches as f64 / template_tokens.len() as f64;
        Some((similarity, merged))
    }

    #[inline]
    fn is_variable(token: &str) -> bool {
        // Empty tokens are not variables
        if token.is_empty() {
            return false;
        }

        // Helper: check if string looks like an IP address (X.X.X.X)
        let looks_like_ip = |s: &str| -> bool {
            if s.matches('.').count() == 3 {
                let parts: Vec<&str> = s.split('.').collect();
                if parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && p.len() <= 3) {
                    return true;
                }
            }
            false
        };

        // IP address patterns (with optional / prefix and :port suffix)
        // Handles: 10.251.30.85, 10.251.30.85:50010, /10.251.90.64:
        // Also handles: 10.251.30.85:50010:Got (IP:port:text glued together)
        let stripped = token.strip_prefix('/').unwrap_or(token);
        let ip_candidate = stripped.split(':').next().unwrap_or("");
        if looks_like_ip(ip_candidate) {
            return true;
        }

        // Hostnames (domain names like unicomp6.unicomp.net, burger.letters.com)
        // Must have at least one dot and consist of alphanumeric + dots + hyphens
        if token.contains('.') && !token.starts_with('.') && !token.ends_with('.') {
            let is_hostname = token.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
            if is_hostname && token.len() > 4 {
                // Has at least 2 parts separated by dots
                let parts: Vec<&str> = token.split('.').collect();
                if parts.len() >= 2 && parts.iter().all(|p| !p.is_empty()) {
                    return true;
                }
            }
        }

        // URL paths (starts with / and contains common URL chars)
        // Must have more than just "/" and at least some path content
        if token.starts_with('/') && token.len() > 3 {
            let is_url_path = token.chars().all(|c|
                c.is_ascii_alphanumeric() || c == '/' || c == '.' || c == '-' || c == '_' || c == '~' || c == '%'
            );
            if is_url_path {
                return true;
            }
        }

        // Pure numbers (integers, floats, negative numbers)
        if token.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-') {
            // Must have at least one digit
            return token.chars().any(|c| c.is_ascii_digit());
        }

        // Numbers with colons (timestamps like 20:36:15 or 10:50:10)
        if token.chars().all(|c| c.is_ascii_digit() || c == ':') && token.contains(':') {
            return token.chars().any(|c| c.is_ascii_digit());
        }

        // Hex strings (like addresses, hashes)
        if token.len() > 6 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }

        // Contains digits mixed with letters (like blk_123456 or blk_-12345)
        let has_digit = token.chars().any(|c| c.is_ascii_digit());
        let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
        if has_digit && has_alpha {
            // Block IDs (blk_123456 or blk_-123456)
            if token.starts_with("blk_") || token.starts_with("blk-") {
                return true;
            }
            // Mixed alphanumeric with separators (like task_123, node-5, etc.)
            if token.len() > 4 && (token.contains('_') || token.contains('-')) {
                return true;
            }
            // Short hostnames: letters followed by digits (aadmin1, cn450, bn508)
            // Must start with letter, end with digit, be reasonably short
            if token.len() >= 2 && token.len() <= 20 {
                let first_char = token.chars().next().unwrap();
                let last_char = token.chars().last().unwrap();
                if first_char.is_ascii_alphabetic() && last_char.is_ascii_digit() {
                    // All chars are alphanumeric
                    if token.chars().all(|c| c.is_ascii_alphanumeric()) {
                        return true;
                    }
                }
            }
        }

        // User@host patterns (src@aadmin1, local@tbird-admin1)
        if token.contains('@') && !token.starts_with('@') && !token.ends_with('@') {
            let parts: Vec<&str> = token.split('@').collect();
            if parts.len() == 2 {
                // Both parts are reasonable identifiers
                let valid_part = |p: &str| {
                    !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                };
                if valid_part(parts[0]) && valid_part(parts[1]) {
                    return true;
                }
            }
        }

        // Hash-wrapped identifiers (#1#, #21#, #node1#)
        if token.starts_with('#') && token.ends_with('#') && token.len() >= 3 {
            let inner = &token[1..token.len()-1];
            if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_alphanumeric()) {
                return true;
            }
        }

        // Process names with PIDs: sshd[14620]: or ntpd[1234]
        // Pattern: word[digits] with optional trailing colon
        if token.contains('[') && token.contains(']') {
            let bracket_start = token.find('[').unwrap();
            let bracket_end = token.find(']').unwrap();
            if bracket_start < bracket_end {
                let pid_part = &token[bracket_start+1..bracket_end];
                if !pid_part.is_empty() && pid_part.chars().all(|c| c.is_ascii_digit()) {
                    return true;
                }
            }
        }

        false
    }

    fn get_or_create_template_id(&mut self, template: &str) -> u32 {
        if let Some(&id) = self.template_to_id.get(template) {
            return id;
        }

        if self.next_template_id as usize >= self.config.max_templates {
            return 0xFFFFFFFF; // Invalid ID
        }

        let id = self.next_template_id;
        self.next_template_id += 1;
        self.template_to_id.insert(template.to_string(), id);
        id
    }

    /// Preprocess line for multi-space handling
    pub fn preprocess(&self, line: &str) -> String {
        let mut result = line.to_string();

        // Handle trailing \r (Windows line endings)
        let has_cr = result.ends_with('\r');
        if has_cr {
            result.pop();
        }

        // Handle leading tabs
        let mut leading_tabs = 0;
        while result.starts_with('\t') {
            leading_tabs += 1;
            result = result[1..].to_string();
        }

        // Handle trailing spaces
        let mut trailing_spaces = 0;
        while result.ends_with(' ') {
            trailing_spaces += 1;
            result.pop();
        }

        // Replace multi-spaces using precompiled regex
        result = MULTI_SPACE_RE.replace_all(&result, |caps: &regex::Captures| {
            let count = caps[0].len();
            let mut marker = String::new();
            let mut remaining = count;
            while remaining > 0 {
                let chunk = remaining.min(9);
                marker.push(MULTI_SPACE_PREFIX);
                marker.push_str(&chunk.to_string());
                remaining -= chunk;
            }
            marker
        }).to_string();

        // Add leading tab marker
        if leading_tabs > 0 {
            result = format!("{}T{}{}{}", MULTI_SPACE_PREFIX, leading_tabs, MULTI_SPACE_PREFIX, result);
        }

        // Add trailing space marker
        let mut remaining = trailing_spaces;
        while remaining > 0 {
            let chunk = remaining.min(9);
            result.push(MULTI_SPACE_PREFIX);
            result.push_str(&chunk.to_string());
            remaining -= chunk;
        }

        // Add CR marker
        if has_cr {
            result.push(MULTI_SPACE_PREFIX);
            result.push('R');
        }

        result
    }

    /// Postprocess line to restore whitespace
    pub fn postprocess(&self, line: &str) -> String {
        let mut result = line.to_string();

        // Restore trailing CR
        let cr_marker = format!("{}R", MULTI_SPACE_PREFIX);
        let has_cr = result.ends_with(&cr_marker);
        if has_cr {
            result = result[..result.len() - cr_marker.len()].to_string();
        }

        // Restore leading tabs using precompiled regex
        if let Some(caps) = TAB_RE.captures(&result) {
            let tabs = caps[1].parse::<usize>().unwrap_or(0);
            let tab_str: String = std::iter::repeat('\t').take(tabs).collect();
            result = format!("{}{}", tab_str, &result[caps[0].len()..]);
        }

        // Restore multi-spaces using precompiled regex
        loop {
            let new_result = SPACE_RE.replace_all(&result, |caps: &regex::Captures| {
                let count = caps[1].parse::<usize>().unwrap_or(1);
                " ".repeat(count)
            }).to_string();

            if new_result == result {
                break;
            }
            result = new_result;
        }

        // Add back CR
        if has_cr {
            result.push('\r');
        }

        result
    }

    /// Extract variables from line using template
    pub fn extract_variables(&self, line: &str, template: &str) -> Vec<String> {
        if template.is_empty() {
            return vec![line.to_string()];
        }

        let parts: Vec<&str> = template.split("<*>").collect();
        if parts.len() == 1 {
            return if template == line { vec![] } else { vec![line.to_string()] };
        }

        let mut variables = Vec::new();
        let mut remaining = line;

        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                // Empty part means <*> at start or two <*><*> adjacent
                // We need to mark that a variable should be extracted before the NEXT non-empty part
                // For now, don't push anything - the variable will be captured when we find the next literal
                continue;
            }

            if let Some(idx) = remaining.find(part) {
                if idx > 0 {
                    variables.push(remaining[..idx].to_string());
                } else if i > 0 && parts[i-1].is_empty() {
                    // Previous part was empty (meaning a <*> came before this literal)
                    // and idx==0, meaning there's NO content between the <*> and this literal
                    // This is a problem - the variable is empty
                    variables.push(String::new());
                }
                remaining = &remaining[idx + part.len()..];
            } else {
                // Mismatch - return raw line
                return vec![line.to_string()];
            }
        }

        if !remaining.is_empty() {
            variables.push(remaining.to_string());
        }

        variables
    }

    /// Reconstruct line from template and variables
    pub fn reconstruct_line(&self, template: &str, variables: &[String]) -> String {
        if template.is_empty() {
            return variables.first().cloned().unwrap_or_default();
        }

        let parts: Vec<&str> = template.split("<*>").collect();
        if parts.len() == 1 {
            return if variables.is_empty() { template.to_string() } else { variables[0].clone() };
        }

        let mut result = String::new();
        let mut var_idx = 0;

        for (i, part) in parts.iter().enumerate() {
            if i > 0 && var_idx < variables.len() {
                result.push_str(&variables[var_idx]);
                var_idx += 1;
            }
            result.push_str(part);
        }

        if var_idx < variables.len() {
            result.push_str(&variables[var_idx]);
        }

        self.postprocess(&result)
    }

    /// Get all templates for encoding
    pub fn get_templates(&self) -> Vec<(u32, String)> {
        self.template_to_id
            .iter()
            .map(|(tmpl, &id)| (id, tmpl.clone()))
            .collect()
    }

    /// Check if a template ID has been assigned
    pub fn has_template_id(&self, template: &str) -> Option<u32> {
        self.template_to_id.get(template).copied()
    }

    /// Number of clusters
    pub fn cluster_count(&self) -> usize {
        self.clusters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preprocess_multi_space() {
        let drain = DrainState::new(StreamingConfig::default());

        let processed = drain.preprocess("Jun  9 test");
        assert!(processed.contains(MULTI_SPACE_PREFIX));

        let restored = drain.postprocess(&processed);
        assert_eq!(restored, "Jun  9 test");
    }

    #[test]
    fn test_preprocess_cr() {
        let drain = DrainState::new(StreamingConfig::default());

        let processed = drain.preprocess("test line\r");
        assert!(processed.ends_with(&format!("{}R", MULTI_SPACE_PREFIX)));

        let restored = drain.postprocess(&processed);
        assert_eq!(restored, "test line\r");
    }

    #[test]
    fn test_template_mining() {
        let mut drain = DrainState::new(StreamingConfig::default());

        let (tid1, tmpl1, vars1) = drain.add_line("Error at line 123");
        assert!(tid1 >= 0);
        assert!(!vars1.is_empty());

        let (tid2, tmpl2, vars2) = drain.add_line("Error at line 456");
        assert_eq!(tid1, tid2); // Same template
        assert_eq!(vars2, vec!["456"]);
    }
}
