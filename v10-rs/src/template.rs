//! Fast template mining for log lines
//!
//! Simplified Drain-like algorithm optimized for speed.
//! Uses token-based matching with variable detection.

use std::collections::HashMap;

const MAX_TEMPLATES: usize = 1000;
const VARIABLE_MARKER: &str = "<*>";

/// A log template with variable placeholders
#[derive(Clone, Debug)]
pub struct Template {
    pub id: u32,
    pub tokens: Vec<Token>,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    Literal(String),
    Variable,
}

/// Fast template miner
pub struct TemplateMiner {
    /// Templates indexed by (first_token, token_count)
    index: HashMap<(String, usize), Vec<usize>>,
    templates: Vec<Template>,
    next_id: u32,
}

impl TemplateMiner {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
            templates: Vec::with_capacity(MAX_TEMPLATES),
            next_id: 0,
        }
    }

    /// Process a line and return (template_id, variables)
    /// Returns None if no template matches and we're at capacity
    pub fn process_line<'a>(&mut self, line: &'a str) -> Option<(u32, Vec<&'a str>)> {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            return None;
        }

        let key = (tokens[0].to_string(), tokens.len());

        // Try to find matching template
        if let Some(candidates) = self.index.get(&key) {
            let candidates = candidates.clone();
            for idx in candidates {
                if let Some(vars) = self.match_template(&self.templates[idx], &tokens) {
                    // Update count and get id
                    let id = self.templates[idx].id;
                    self.templates[idx].count += 1;
                    return Some((id, vars));
                }
            }
        }

        // No match - create new template if under limit
        if self.templates.len() >= MAX_TEMPLATES {
            return None;
        }

        let (template, vars) = self.create_template(&tokens);
        let id = template.id;
        let idx = self.templates.len();
        self.templates.push(template);

        self.index.entry(key).or_default().push(idx);

        // Return variables extracted during template creation
        Some((id, vars))
    }

    fn match_template<'a>(&self, template: &Template, tokens: &[&'a str]) -> Option<Vec<&'a str>> {
        if template.tokens.len() != tokens.len() {
            return None;
        }

        let mut vars = Vec::new();

        for (tmpl_token, &line_token) in template.tokens.iter().zip(tokens.iter()) {
            match tmpl_token {
                Token::Literal(s) => {
                    if s != line_token {
                        return None;
                    }
                }
                Token::Variable => {
                    vars.push(line_token);
                }
            }
        }

        Some(vars)
    }

    fn create_template<'a>(&mut self, tokens: &[&'a str]) -> (Template, Vec<&'a str>) {
        let mut vars = Vec::new();
        let template_tokens: Vec<Token> = tokens
            .iter()
            .map(|&t| {
                if Self::is_variable(t) {
                    vars.push(t);
                    Token::Variable
                } else {
                    Token::Literal(t.to_string())
                }
            })
            .collect();

        let id = self.next_id;
        self.next_id += 1;

        (Template {
            id,
            tokens: template_tokens,
            count: 1,
        }, vars)
    }

    /// Heuristic: is this token likely a variable?
    #[inline]
    fn is_variable(token: &str) -> bool {
        // Numbers are likely variables
        if token.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == ':') {
            return true;
        }

        // Hex strings (like addresses, hashes)
        if token.len() > 6 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }

        // Contains digits mixed with letters (like blk_123456)
        let has_digit = token.chars().any(|c| c.is_ascii_digit());
        let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
        if has_digit && has_alpha && token.len() > 4 {
            // Check if it looks like an ID pattern
            if token.contains('_') || token.contains('-') {
                return true;
            }
        }

        // IP addresses
        if token.matches('.').count() == 3 && token.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return true;
        }

        false
    }

    /// Get template by ID
    pub fn get_template(&self, id: u32) -> Option<&Template> {
        self.templates.iter().find(|t| t.id == id)
    }

    /// Serialize template to string format
    pub fn template_to_string(template: &Template) -> String {
        template
            .tokens
            .iter()
            .map(|t| match t {
                Token::Literal(s) => s.as_str(),
                Token::Variable => VARIABLE_MARKER,
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Get all templates
    pub fn templates(&self) -> &[Template] {
        &self.templates
    }

    /// Number of templates
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

impl Default for TemplateMiner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_mining() {
        let mut miner = TemplateMiner::new();

        // First line creates template
        let result = miner.process_line("Error at line 123");
        assert!(result.is_some());
        let (id1, vars1) = result.unwrap();
        assert_eq!(vars1, vec!["123"]); // Variables extracted even on first occurrence

        // Second similar line should match
        let result = miner.process_line("Error at line 456");
        assert!(result.is_some());
        let (id2, vars2) = result.unwrap();
        assert_eq!(id1, id2); // Same template
        assert_eq!(vars2, vec!["456"]); // Variable extracted
    }
}
