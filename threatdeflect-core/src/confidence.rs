use std::collections::HashMap;

pub fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    let total = s.len() as f64;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / total;
        acc - p * p.log2()
    })
}

pub fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    const PLACEHOLDERS: &[&str] = &[
        "your_",
        "change_me",
        "changeme",
        "todo",
        "example",
        "test",
        "dummy",
        "fake",
        "sample",
        "placeholder",
        "insert_",
        "put_",
        "replace_",
        "xxx",
        "aaa",
        "000",
        "enter_your",
        "add_your",
        "my_secret",
        "my_key",
        "my_token",
        "secret_here",
        "key_here",
        "token_here",
        "password_here",
        "api_key_here",
    ];
    PLACEHOLDERS.iter().any(|p| lower.contains(p))
}

pub fn has_assignment_context(line: &str, match_start: usize) -> bool {
    if match_start == 0 {
        return false;
    }
    let before = &line[..match_start.min(line.len())];
    let trimmed = before.trim_end();
    trimmed.ends_with('=')
        || trimmed.ends_with(':')
        || trimmed.ends_with("=>")
        || trimmed.ends_with("= ")
        || trimmed.ends_with(": ")
}

pub fn get_base_confidence(rule_id: &str) -> f64 {
    match rule_id {
        "Private Key" => 0.95,
        "AWS Key" | "AWS Secret Key" => 0.90,
        "GitHub Token" | "GitLab PAT" => 0.90,
        "Slack Token" => 0.85,
        "Stripe API Key" | "Stripe Secret Key" => 0.90,
        "Google Cloud API Key" => 0.85,
        "Firebase Server Key" => 0.85,
        "SendGrid API Key" => 0.90,
        "Discord Bot Token" => 0.80,
        "Telegram Bot Token" => 0.75,
        "NPM Auth Token" | "PyPI Token" => 0.90,
        "DigitalOcean Token" => 0.90,
        "Discord Webhook" | "Slack Incoming Webhook" => 0.90,
        "Database Connection String" => 0.85,
        "Supabase Service Key" => 0.85,
        "Azure Storage Key" => 0.80,
        "GCP Service Account Key" => 0.80,
        "Crypto Mining" => 0.85,
        "JNDI Injection" => 0.90,
        "Docker Socket Mount" => 0.80,
        "Cloud Metadata SSRF" => 0.75,
        "Remote Script Execution" | "Encoded Payload Execution" => 0.80,
        "SSH Key Injection" | "Crontab Injection" => 0.75,
        "Sensitive File Access" => 0.70,
        "PowerShell Encoded" => 0.80,
        "NPM Dangerous Hook" => 0.85,
        "Unsafe Deserialization" => 0.70,
        "Heroku API Key" | "Twilio Auth Token" | "Mailgun API Key" | "Datadog API Key" => 0.75,
        "Twilio SID" => 0.70,
        "Password in URL" => 0.65,
        "Tunnel Service URL" => 0.60,
        "JSON Web Token (JWT)" => 0.45,
        "Google OAuth Client ID" => 0.50,
        "Generic API Key" => 0.40,
        "High Entropy String" => 0.30,
        "Suspicious Command" => 0.50,
        "Suspicious JS Keyword" => 0.25,
        "Invisible Whitespace" => 0.35,
        "Hidden IOC (Base64)" => 0.70,
        _ => 0.50,
    }
}

pub fn calculate_pattern_confidence(
    rule_id: &str,
    matched_value: &str,
    line: &str,
    match_start: usize,
) -> f64 {
    let mut confidence = get_base_confidence(rule_id);

    if is_placeholder(matched_value) {
        return 0.05;
    }

    let entropy = calculate_entropy(matched_value);
    if matched_value.len() >= 16 {
        if entropy > 5.5 {
            confidence += 0.1;
        } else if entropy < 3.5 {
            confidence -= 0.2;
        }
    }

    if has_assignment_context(line, match_start) {
        confidence += 0.1;
    }

    confidence.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_single_char() {
        assert_eq!(calculate_entropy("aaaa"), 0.0);
    }

    #[test]
    fn test_entropy_high() {
        let entropy = calculate_entropy("aB3$xY9!mK2@nW5#");
        assert!(entropy > 3.5);
    }

    #[test]
    fn test_placeholder_detection() {
        assert!(is_placeholder("your_api_key"));
        assert!(is_placeholder("CHANGE_ME"));
        assert!(is_placeholder("todo_replace"));
        assert!(!is_placeholder("ghp_a1b2c3d4e5f6g7h8i9j0"));
    }

    #[test]
    fn test_placeholder_returns_low_confidence() {
        let conf = calculate_pattern_confidence("AWS Key", "your_aws_key_here", "key = your_aws_key_here", 6);
        assert!(conf < 0.1);
    }

    #[test]
    fn test_assignment_context() {
        assert!(has_assignment_context("API_KEY = sk-abc123", 10));
        assert!(has_assignment_context("token: ghp_xyz", 7));
        assert!(!has_assignment_context("sk-abc123", 0));
    }
}
