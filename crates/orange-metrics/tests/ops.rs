//! The operator assets in `ops/` and the metric table of spec 11 cannot
//! drift from what a node exports: every metric an alert or a dashboard
//! query names exists, the alert thresholds are the doctor's defaults, and
//! the spec lists exactly the exported families with their types and labels.

use std::collections::BTreeSet;

use orange_metrics::node::ALL;
use orange_metrics::{DEFAULT_LIMITS, NodeMetrics, exported_names, parse};
use serde_json::Value;

const ALERTS: &str = include_str!("../../../ops/alerts.yml");
const PROMETHEUS: &str = include_str!("../../../ops/prometheus.yml");
const DASHBOARD: &str = include_str!("../../../ops/grafana-orange.json");
const SPEC: &str = include_str!("../../../spec/11-telemetry.md");

/// Names Prometheus itself synthesizes for every target.
const SYNTHESIZED: &[&str] = &["up"];

/// Query-language words that are not metrics and need not be followed by `(`:
/// binary operators, modifiers, and the aggregation operators, which may
/// take `by (...)` before their argument.
const KEYWORDS: &[&str] = &[
    "and",
    "or",
    "unless",
    "bool",
    "offset",
    "sum",
    "min",
    "max",
    "avg",
    "group",
    "stddev",
    "stdvar",
    "count",
    "count_values",
    "bottomk",
    "topk",
    "quantile",
];

/// Query-language modifiers whose parenthesized list names labels, not metrics.
const GROUPING: &[&str] = &[
    "by",
    "without",
    "on",
    "ignoring",
    "group_left",
    "group_right",
];

/// Drops string literals, label matchers and range selectors, leaving a
/// space where each was.
fn strip(expr: &str) -> String {
    let mut out = String::new();
    // The closing characters expected, innermost last.
    let mut open: Vec<char> = Vec::new();
    let mut escaped = false;
    for c in expr.chars() {
        let closes = match open.last() {
            Some('"') if escaped => {
                escaped = false;
                false
            }
            Some('"') => {
                escaped = c == '\\';
                c == '"'
            }
            Some(end) if c == *end => true,
            Some(_) => {
                if c == '"' {
                    open.push('"');
                }
                false
            }
            None => {
                match c {
                    '"' => open.push('"'),
                    '{' => open.push('}'),
                    '[' => open.push(']'),
                    _ => out.push(c),
                }
                false
            }
        };
        if closes {
            open.pop();
            if open.is_empty() {
                out.push(' ');
            }
        }
    }
    out
}

/// The metric names a Prometheus query expression reads.
fn metric_names(expr: &str) -> Vec<String> {
    let text = strip(expr);
    let chars: Vec<char> = text.chars().collect();
    let mut names = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_ascii_digit() || c == '.' {
            // A number, including any exponent or unit letters.
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            continue;
        }
        if !(c.is_ascii_alphabetic() || c == '_' || c == ':') {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len()
            && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == ':')
        {
            i += 1;
        }
        let word: String = chars[start..i].iter().collect();
        let mut next = i;
        while next < chars.len() && chars[next] == ' ' {
            next += 1;
        }
        let call = chars.get(next) == Some(&'(');
        if call && GROUPING.contains(&word.as_str()) {
            // Skip the label list.
            while i < chars.len() && chars[i] != ')' {
                i += 1;
            }
        } else if !call && !KEYWORDS.contains(&word.as_str()) {
            names.push(word);
        }
    }
    names
}

fn check(source: &str, expr: &str) {
    let exported = exported_names();
    let names = metric_names(expr);
    assert!(!names.is_empty(), "{source}: `{expr}` reads no metric");
    for name in names {
        assert!(
            exported.contains(&name) || SYNTHESIZED.contains(&name.as_str()),
            "{source}: `{expr}` reads `{name}`, which the node does not export"
        );
    }
}

#[test]
fn the_extractor_understands_promql() {
    assert_eq!(
        metric_names(
            r#"histogram_quantile(0.99, sum by (le, instance) (rate(a_bucket{x="}",y=~"b"}[5m]))) > 1e3 and on(job) up == bool 0 offset 5m"#
        ),
        vec!["a_bucket", "up"]
    );
    assert_eq!(
        metric_names(r#"m{a="q\"}"} - n:rate5m"#),
        vec!["m", "n:rate5m"]
    );
    assert!(metric_names("time() - 1").is_empty());
}

fn alert_rules() -> Vec<(String, String)> {
    let mut rules = Vec::new();
    let mut alert = None;
    for line in ALERTS.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("- alert:") {
            alert = Some(name.trim().to_owned());
        } else if let Some(expr) = line.strip_prefix("expr:") {
            let expr = expr.trim();
            assert!(
                !expr.is_empty() && !expr.starts_with('|') && !expr.starts_with('>'),
                "keep each alert expression on its own line: {line}"
            );
            let name = alert.take().expect("an expr follows its alert name");
            rules.push((name, expr.to_owned()));
        }
    }
    rules
}

#[test]
fn alert_rules_read_exported_metrics() {
    let rules = alert_rules();
    assert_eq!(rules.len(), ALERTS.matches("- alert:").count());
    assert!(rules.len() >= 9);
    for (name, expr) in &rules {
        check(name, expr);
    }
    assert!(PROMETHEUS.contains("- alerts.yml"));
    assert!(PROMETHEUS.contains("job_name: orange"));
}

/// The number after the last comparison operator of an expression, up to
/// the first character that cannot be part of it.
fn threshold(expr: &str) -> f64 {
    let at = expr.rfind(['>', '<']).expect("a comparison");
    leading_number(&expr[at + 1..])
}

fn leading_number(text: &str) -> f64 {
    let text = text.trim_start();
    let end = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    text[..end]
        .parse()
        .unwrap_or_else(|_| panic!("a number at the start of `{text}`"))
}

/// The Condition cell of `alert`'s row in the alert table of spec 11 §7.
fn spec_condition(alert: &str) -> &'static str {
    let row = SPEC
        .lines()
        .find(|l| l.starts_with(&format!("| `{alert}` |")))
        .unwrap_or_else(|| panic!("{alert} is not in the spec's alert table"));
    row.split('|').nth(2).unwrap()
}

/// The default the spec 11 §7 doctor list gives for `flag`, read from
/// `(default N <unit>, `flag`)`.
fn spec_default(flag: &str) -> f64 {
    let item = SPEC
        .lines()
        .find(|l| l.contains(&format!("`{flag}`")) && l.contains("(default "))
        .unwrap_or_else(|| panic!("{flag} has no default in the spec"));
    let at = item.find("(default ").unwrap() + "(default ".len();
    leading_number(&item[at..])
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn alert_thresholds_are_the_doctor_defaults() {
    let rules = alert_rules();
    let expr = |alert: &str| {
        rules
            .iter()
            .find(|(name, _)| name == alert)
            .map_or_else(|| panic!("{alert} missing"), |(_, expr)| expr.as_str())
    };
    let d = DEFAULT_LIMITS;
    let pairs = [
        ("OrangeHeadNotAdvancing", d.max_head_age_seconds),
        ("OrangeFinalityLag", d.max_finality_lag as f64),
        ("OrangeNoPeers", d.min_peers as f64),
        ("OrangeMempoolBacklog", d.max_mempool as f64),
        ("OrangeKernelCallSlow", d.max_call_seconds),
    ];
    for (alert, limit) in pairs {
        assert!(
            (threshold(expr(alert)) - limit).abs() < f64::EPSILON,
            "{alert}: `{}` does not use the doctor's limit {limit}",
            expr(alert)
        );
        // The spec's alert table states the same threshold.
        assert!(
            (threshold(spec_condition(alert)) - limit).abs() < f64::EPSILON,
            "{alert}: spec 11 says `{}`, the doctor's limit is {limit}",
            spec_condition(alert)
        );
    }
    // So does the spec's list of the doctor's checks.
    let defaults = [
        ("--max-head-age", d.max_head_age_seconds),
        ("--max-finality-lag", d.max_finality_lag as f64),
        ("--min-peers", d.min_peers as f64),
        ("--max-mempool", d.max_mempool as f64),
        ("--max-call-ms", d.max_call_seconds),
    ];
    for (flag, limit) in defaults {
        assert!(
            (spec_default(flag) - limit).abs() < f64::EPSILON,
            "{flag}: spec 11 says {}, the doctor's default is {limit}",
            spec_default(flag)
        );
    }
    // Every alert spec 11 §7 lists is in the rule file, and only those.
    let listed: BTreeSet<String> = SPEC
        .lines()
        .filter_map(|l| l.strip_prefix("| `Orange"))
        .map(|l| format!("Orange{}", l.split('`').next().unwrap()))
        .collect();
    let shipped: BTreeSet<String> = rules.into_iter().map(|(name, _)| name).collect();
    assert_eq!(listed, shipped);
}

#[test]
fn spec_thresholds_are_read_from_the_right_place() {
    assert!((threshold("p99 of `x` over 5 m `> 1` s, per entrypoint") - 1.0).abs() < f64::EPSILON);
    assert!((leading_number(" 16, `--x`)") - 16.0).abs() < f64::EPSILON);
    assert_eq!(
        spec_condition("OrangeMempoolBacklog").trim(),
        "`orange_mempool_transactions > 1000`"
    );
}

/// An alert on `increase(c[w]) > 0` misses the first event of a series that
/// is born at 1, since `increase` needs two samples of the same series:
/// every series such a rule reads exists, at zero, from the moment the
/// node opens.
#[test]
fn increase_alerts_read_series_that_exist_from_the_start() {
    let at_open = parse(&NodeMetrics::new().render()).unwrap();
    let mut checked = 0;
    for (alert, expr) in alert_rules() {
        if !expr.contains("increase(") {
            continue;
        }
        for name in metric_names(&expr) {
            let series: Vec<_> = at_open.iter().filter(|s| s.name == name).collect();
            assert!(
                !series.is_empty() && series.iter().all(|s| s.value == 0.0),
                "{alert}: `{name}` has no zero series when the node opens"
            );
            checked += 1;
        }
    }
    assert!(checked >= 3);
}

fn queries(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (key, value) in map {
                match (key.as_str(), value) {
                    ("expr" | "definition", Value::String(s)) => out.push(s.clone()),
                    _ => queries(value, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| queries(item, out)),
        _ => {}
    }
}

#[test]
fn dashboard_queries_read_exported_metrics() {
    let dashboard: Value = serde_json::from_str(DASHBOARD).unwrap();
    assert_eq!(dashboard["uid"], "orange-node");
    let mut found = Vec::new();
    queries(&dashboard, &mut found);
    assert!(found.len() >= 20, "{found:?}");
    for query in &found {
        // `label_values(metric, label)`: only the first argument is a metric.
        let expr = query
            .strip_prefix("label_values(")
            .map_or(query.as_str(), |rest| rest.split(',').next().unwrap());
        check("ops/grafana-orange.json", expr);
    }
    // Every family is on the dashboard somewhere.
    let all = found.join("\n");
    for d in ALL {
        assert!(all.contains(d.name), "{} is not on the dashboard", d.name);
    }
}

#[test]
fn spec_lists_exactly_the_exported_families() {
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in SPEC.lines() {
        if line.starts_with("| Name | Type | Labels |") {
            in_table = true;
            continue;
        }
        if in_table && !line.starts_with('|') {
            break;
        }
        if in_table && line.starts_with("| `") {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            rows.push((
                cells[1].trim_matches('`').to_owned(),
                cells[2].to_owned(),
                cells[3].to_owned(),
            ));
        }
    }
    assert_eq!(rows.len(), ALL.len(), "{rows:?}");
    for (d, (name, kind, labels)) in ALL.iter().zip(&rows) {
        assert_eq!(d.name, name);
        assert_eq!(d.kind.as_str(), kind, "{name}");
        let expected = if d.labels.is_empty() {
            "—".to_owned()
        } else {
            d.labels
                .iter()
                .map(|l| format!("`{l}`"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        assert_eq!(&expected, labels, "{name}");
    }
}
