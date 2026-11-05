//! Metric families, label sets and the Prometheus text exposition format,
//! version 0.0.4 (spec 11 §3).

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The `Content-Type` of [`Registry::render`] output.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// What a family measures and how it is exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A value that only grows while the node runs.
    Counter,
    /// A value that goes up and down.
    Gauge,
    /// Observations counted into fixed buckets, with their sum and count.
    Histogram,
}

impl Kind {
    /// The word on the family's `# TYPE` line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
            Kind::Histogram => "histogram",
        }
    }
}

/// The fixed description of one metric family.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Desc {
    /// Family name; for a counter it ends in `_total`.
    pub name: &'static str,
    /// The text of the `# HELP` line.
    pub help: &'static str,
    /// How the family is exposed.
    pub kind: Kind,
    /// Label names, in the order every series gives their values.
    pub labels: &'static [&'static str],
    /// Bucket upper bounds of a histogram, ascending, without `+Inf`; empty
    /// for other kinds.
    pub buckets: &'static [f64],
}

impl Desc {
    /// The sample names this family exposes: its own name, or for a
    /// histogram the `_bucket`, `_sum` and `_count` series.
    #[must_use]
    pub fn sample_names(&self) -> Vec<String> {
        match self.kind {
            Kind::Histogram => ["_bucket", "_sum", "_count"]
                .iter()
                .map(|suffix| format!("{}{suffix}", self.name))
                .collect(),
            Kind::Counter | Kind::Gauge => vec![self.name.to_owned()],
        }
    }
}

/// Whether `name` is a valid metric name: `[a-zA-Z_:][a-zA-Z0-9_:]*`.
#[must_use]
pub fn valid_metric_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == ':')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

/// Whether `name` is a valid label name: `[a-zA-Z_][a-zA-Z0-9_]*`, not
/// starting with the reserved `__`.
#[must_use]
pub fn valid_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    !name.starts_with("__")
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, PartialEq)]
enum Series {
    Value(f64),
    /// Cumulative bucket counts (one per bound), the sum and the count.
    Histogram {
        buckets: Vec<u64>,
        sum: f64,
        count: u64,
    },
}

#[derive(Debug, Clone, PartialEq)]
struct Family {
    desc: Desc,
    series: BTreeMap<Vec<String>, Series>,
}

/// A set of metric families, rendered in name order.
///
/// A family appears in the output once it is registered or first recorded;
/// a series (one set of label values) appears once it is first recorded.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Registry {
    families: BTreeMap<&'static str, Family>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Registry {
        Registry::default()
    }

    /// Makes `desc` appear in the output, with its `HELP` and `TYPE` lines,
    /// before anything is recorded in it.
    ///
    /// # Panics
    /// If the name or a label name is invalid, or a histogram has no buckets.
    pub fn register(&mut self, desc: &Desc) {
        assert!(valid_metric_name(desc.name), "metric name {}", desc.name);
        assert!(
            desc.labels
                .iter()
                .all(|l| valid_label_name(l) && *l != "le"),
            "label names of {}",
            desc.name
        );
        assert!(
            (desc.kind == Kind::Histogram) != desc.buckets.is_empty(),
            "buckets of {}",
            desc.name
        );
        self.family(desc);
    }

    fn family(&mut self, desc: &Desc) -> &mut Family {
        self.families.entry(desc.name).or_insert_with(|| Family {
            desc: *desc,
            series: BTreeMap::new(),
        })
    }

    fn slot(&mut self, desc: &Desc, labels: &[&str]) -> &mut Series {
        assert_eq!(labels.len(), desc.labels.len(), "labels of {}", desc.name);
        let fresh = match desc.kind {
            Kind::Histogram => Series::Histogram {
                buckets: vec![0; desc.buckets.len()],
                sum: 0.0,
                count: 0,
            },
            Kind::Counter | Kind::Gauge => Series::Value(0.0),
        };
        let key: Vec<String> = labels.iter().map(|l| (*l).to_owned()).collect();
        self.family(desc).series.entry(key).or_insert(fresh)
    }

    /// Adds `by` to a counter or gauge series. Counters only grow: a
    /// negative `by` on a counter is ignored. No effect on a histogram.
    ///
    /// # Panics
    /// If `labels` does not give one value per label name of `desc`.
    pub fn inc(&mut self, desc: &Desc, labels: &[&str], by: f64) {
        let ignored = desc.kind == Kind::Counter && by < 0.0;
        if let (Series::Value(v), false) = (self.slot(desc, labels), ignored) {
            *v += by;
        }
    }

    /// Sets a gauge (or counter) series. No effect on a histogram.
    ///
    /// # Panics
    /// As [`Registry::inc`].
    pub fn set(&mut self, desc: &Desc, labels: &[&str], value: f64) {
        if let Series::Value(v) = self.slot(desc, labels) {
            *v = value;
        }
    }

    /// Counts one observation into a histogram series. No effect on a
    /// counter or gauge.
    ///
    /// # Panics
    /// As [`Registry::inc`].
    pub fn observe(&mut self, desc: &Desc, labels: &[&str], value: f64) {
        if let Series::Histogram {
            buckets,
            sum,
            count,
        } = self.slot(desc, labels)
        {
            for (n, bound) in buckets.iter_mut().zip(desc.buckets) {
                *n += u64::from(value <= *bound);
            }
            *sum += value;
            *count += 1;
        }
    }

    fn get(&self, desc: &Desc, labels: &[&str]) -> Option<&Series> {
        let key: Vec<String> = labels.iter().map(|l| (*l).to_owned()).collect();
        self.families.get(desc.name)?.series.get(&key)
    }

    /// The value of a counter or gauge series, if it was recorded.
    #[must_use]
    pub fn value(&self, desc: &Desc, labels: &[&str]) -> Option<f64> {
        match self.get(desc, labels)? {
            Series::Value(v) => Some(*v),
            Series::Histogram { .. } => None,
        }
    }

    /// The `(count, sum)` of a histogram series, if it was recorded.
    #[must_use]
    pub fn histogram(&self, desc: &Desc, labels: &[&str]) -> Option<(u64, f64)> {
        match self.get(desc, labels)? {
            Series::Histogram { count, sum, .. } => Some((*count, *sum)),
            Series::Value(_) => None,
        }
    }

    /// How many series `desc` has.
    #[must_use]
    pub fn series(&self, desc: &Desc) -> usize {
        self.families.get(desc.name).map_or(0, |f| f.series.len())
    }

    /// Whether the series exists.
    #[must_use]
    pub fn contains(&self, desc: &Desc, labels: &[&str]) -> bool {
        self.get(desc, labels).is_some()
    }

    /// The text exposition format 0.0.4 of every family, in name order.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for family in self.families.values() {
            let d = &family.desc;
            let _ = writeln!(out, "# HELP {} {}", d.name, escape_help(d.help));
            let _ = writeln!(out, "# TYPE {} {}", d.name, d.kind.as_str());
            for (values, series) in &family.series {
                let labels: Vec<(&str, &str)> = d
                    .labels
                    .iter()
                    .copied()
                    .zip(values.iter().map(String::as_str))
                    .collect();
                render_series(&mut out, d, &labels, series);
            }
        }
        out
    }
}

#[allow(clippy::cast_precision_loss)]
fn render_series(out: &mut String, d: &Desc, labels: &[(&str, &str)], series: &Series) {
    match series {
        Series::Value(v) => sample(out, d.name, labels, None, *v),
        Series::Histogram {
            buckets,
            sum,
            count,
        } => {
            let bucket = format!("{}_bucket", d.name);
            for (bound, n) in d.buckets.iter().zip(buckets) {
                sample(out, &bucket, labels, Some(&format_value(*bound)), *n as f64);
            }
            sample(out, &bucket, labels, Some("+Inf"), *count as f64);
            sample(out, &format!("{}_sum", d.name), labels, None, *sum);
            sample(
                out,
                &format!("{}_count", d.name),
                labels,
                None,
                *count as f64,
            );
        }
    }
}

fn sample(out: &mut String, name: &str, labels: &[(&str, &str)], le: Option<&str>, value: f64) {
    out.push_str(name);
    let pairs: Vec<(&str, &str)> = labels
        .iter()
        .copied()
        .chain(le.map(|b| ("le", b)))
        .collect();
    if !pairs.is_empty() {
        out.push('{');
        for (i, (label, v)) in pairs.iter().enumerate() {
            let comma = if i == 0 { "" } else { "," };
            let _ = write!(out, "{comma}{label}=\"{}\"", escape_label(v));
        }
        out.push('}');
    }
    let _ = writeln!(out, " {}", format_value(value));
}

/// A sample value as the format writes it: `NaN`, `+Inf`, `-Inf`, or the
/// shortest decimal that reads back as the same `f64`.
#[must_use]
pub fn format_value(v: f64) -> String {
    if v.is_nan() {
        "NaN".to_owned()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf" } else { "-Inf" }.to_owned()
    } else {
        format!("{v}")
    }
}

/// Escapes `HELP` text: backslash and line feed.
#[must_use]
pub fn escape_help(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\n', "\\n")
}

/// Escapes a label value: backslash, double quote and line feed.
#[must_use]
pub fn escape_label(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUESTS: Desc = Desc {
        name: "requests_total",
        help: "Requests.\nWith a \\ in help.",
        kind: Kind::Counter,
        labels: &["path"],
        buckets: &[],
    };
    const TEMPERATURE: Desc = Desc {
        name: "temperature",
        help: "Degrees.",
        kind: Kind::Gauge,
        labels: &[],
        buckets: &[],
    };
    const LATENCY: Desc = Desc {
        name: "latency_seconds",
        help: "Latency.",
        kind: Kind::Histogram,
        labels: &["op"],
        buckets: &[0.1, 1.0],
    };

    #[test]
    fn renders_every_kind_with_escaping() {
        let mut r = Registry::new();
        r.register(&TEMPERATURE);
        assert_eq!(
            r.render(),
            "# HELP temperature Degrees.\n# TYPE temperature gauge\n"
        );
        r.inc(&REQUESTS, &["/a\"b\\c\nd"], 2.0);
        r.inc(&REQUESTS, &["/a\"b\\c\nd"], 1.5);
        r.inc(&REQUESTS, &["/a\"b\\c\nd"], -10.0);
        r.set(&TEMPERATURE, &[], -3.25);
        r.inc(&TEMPERATURE, &[], -1.0);
        r.observe(&LATENCY, &["x"], 0.0625);
        r.observe(&LATENCY, &["x"], 0.5);
        r.observe(&LATENCY, &["x"], 7.0);
        // Records of the wrong kind change nothing.
        r.observe(&TEMPERATURE, &[], 9.0);
        r.set(&LATENCY, &["x"], 9.0);
        r.inc(&LATENCY, &["x"], 9.0);
        let text = r.render();
        assert_eq!(
            text,
            "# HELP latency_seconds Latency.\n\
             # TYPE latency_seconds histogram\n\
             latency_seconds_bucket{op=\"x\",le=\"0.1\"} 1\n\
             latency_seconds_bucket{op=\"x\",le=\"1\"} 2\n\
             latency_seconds_bucket{op=\"x\",le=\"+Inf\"} 3\n\
             latency_seconds_sum{op=\"x\"} 7.5625\n\
             latency_seconds_count{op=\"x\"} 3\n\
             # HELP requests_total Requests.\\nWith a \\\\ in help.\n\
             # TYPE requests_total counter\n\
             requests_total{path=\"/a\\\"b\\\\c\\nd\"} 3.5\n\
             # HELP temperature Degrees.\n\
             # TYPE temperature gauge\n\
             temperature -4.25\n"
        );
        assert_eq!(r.value(&TEMPERATURE, &[]), Some(-4.25));
        assert_eq!(r.value(&LATENCY, &["x"]), None);
        assert_eq!(r.value(&REQUESTS, &["nope"]), None);
        assert_eq!(r.histogram(&LATENCY, &["x"]), Some((3, 7.5625)));
        assert_eq!(r.histogram(&TEMPERATURE, &[]), None);
        assert_eq!(r.histogram(&LATENCY, &["y"]), None);
        assert_eq!(r.series(&REQUESTS), 1);
        assert_eq!(
            r.series(&Desc {
                name: "absent",
                ..TEMPERATURE
            }),
            0
        );
        assert!(r.contains(&LATENCY, &["x"]));
        assert!(!r.contains(&LATENCY, &["y"]));
        assert_eq!(r.clone(), r);
        assert!(format!("{r:?}").contains("latency_seconds"));
    }

    #[test]
    fn values_and_names() {
        assert_eq!(format_value(f64::NAN), "NaN");
        assert_eq!(format_value(f64::INFINITY), "+Inf");
        assert_eq!(format_value(f64::NEG_INFINITY), "-Inf");
        assert_eq!(format_value(0.1 + 0.2), "0.30000000000000004");
        assert_eq!(format_value(1e21), "1000000000000000000000");
        assert!(valid_metric_name("a:b_c9"));
        assert!(valid_metric_name("_x"));
        assert!(!valid_metric_name(""));
        assert!(!valid_metric_name("9a"));
        assert!(!valid_metric_name("a-b"));
        assert!(valid_label_name("entry_point"));
        assert!(!valid_label_name("__name"));
        assert!(!valid_label_name("1a"));
        assert!(!valid_label_name("a:b"));
        assert!(!valid_label_name(""));
        assert_eq!(Kind::Gauge.as_str(), "gauge");
        assert_eq!(
            LATENCY.sample_names(),
            vec![
                "latency_seconds_bucket",
                "latency_seconds_sum",
                "latency_seconds_count"
            ]
        );
        assert_eq!(REQUESTS.sample_names(), vec!["requests_total"]);
    }

    #[test]
    #[should_panic(expected = "metric name")]
    fn bad_metric_name_is_refused() {
        Registry::new().register(&Desc {
            name: "a-b",
            ..TEMPERATURE
        });
    }

    #[test]
    #[should_panic(expected = "label names")]
    fn reserved_label_is_refused() {
        Registry::new().register(&Desc {
            labels: &["le"],
            ..LATENCY
        });
    }

    #[test]
    #[should_panic(expected = "buckets")]
    fn histogram_without_buckets_is_refused() {
        Registry::new().register(&Desc {
            buckets: &[],
            ..LATENCY
        });
    }

    #[test]
    #[should_panic(expected = "labels of")]
    fn wrong_label_count_is_refused() {
        Registry::new().inc(&REQUESTS, &[], 1.0);
    }
}
