//! Whatever the registry renders, the parser reads back exactly: label
//! values with any characters, and any finite value.

use proptest::prelude::*;
use solo_metrics::{Desc, Kind, Registry, parse};

const SERIES: Desc = Desc {
    name: "roundtrip_gauge",
    help: "A gauge with two labels.",
    kind: Kind::Gauge,
    labels: &["a", "b"],
    buckets: &[],
};

const HISTOGRAM: Desc = Desc {
    name: "roundtrip_seconds",
    help: "A histogram.",
    kind: Kind::Histogram,
    labels: &["op"],
    buckets: &[0.5, 1.0, 2.0],
};

proptest! {
    #[test]
    fn rendered_samples_parse_back(
        entries in proptest::collection::btree_map(
            (any::<String>(), "[\\\\\"\n a-z]{0,8}"),
            any::<f64>().prop_filter("finite", |v| v.is_finite()),
            0..8,
        ),
        observations in proptest::collection::vec(0.0f64..4.0, 0..20),
    ) {
        let mut r = Registry::new();
        for ((a, b), v) in &entries {
            r.set(&SERIES, &[a, b], *v);
        }
        for v in &observations {
            r.observe(&HISTOGRAM, &["x\"y"], *v);
        }
        let samples = parse(&r.render()).unwrap();
        let gauges: Vec<_> = samples.iter().filter(|s| s.name == SERIES.name).collect();
        prop_assert_eq!(gauges.len(), entries.len());
        for ((a, b), v) in &entries {
            let found = gauges
                .iter()
                .find(|s| s.label("a") == Some(a) && s.label("b") == Some(b))
                .unwrap();
            prop_assert_eq!(found.value.to_bits(), v.to_bits());
        }
        if !observations.is_empty() {
            let count = samples
                .iter()
                .find(|s| s.name == "roundtrip_seconds_count")
                .unwrap();
            prop_assert_eq!(count.label("op"), Some("x\"y"));
            #[allow(clippy::cast_precision_loss)]
            let n = observations.len() as f64;
            prop_assert!((count.value - n).abs() < f64::EPSILON);
            let buckets: Vec<f64> = samples
                .iter()
                .filter(|s| s.name == "roundtrip_seconds_bucket")
                .map(|s| s.value)
                .collect();
            prop_assert_eq!(buckets.len(), 4);
            prop_assert!(buckets.windows(2).all(|w| w[0] <= w[1]));
            prop_assert!((buckets[3] - n).abs() < f64::EPSILON);
        }
    }
}
