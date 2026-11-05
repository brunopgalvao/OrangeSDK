//! Reading the text exposition format back: what `orange doctor` does with a
//! node's `/metrics`, and how the tests check [`crate::Registry::render`].

/// One sample line.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Sample name, including any `_bucket`, `_sum` or `_count` suffix.
    pub name: String,
    /// Label pairs in the order they were written.
    pub labels: Vec<(String, String)>,
    /// The value.
    pub value: f64,
}

impl Sample {
    /// The value of label `name`, if present.
    #[must_use]
    pub fn label(&self, name: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Why a line did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line number.
    pub line: usize,
    /// What was wrong.
    pub message: &'static str,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parses every sample in `text`, skipping blank lines and `#` comments
/// (`HELP` and `TYPE` included). A timestamp after the value is ignored.
///
/// # Errors
/// The first line that is not a valid sample.
pub fn parse(text: &str) -> Result<Vec<Sample>, ParseError> {
    let mut samples = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let sample = parse_line(line).map_err(|message| ParseError {
            line: index + 1,
            message,
        })?;
        samples.push(sample);
    }
    Ok(samples)
}

struct Cursor<'a> {
    rest: &'a str,
}

impl<'a> Cursor<'a> {
    fn eat(&mut self, c: char) -> bool {
        match self.rest.strip_prefix(c) {
            Some(rest) => {
                self.rest = rest;
                true
            }
            None => false,
        }
    }

    fn take_while(&mut self, keep: fn(char) -> bool) -> &'a str {
        let end = self.rest.find(|c| !keep(c)).unwrap_or(self.rest.len());
        let (taken, rest) = self.rest.split_at(end);
        self.rest = rest;
        taken
    }

    fn skip_spaces(&mut self) {
        self.rest = self.rest.trim_start();
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.rest.chars().next()?;
        self.rest = &self.rest[c.len_utf8()..];
        Some(c)
    }
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == ':'
}

fn is_label_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_value_char(c: char) -> bool {
    !c.is_whitespace()
}

fn parse_line(line: &str) -> Result<Sample, &'static str> {
    let mut c = Cursor { rest: line };
    let name = c.take_while(is_name_char).to_owned();
    if name.is_empty() {
        return Err("expected a metric name");
    }
    let mut labels = Vec::new();
    if c.eat('{') {
        loop {
            c.skip_spaces();
            if c.eat('}') {
                break;
            }
            let label = c.take_while(is_label_char).to_owned();
            if label.is_empty() || !c.eat('=') || !c.eat('"') {
                return Err("expected label=\"value\"");
            }
            labels.push((label, label_value(&mut c)?));
            c.skip_spaces();
            if !c.eat(',') && !c.rest.starts_with('}') {
                return Err("expected , or } after a label");
            }
        }
    }
    c.skip_spaces();
    let value = c
        .take_while(is_value_char)
        .parse::<f64>()
        .ok()
        .ok_or("expected a number")?;
    Ok(Sample {
        name,
        labels,
        value,
    })
}

fn label_value(c: &mut Cursor<'_>) -> Result<String, &'static str> {
    let mut value = String::new();
    loop {
        match c.bump().ok_or("unterminated label value")? {
            '"' => return Ok(value),
            '\\' => match c.bump() {
                Some('n') => value.push('\n'),
                Some(e @ ('\\' | '"')) => value.push(e),
                _ => return Err("bad escape in a label value"),
            },
            other => value.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_labels_and_comments() {
        let text = "# HELP x Help.\n# TYPE x gauge\n\nx 1\n  y{a=\"1\", b=\"q\\\"\\\\\\nz\",} -2.5 1700000000\nz{} +Inf\nw{a=\"é\"} NaN\n";
        let samples = parse(text).unwrap();
        assert_eq!(samples.len(), 4);
        assert_eq!(samples[0].name, "x");
        assert!(samples[0].labels.is_empty());
        assert!((samples[0].value - 1.0).abs() < f64::EPSILON);
        assert_eq!(samples[1].label("a"), Some("1"));
        assert_eq!(samples[1].label("b"), Some("q\"\\\nz"));
        assert_eq!(samples[1].label("c"), None);
        assert!((samples[1].value + 2.5).abs() < f64::EPSILON);
        assert!(samples[2].value.is_infinite());
        assert!(samples[3].value.is_nan());
        assert_eq!(samples[3].label("a"), Some("é"));
    }

    #[test]
    fn errors_name_the_line() {
        let cases = [
            ("{a=\"1\"} 1", "expected a metric name"),
            ("x{a} 1", "expected label=\"value\""),
            ("x{=\"1\"} 1", "expected label=\"value\""),
            ("x{a=1} 1", "expected label=\"value\""),
            ("x{a=\"1", "unterminated label value"),
            ("x{a=\"\\t\"} 1", "bad escape in a label value"),
            ("x{a=\"\\", "bad escape in a label value"),
            ("x{a=\"1\" b=\"2\"} 1", "expected , or } after a label"),
            ("x", "expected a number"),
            ("x one", "expected a number"),
        ];
        for (line, message) in cases {
            let err = parse(&format!("ok 1\n{line}\n")).unwrap_err();
            assert_eq!(err, ParseError { line: 2, message }, "{line}");
        }
        let err = parse("x{").unwrap_err();
        assert_eq!(err.to_string(), "line 1: expected label=\"value\"");
        let boxed: Box<dyn std::error::Error> = Box::new(err.clone());
        assert!(boxed.to_string().contains("line 1"));
        assert!(format!("{err:?}").contains("ParseError"));
    }
}
