//! Parsed system-one and model-list responses.
//!
//! The raw body is kept as [`Bytes`] so `raw_body` does not copy it. Typed
//! fields are parsed from that slice. A plain `serde_json::from_slice` is tried
//! first; [`serde_path_to_error`] runs only after that fails.

use std::fmt;
use std::marker::PhantomData;

use bytes::Bytes;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;

use crate::error::{self, Error};

/// Token counts for one request. Missing counts stay `None`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Usage {
    /// Input tokens, when the API reported them.
    #[serde(default)]
    pub input_tokens: Option<i64>,
    /// Output tokens, when the API reported them.
    #[serde(default)]
    pub output_tokens: Option<i64>,
}

/// One model returned by `GET /v1/models`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ModelMetadata {
    /// Name accepted by a system-one request.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Release date, `YYYY-MM-DD`.
    pub release_date: String,
}

/// Yes/no answer.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct NoulAnswer {
    /// Probability of yes, from 0 to 1.
    pub noul: f64,
}

/// Selected label and its probabilities.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ChoiceAnswer {
    /// Label with the highest probability.
    pub choice: String,
    /// Confidence in that label, from 0 to 1.
    pub confidence: f64,
    /// Probability of each label, in response order.
    #[serde(deserialize_with = "string_map")]
    pub probabilities: Vec<(String, f64)>,
}

/// Expected score, rubric, and per-level probabilities.
///
/// Legend and probability keys are the integer score levels. JSON sends those
/// keys as strings.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreAnswer {
    /// Probability-weighted score. It may fall between integer levels.
    pub score: f64,
    /// Confidence in the score, from 0 to 1.
    pub confidence: f64,
    /// Rubric text or JSON keyed by integer score, in response order.
    pub legend: Vec<(i64, Value)>,
    /// Probability of each score level, in response order.
    pub probabilities: Vec<(i64, f64)>,
}

impl ScoreAnswer {
    /// Rubric value for `score`, if that level was returned.
    #[must_use]
    pub fn legend_value(&self, score: i64) -> Option<&Value> {
        self.legend
            .iter()
            .find(|(level, _)| *level == score)
            .map(|(_, value)| value)
    }

    /// Probability for `score`, if that level was returned.
    #[must_use]
    pub fn probability(&self, score: i64) -> Option<f64> {
        self.probabilities
            .iter()
            .find(|(level, _)| *level == score)
            .map(|(_, probability)| *probability)
    }
}

/// An answer whose `type` this SDK understands.
///
/// Unknown `type` values are dropped while parsing, not represented here.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Answer {
    /// Yes/no answer.
    Noul(NoulAnswer),
    /// Choice answer.
    Choice(ChoiceAnswer),
    /// Score answer.
    Score(ScoreAnswer),
}

/// `POST /v1/systemone` response.
#[derive(Debug, Clone)]
pub struct SystemOneResponse {
    /// Model that answered the request.
    pub model: String,
    /// Token usage.
    pub usage: Usage,
    answers: Vec<(String, Answer)>,
    request_id: Option<String>,
    raw: Bytes,
}

impl SystemOneResponse {
    /// All answers in response order.
    pub fn answers(&self) -> impl Iterator<Item = (&str, &Answer)> {
        self.answers
            .iter()
            .map(|(name, answer)| (name.as_str(), answer))
    }

    /// Yes/no answers.
    pub fn nouls(&self) -> impl Iterator<Item = (&str, &NoulAnswer)> {
        self.answers().filter_map(|(name, answer)| match answer {
            Answer::Noul(answer) => Some((name, answer)),
            _ => None,
        })
    }

    /// Choice answers.
    pub fn choices(&self) -> impl Iterator<Item = (&str, &ChoiceAnswer)> {
        self.answers().filter_map(|(name, answer)| match answer {
            Answer::Choice(answer) => Some((name, answer)),
            _ => None,
        })
    }

    /// Score answers.
    pub fn scores(&self) -> impl Iterator<Item = (&str, &ScoreAnswer)> {
        self.answers().filter_map(|(name, answer)| match answer {
            Answer::Score(answer) => Some((name, answer)),
            _ => None,
        })
    }

    /// The answer named `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Answer> {
        self.answers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, answer)| answer)
    }

    /// `x-typesafe-request-id`, if the response included it.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// Original response bytes. Cloning the backing buffer is a refcount bump;
    /// this borrow does not copy them.
    #[must_use]
    pub fn raw_body(&self) -> &[u8] {
        &self.raw
    }
}

/// `GET /v1/models` response.
#[derive(Debug, Clone)]
pub struct ListModelsResponse {
    /// Models available to the account.
    pub models: Vec<ModelMetadata>,
    request_id: Option<String>,
    raw: Bytes,
}

impl ListModelsResponse {
    /// `x-typesafe-request-id`, if the response included it.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// Original response bytes.
    #[must_use]
    pub fn raw_body(&self) -> &[u8] {
        &self.raw
    }
}

pub(crate) fn parse_system_one(
    status: u16,
    body: Bytes,
    request_id: Option<String>,
    endpoint: &str,
) -> Result<SystemOneResponse, Error> {
    let Ok(wire) = serde_json::from_slice::<SystemOneWire>(&body) else {
        let path = json_field_path::<SystemOneWire>(&body);
        return Err(invalid(status, &body, request_id, endpoint, &path));
    };
    let mut answers = Vec::with_capacity(wire.answers.len());
    for (name, raw) in wire.answers {
        match interpret_answer(raw.get()) {
            AnswerParse::Known(answer) => answers.push((name, answer)),
            AnswerParse::Unknown { type_name } => {
                // Forward-compat: a future answer type must not fail the whole response.
                tracing::warn!(
                    answer = %name,
                    answer_type = %type_name,
                    "ignoring answer with unrecognized type"
                );
            }
            AnswerParse::Invalid { relative_path } => {
                let path = format!("answers.{name}.{relative_path}");
                return Err(invalid(status, &body, request_id, endpoint, &path));
            }
        }
    }
    Ok(SystemOneResponse {
        model: wire.model,
        usage: wire.usage,
        answers,
        request_id,
        raw: body,
    })
}

pub(crate) fn parse_models(
    status: u16,
    body: Bytes,
    request_id: Option<String>,
    endpoint: &str,
) -> Result<ListModelsResponse, Error> {
    let Ok(wire) = serde_json::from_slice::<ModelsWire>(&body) else {
        let path = json_field_path::<ModelsWire>(&body);
        return Err(invalid(status, &body, request_id, endpoint, &path));
    };
    Ok(ListModelsResponse {
        models: wire.models,
        request_id,
        raw: body,
    })
}

pub(crate) fn parse_json<T: de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    if let Ok(value) = serde_json::from_slice::<T>(bytes) {
        return Ok(value);
    }
    let path = json_field_path::<T>(bytes);
    Err(if path.is_empty() {
        ".".to_owned()
    } else {
        path
    })
}

fn invalid(
    status: u16,
    body: &[u8],
    request_id: Option<String>,
    endpoint: &str,
    field_path: &str,
) -> Error {
    Error::Api(Box::new(error::invalid_response(
        status, body, request_id, endpoint, field_path,
    )))
}

fn json_field_path<T: de::DeserializeOwned>(bytes: &[u8]) -> String {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    match serde_path_to_error::deserialize::<_, T>(&mut deserializer) {
        Err(error) => {
            let path = error.path().to_string();
            let path = if path.is_empty() { "." } else { path.as_str() };
            match missing_field(error.inner()) {
                Some(field) if path == "." => field,
                Some(field) if path != field && !path.ends_with(&format!(".{field}")) => {
                    format!("{path}.{field}")
                }
                _ => path.to_owned(),
            }
        }
        Ok(_) => String::new(),
    }
}

fn missing_field(error: &serde_json::Error) -> Option<String> {
    let rest = error
        .to_string()
        .strip_prefix("missing field `")?
        .to_owned();
    Some(rest.split('`').next()?.to_owned())
}

#[derive(Deserialize)]
struct SystemOneWire {
    model: String,
    usage: Usage,
    #[serde(default, deserialize_with = "raw_answers")]
    answers: Vec<(String, Box<RawValue>)>,
}

#[derive(Deserialize)]
struct ModelsWire {
    models: Vec<ModelMetadata>,
}

#[derive(Deserialize)]
struct TypePeek {
    #[serde(default, rename = "type")]
    kind: Option<TypeValue>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TypeValue {
    Text(String),
    Other(IgnoredAny),
}

#[derive(Deserialize)]
struct ScoreWire {
    score: f64,
    confidence: f64,
    #[serde(deserialize_with = "string_map")]
    legend: Vec<(String, Value)>,
    #[serde(deserialize_with = "string_map")]
    probabilities: Vec<(String, f64)>,
}

enum AnswerParse {
    Known(Answer),
    Unknown { type_name: String },
    Invalid { relative_path: String },
}

fn interpret_answer(text: &str) -> AnswerParse {
    let kind = match serde_json::from_str::<TypePeek>(text) {
        Ok(TypePeek {
            kind: Some(TypeValue::Text(kind)),
        }) if !kind.is_empty() => kind,
        _ => {
            return AnswerParse::Invalid {
                relative_path: "type".to_owned(),
            }
        }
    };
    match kind.as_str() {
        "noul" => parse_known(text, Answer::Noul),
        "choice" => parse_known(text, Answer::Choice),
        "score" => parse_score(text),
        _ => AnswerParse::Unknown { type_name: kind },
    }
}

fn parse_known<T>(text: &str, wrap: fn(T) -> Answer) -> AnswerParse
where
    T: de::DeserializeOwned,
{
    match serde_json::from_str::<T>(text) {
        Ok(value) => AnswerParse::Known(wrap(value)),
        Err(_) => AnswerParse::Invalid {
            relative_path: answer_field_path::<T>(text),
        },
    }
}

fn parse_score(text: &str) -> AnswerParse {
    match serde_json::from_str::<ScoreWire>(text) {
        Ok(wire) => match finish_score(wire) {
            Ok(answer) => AnswerParse::Known(Answer::Score(answer)),
            Err(relative_path) => AnswerParse::Invalid { relative_path },
        },
        Err(_) => AnswerParse::Invalid {
            relative_path: answer_field_path::<ScoreWire>(text),
        },
    }
}

fn finish_score(wire: ScoreWire) -> Result<ScoreAnswer, String> {
    let mut legend = Vec::with_capacity(wire.legend.len());
    for (key, value) in wire.legend {
        legend.push((int_key("legend", &key)?, value));
    }
    let mut probabilities = Vec::with_capacity(wire.probabilities.len());
    for (key, value) in wire.probabilities {
        probabilities.push((int_key("probabilities", &key)?, value));
    }
    Ok(ScoreAnswer {
        score: wire.score,
        confidence: wire.confidence,
        legend,
        probabilities,
    })
}

fn int_key(field: &str, key: &str) -> Result<i64, String> {
    key.parse::<i64>().map_err(|_| format!("{field}.{key}"))
}

fn answer_field_path<T: de::DeserializeOwned>(text: &str) -> String {
    let path = json_field_path::<T>(text.as_bytes());
    if path.is_empty() || path == "." {
        "type".to_owned()
    } else {
        path
    }
}

fn raw_answers<'de, D>(deserializer: D) -> Result<Vec<(String, Box<RawValue>)>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RawVisitor;

    impl<'de> Visitor<'de> for RawVisitor {
        type Value = Vec<(String, Box<RawValue>)>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map of answers")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut answers = Vec::with_capacity(map.size_hint().unwrap_or(0));
            while let Some(name) = map.next_key::<String>()? {
                answers.push((name, map.next_value::<Box<RawValue>>()?));
            }
            Ok(answers)
        }
    }

    deserializer.deserialize_map(RawVisitor)
}

fn string_map<'de, D, T>(deserializer: D) -> Result<Vec<(String, T)>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct MapVisitor<T> {
        marker: PhantomData<T>,
    }

    impl<'de, T> Visitor<'de> for MapVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<(String, T)>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JSON object")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0));
            while let Some(key) = map.next_key::<String>()? {
                entries.push((key, map.next_value()?));
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_map(MapVisitor {
        marker: PhantomData,
    })
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::{parse_models, parse_system_one, Answer};
    use crate::error::ApiErrorKind;
    use bytes::Bytes;
    use serde_json::json;

    const ENDPOINT: &str = "POST https://api.typesafe.ai/v1/systemone";

    fn system(body: &str) -> super::SystemOneResponse {
        parse_system_one(
            200,
            Bytes::from(body.to_owned()),
            Some("req-1".to_owned()),
            ENDPOINT,
        )
        .unwrap_or_else(|error| panic!("parse failed: {error}"))
    }

    fn system_err(body: &str) -> crate::Error {
        parse_system_one(
            200,
            Bytes::from(body.to_owned()),
            Some("req-123".to_owned()),
            ENDPOINT,
        )
        .expect_err("invalid body")
    }

    #[test]
    fn parses_answers_without_copying_away_the_raw_body() {
        let body = r#"{"model":"jev-latest","usage":{"input_tokens":12,"output_tokens":3,"reasoning_tokens":9},"answers":{"spam":{"type":"noul","noul":0.98,"explanation":"spammy"},"tone":{"type":"choice","choice":"friendly","confidence":0.9,"probabilities":{"friendly":0.9,"hostile":0.1}},"quality":{"type":"score","score":1.7,"confidence":0.8,"legend":{"0":"bad","1":{"note":null},"2":"great"},"probabilities":{"0":0.1,"1":0.1,"2":0.8}}}}"#;
        let response = system(body);
        assert_eq!(response.model, "jev-latest");
        assert_eq!(response.usage.input_tokens, Some(12));
        assert_eq!(response.usage.output_tokens, Some(3));
        assert_eq!(response.request_id(), Some("req-1"));
        assert_eq!(response.raw_body(), body.as_bytes());
        let noul = response.nouls().next().expect("noul");
        assert_eq!(noul.0, "spam");
        assert_eq!(noul.1.noul, 0.98);
        let choice = response.choices().next().expect("choice");
        assert_eq!(choice.1.choice, "friendly");
        assert_eq!(
            choice.1.probabilities,
            vec![("friendly".to_owned(), 0.9), ("hostile".to_owned(), 0.1)]
        );
        let score = response.scores().next().expect("score");
        assert_eq!(score.1.score, 1.7);
        assert_eq!(score.1.legend_value(0), Some(&json!("bad")));
        assert_eq!(score.1.legend_value(1), Some(&json!({"note": null})));
        assert_eq!(score.1.probability(2), Some(0.8));
        assert!(std::str::from_utf8(response.raw_body())
            .expect("utf8")
            .contains("reasoning_tokens"));
    }

    #[test]
    fn drops_unknown_answer_types() {
        let body = r#"{"model":"test","usage":{"input_tokens":1,"output_tokens":1},"answers":{"spam":{"type":"noul","noul":0.9},"mystery":{"type":"aurora","value":3}}}"#;
        let response = system(body);
        assert_eq!(response.answers().count(), 1);
        assert!(matches!(response.get("spam"), Some(Answer::Noul(_))));
        assert!(response.get("mystery").is_none());
        assert!(response
            .raw_body()
            .windows(6)
            .any(|window| window == b"aurora"));
    }

    #[test]
    fn field_paths_match_python() {
        let cases = [
            (
                r#"{"usage":{"input_tokens":1,"output_tokens":1},"answers":{}}"#,
                "model",
            ),
            (
                r#"{"model":"test","usage":{"input_tokens":1,"output_tokens":1},"answers":{"n":{"type":"noul"}}}"#,
                "answers.n.noul",
            ),
            (
                r#"{"model":"test","usage":{"input_tokens":1,"output_tokens":1},"answers":{"n":{"type":"noul","noul":"0.5"}}}"#,
                "answers.n.noul",
            ),
            (
                r#"{"model":"test","usage":{"input_tokens":1,"output_tokens":1},"answers":{"c":{"type":"choice","choice":"a","probabilities":{}}}}"#,
                "answers.c.confidence",
            ),
            (
                r#"{"model":"test","usage":{"input_tokens":1,"output_tokens":1},"answers":{"c":{"type":"choice","confidence":0.5,"probabilities":{}}}}"#,
                "answers.c.choice",
            ),
            (
                r#"{"model":"test","usage":{"input_tokens":1,"output_tokens":1},"answers":{"s":{"type":"score","score":1.0,"confidence":1.0,"legend":[],"probabilities":{}}}}"#,
                "answers.s.legend",
            ),
            (
                r#"{"model":"test","usage":{"input_tokens":1,"output_tokens":1},"answers":{"s":{"type":"score","score":1.0,"confidence":1.0,"legend":{"x":"bad"},"probabilities":{}}}}"#,
                "answers.s.legend.x",
            ),
            (
                r#"{"model":"test","usage":{"input_tokens":1,"output_tokens":1},"answers":{"c":"not-a-mapping"}}"#,
                "answers.c.type",
            ),
        ];
        for (body, path) in cases {
            let error = system_err(body);
            let api = error.api().expect("api error");
            assert_eq!(api.kind, ApiErrorKind::InvalidResponse);
            assert_eq!(api.field_path.as_deref(), Some(path), "{body}");
            assert_eq!(api.request_id.as_deref(), Some("req-123"));
            assert!(api
                .to_string()
                .contains(&format!("Invalid response data at '{path}'.")));
        }
    }

    #[test]
    fn model_list_field_path_uses_indexes() {
        let body = br#"{"models":[{"name":"test","description":"Test model","release_date":"2026-09-14"},{"name":"x","description":"d"}]}"#;
        let error = parse_models(
            200,
            Bytes::from_static(body),
            None,
            "GET https://api.typesafe.ai/v1/models",
        )
        .expect_err("missing release date");
        assert_eq!(
            error.api().and_then(|api| api.field_path.as_deref()),
            Some("models[1].release_date")
        );
    }

    #[test]
    fn model_list_ignores_unknown_fields() {
        let body = br#"{"models":[{"name":"jev-latest","description":"General-purpose.","release_date":"2026-09-15","context_window":128000}]}"#;
        let response = parse_models(
            200,
            Bytes::from_static(body),
            Some("m".to_owned()),
            "GET /v1/models",
        )
        .expect("models");
        assert_eq!(response.models[0].name, "jev-latest");
        assert!(std::str::from_utf8(response.raw_body())
            .expect("utf8")
            .contains("context_window"));
    }
}
