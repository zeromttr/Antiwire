//! Question values and the system-one request body.
//!
//! Questions stay in insertion order. The body serializer writes borrowed
//! state and questions directly; `extra_body` is merged last without parsing
//! that body back into a `Value`.

use std::borrow::Cow;

use serde_json::{Map, Value};

use crate::error::Error;

/// Text, a JSON object, or a JSON array.
///
/// Top-level numbers, booleans, and null are rejected. Nested JSON values may
/// still contain them.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonContent<'a> {
    /// A JSON string.
    Text(Cow<'a, str>),
    /// A JSON object or array.
    Value(Cow<'a, Value>),
}

impl<'a> JsonContent<'a> {
    /// Borrow or own a text value.
    #[must_use]
    pub fn text(text: impl Into<Cow<'a, str>>) -> Self {
        Self::Text(text.into())
    }
}

impl JsonContent<'static> {
    /// Own a JSON object or array.
    #[must_use]
    pub fn json(value: Value) -> Self {
        Self::Value(Cow::Owned(value))
    }
}

impl<'a> From<&'a str> for JsonContent<'a> {
    fn from(text: &'a str) -> Self {
        Self::text(text)
    }
}

impl From<String> for JsonContent<'static> {
    fn from(text: String) -> Self {
        Self::text(text)
    }
}

/// Descriptions of the yes and no outcomes for a [`Noul`] question.
///
/// Absent outcomes are left off the wire. [`NoulCriteria::yes_null`] writes JSON null.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NoulCriteria<'a> {
    yes: Slot<'a>,
    no: Slot<'a>,
}

impl<'a> NoulCriteria<'a> {
    /// No outcomes described.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            yes: Slot::Omitted,
            no: Slot::Omitted,
        }
    }

    /// Describe the yes outcome.
    #[must_use]
    pub fn yes(mut self, content: JsonContent<'a>) -> Self {
        self.yes = Slot::Value(content);
        self
    }

    /// Describe the yes outcome with text.
    #[must_use]
    pub fn yes_text(self, text: impl Into<Cow<'a, str>>) -> Self {
        self.yes(JsonContent::text(text))
    }

    /// Write `"true": null`.
    #[must_use]
    pub fn yes_null(mut self) -> Self {
        self.yes = Slot::Null;
        self
    }

    /// Describe the no outcome.
    #[must_use]
    pub fn no(mut self, content: JsonContent<'a>) -> Self {
        self.no = Slot::Value(content);
        self
    }

    /// Describe the no outcome with text.
    #[must_use]
    pub fn no_text(self, text: impl Into<Cow<'a, str>>) -> Self {
        self.no(JsonContent::text(text))
    }
}

/// A yes/no question (`type` = `noul`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Noul<'a> {
    instructions: Option<JsonContent<'a>>,
    criteria: Option<NoulCriteria<'a>>,
}

impl<'a> Noul<'a> {
    /// A noul question with no instructions or criteria.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instructions: None,
            criteria: None,
        }
    }

    /// Set the question text or JSON. `None` is not representable; omit the call instead.
    #[must_use]
    pub fn instructions(mut self, instructions: JsonContent<'a>) -> Self {
        self.instructions = Some(instructions);
        self
    }

    /// Set outcome descriptions. An empty [`NoulCriteria`] is written as `{}`.
    #[must_use]
    pub fn criteria(mut self, criteria: NoulCriteria<'a>) -> Self {
        self.criteria = Some(criteria);
        self
    }
}

/// A question that selects between named alternatives.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Choice<'a> {
    instructions: Option<JsonContent<'a>>,
    criteria: Vec<(Cow<'a, str>, Option<JsonContent<'a>>)>,
}

impl<'a> Choice<'a> {
    /// A choice question with no options yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instructions: None,
            criteria: Vec::new(),
        }
    }

    /// Set the question text or JSON.
    #[must_use]
    pub fn instructions(mut self, instructions: JsonContent<'a>) -> Self {
        self.instructions = Some(instructions);
        self
    }

    /// Add a label. `None` is written as JSON null.
    #[must_use]
    pub fn option(
        mut self,
        label: impl Into<Cow<'a, str>>,
        description: Option<JsonContent<'a>>,
    ) -> Self {
        self.criteria.push((label.into(), description));
        self
    }

    /// Add a label whose description is null.
    #[must_use]
    pub fn option_null(self, label: impl Into<Cow<'a, str>>) -> Self {
        self.option(label, None)
    }
}

/// A question that assigns a score from an ordered rubric.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Score<'a> {
    instructions: Option<JsonContent<'a>>,
    criteria: Vec<JsonContent<'a>>,
}

impl<'a> Score<'a> {
    /// A score question. At least one criterion is required before send.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instructions: None,
            criteria: Vec::new(),
        }
    }

    /// Set the question text or JSON.
    #[must_use]
    pub fn instructions(mut self, instructions: JsonContent<'a>) -> Self {
        self.instructions = Some(instructions);
        self
    }

    /// Append one rubric level. The first level is score zero.
    #[must_use]
    pub fn criterion(mut self, content: JsonContent<'a>) -> Self {
        self.criteria.push(content);
        self
    }

    /// Append a text rubric level.
    #[must_use]
    pub fn criterion_text(self, text: impl Into<Cow<'a, str>>) -> Self {
        self.criterion(JsonContent::text(text))
    }
}

/// One question, either a typed value or a raw object passed through to the API.
#[derive(Debug, Clone, PartialEq)]
pub enum Question<'a> {
    /// Yes/no question.
    Noul(Noul<'a>),
    /// Labeled alternatives.
    Choice(Choice<'a>),
    /// Ordered rubric.
    Score(Score<'a>),
    /// Object with a nonempty string `type`. Unknown fields are preserved.
    Raw(Cow<'a, Map<String, Value>>),
}

impl Question<'_> {
    /// Pass a JSON object through. Its `type` is checked before the request is sent.
    #[must_use]
    pub fn raw(map: Map<String, Value>) -> Question<'static> {
        Question::Raw(Cow::Owned(map))
    }
}

impl<'a> From<Noul<'a>> for Question<'a> {
    fn from(question: Noul<'a>) -> Self {
        Self::Noul(question)
    }
}

impl<'a> From<Choice<'a>> for Question<'a> {
    fn from(question: Choice<'a>) -> Self {
        Self::Choice(question)
    }
}

impl<'a> From<Score<'a>> for Question<'a> {
    fn from(question: Score<'a>) -> Self {
        Self::Score(question)
    }
}

/// Named questions in insertion order.
///
/// A repeated name replaces the previous question and keeps its position.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Questions<'a> {
    entries: Vec<(Cow<'a, str>, Question<'a>)>,
}

impl<'a> Questions<'a> {
    /// No questions. Sending this fails validation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of questions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether [`Self::ask`] has not been called.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert or replace `name`.
    #[must_use]
    pub fn ask(mut self, name: impl Into<Cow<'a, str>>, question: impl Into<Question<'a>>) -> Self {
        let name = name.into();
        let question = question.into();
        if let Some((_, existing)) = self
            .entries
            .iter_mut()
            .find(|(candidate, _)| candidate == &name)
        {
            *existing = question;
        } else {
            self.entries.push((name, question));
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
enum Slot<'a> {
    #[default]
    Omitted,
    Null,
    Value(JsonContent<'a>),
}

pub(crate) fn encode_system_one(
    state: &JsonContent<'_>,
    model: &str,
    questions: &Questions<'_>,
    extra: Option<&Map<String, Value>>,
) -> Result<Vec<u8>, Error> {
    validate_questions(questions)?;
    let mut buf = Vec::with_capacity(256);
    write_object(&mut buf, |writer| {
        writer.entry("state", |buf| match extra_value(extra, "state") {
            Some(value) => write_json(buf, value),
            None => write_content(buf, state),
        })?;
        writer.entry("model", |buf| match extra_value(extra, "model") {
            Some(value) => write_json(buf, value),
            None => write_str(buf, model),
        })?;
        writer.entry("questions", |buf| match extra_value(extra, "questions") {
            Some(value) => write_json(buf, value),
            None => write_questions(buf, questions),
        })?;
        if let Some(extra) = extra {
            for (key, value) in extra {
                if matches!(key.as_str(), "state" | "model" | "questions") {
                    continue;
                }
                writer.entry(key, |buf| write_json(buf, value))?;
            }
        }
        Ok(())
    })?;
    Ok(buf)
}

fn validate_questions(questions: &Questions<'_>) -> Result<(), Error> {
    if questions.entries.is_empty() {
        return Err(Error::client("At least one question is required."));
    }
    for (name, question) in &questions.entries {
        match question {
            Question::Score(score) if score.criteria.is_empty() => {
                return Err(score_criteria_error(name));
            }
            Question::Raw(raw) => validate_raw(name, raw)?,
            Question::Noul(_) | Question::Choice(_) | Question::Score(_) => {}
        }
    }
    Ok(())
}

fn validate_raw(name: &str, raw: &Map<String, Value>) -> Result<(), Error> {
    let Some(kind) = raw.get("type").and_then(Value::as_str) else {
        return Err(raw_shape_error(name));
    };
    if kind.is_empty() {
        return Err(raw_shape_error(name));
    }
    if matches!(kind, "choice" | "score") && !raw.contains_key("criteria") {
        return Err(Error::client(format!(
            "Question \"{name}\" requires \"criteria\"."
        )));
    }
    if kind == "score" {
        let criteria = raw
            .get("criteria")
            .ok_or_else(|| Error::client(format!("Question \"{name}\" requires \"criteria\".")))?;
        if is_falsy_json(criteria) {
            return Err(score_criteria_error(name));
        }
    }
    Ok(())
}

fn is_falsy_json(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Number(number) => number.as_f64().is_some_and(|value| value == 0.0),
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
    }
}

fn score_criteria_error(name: &str) -> Error {
    Error::client(format!(
        "Score question \"{name}\" has no criteria; at least one score is required."
    ))
}

fn raw_shape_error(name: &str) -> Error {
    Error::client(format!(
        "Question \"{name}\" must be a question object or a dictionary with a nonempty string \"type\"."
    ))
}

fn extra_value<'a>(extra: Option<&'a Map<String, Value>>, key: &str) -> Option<&'a Value> {
    extra.and_then(|map| map.get(key))
}

fn encode_error() -> Error {
    Error::client("The request body could not be encoded as JSON")
}

struct ObjectWriter<'a> {
    buf: &'a mut Vec<u8>,
    first: bool,
}

impl ObjectWriter<'_> {
    fn entry(
        &mut self,
        key: &str,
        write: impl FnOnce(&mut Vec<u8>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.first {
            self.buf.push(b',');
        }
        self.first = false;
        write_str(self.buf, key)?;
        self.buf.push(b':');
        write(self.buf)
    }
}

fn write_object(
    buf: &mut Vec<u8>,
    write: impl FnOnce(&mut ObjectWriter<'_>) -> Result<(), Error>,
) -> Result<(), Error> {
    buf.push(b'{');
    let mut writer = ObjectWriter { buf, first: true };
    write(&mut writer)?;
    writer.buf.push(b'}');
    Ok(())
}

fn write_questions(buf: &mut Vec<u8>, questions: &Questions<'_>) -> Result<(), Error> {
    write_object(buf, |writer| {
        for (name, question) in &questions.entries {
            writer.entry(name.as_ref(), |buf| write_question(buf, question))?;
        }
        Ok(())
    })
}

fn write_question(buf: &mut Vec<u8>, question: &Question<'_>) -> Result<(), Error> {
    match question {
        Question::Noul(question) => write_object(buf, |writer| write_noul(writer, question)),
        Question::Choice(question) => write_object(buf, |writer| write_choice(writer, question)),
        Question::Score(question) => write_object(buf, |writer| write_score(writer, question)),
        Question::Raw(raw) => write_json(buf, raw.as_ref()),
    }
}

fn write_noul(writer: &mut ObjectWriter<'_>, question: &Noul<'_>) -> Result<(), Error> {
    writer.entry("type", |buf| write_str(buf, "noul"))?;
    if let Some(instructions) = &question.instructions {
        writer.entry("instructions", |buf| write_content(buf, instructions))?;
    }
    if let Some(criteria) = &question.criteria {
        writer.entry("criteria", |buf| write_noul_criteria(buf, criteria))?;
    }
    Ok(())
}

fn write_choice(writer: &mut ObjectWriter<'_>, question: &Choice<'_>) -> Result<(), Error> {
    writer.entry("type", |buf| write_str(buf, "choice"))?;
    if let Some(instructions) = &question.instructions {
        writer.entry("instructions", |buf| write_content(buf, instructions))?;
    }
    writer.entry("criteria", |buf| {
        write_choice_criteria(buf, &question.criteria)
    })
}

fn write_score(writer: &mut ObjectWriter<'_>, question: &Score<'_>) -> Result<(), Error> {
    writer.entry("type", |buf| write_str(buf, "score"))?;
    if let Some(instructions) = &question.instructions {
        writer.entry("instructions", |buf| write_content(buf, instructions))?;
    }
    writer.entry("criteria", |buf| {
        write_score_criteria(buf, &question.criteria)
    })
}

fn write_noul_criteria(buf: &mut Vec<u8>, criteria: &NoulCriteria<'_>) -> Result<(), Error> {
    write_object(buf, |writer| {
        write_slot(writer, "true", &criteria.yes)?;
        write_slot(writer, "false", &criteria.no)?;
        Ok(())
    })
}

fn write_slot(writer: &mut ObjectWriter<'_>, key: &str, slot: &Slot<'_>) -> Result<(), Error> {
    match slot {
        Slot::Omitted => Ok(()),
        Slot::Null => writer.entry(key, write_null),
        Slot::Value(content) => writer.entry(key, |buf| write_content(buf, content)),
    }
}

fn write_choice_criteria(
    buf: &mut Vec<u8>,
    criteria: &[(Cow<'_, str>, Option<JsonContent<'_>>)],
) -> Result<(), Error> {
    write_object(buf, |writer| {
        for (label, description) in criteria {
            match description {
                Some(content) => writer.entry(label, |buf| write_content(buf, content))?,
                None => writer.entry(label, write_null)?,
            }
        }
        Ok(())
    })
}

fn write_score_criteria(buf: &mut Vec<u8>, criteria: &[JsonContent<'_>]) -> Result<(), Error> {
    buf.push(b'[');
    for (index, criterion) in criteria.iter().enumerate() {
        if index > 0 {
            buf.push(b',');
        }
        write_content(buf, criterion)?;
    }
    buf.push(b']');
    Ok(())
}

fn write_content(buf: &mut Vec<u8>, content: &JsonContent<'_>) -> Result<(), Error> {
    match content {
        JsonContent::Text(text) => write_str(buf, text),
        JsonContent::Value(value) => match value.as_ref() {
            Value::String(_) | Value::Array(_) | Value::Object(_) => {
                write_json(buf, value.as_ref())
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => Err(encode_error()),
        },
    }
}

#[allow(clippy::unnecessary_wraps)]
fn write_null(buf: &mut Vec<u8>) -> Result<(), Error> {
    buf.extend_from_slice(b"null");
    Ok(())
}

fn write_str(buf: &mut Vec<u8>, value: &str) -> Result<(), Error> {
    serde_json::to_writer(buf, value).map_err(|_| encode_error())
}

fn write_json<T: serde::Serialize>(buf: &mut Vec<u8>, value: &T) -> Result<(), Error> {
    serde_json::to_writer(buf, value).map_err(|_| encode_error())
}

#[cfg(test)]
mod tests {
    use super::{encode_system_one, JsonContent, Noul, NoulCriteria, Question, Questions, Score};
    use crate::Choice;
    use serde_json::{json, Map, Value};

    fn encode(
        state: &JsonContent<'_>,
        model: &str,
        questions: &Questions<'_>,
        extra: Option<&Map<String, Value>>,
    ) -> Value {
        let bytes = encode_system_one(state, model, questions, extra).expect("encode");
        serde_json::from_slice(&bytes).expect("json")
    }

    fn noul(text: &str) -> Noul<'_> {
        Noul::new().instructions(JsonContent::text(text))
    }

    #[test]
    fn omits_default_fields_and_preserves_explicit_empty_values() {
        let questions = Questions::new()
            .ask("bare", Noul::new())
            .ask(
                "empty",
                Noul::new()
                    .instructions(JsonContent::text(""))
                    .criteria(NoulCriteria::new()),
            )
            .ask(
                "null-yes",
                Noul::new()
                    .instructions(JsonContent::json(json!([])))
                    .criteria(NoulCriteria::new().yes_null()),
            )
            .ask("choice", Choice::new().option_null("a"))
            .ask("score", Score::new().criterion_text("good"));
        assert_eq!(
            encode(&JsonContent::text("hi"), "jev-latest", &questions, None),
            json!({
                "state": "hi",
                "model": "jev-latest",
                "questions": {
                    "bare": {"type": "noul"},
                    "empty": {"type": "noul", "instructions": "", "criteria": {}},
                    "null-yes": {"type": "noul", "instructions": [], "criteria": {"true": null}},
                    "choice": {"type": "choice", "criteria": {"a": null}},
                    "score": {"type": "score", "criteria": ["good"]}
                }
            })
        );
    }

    #[test]
    fn preserves_question_order_and_nested_json() {
        let nested = json!({"summary": "duplicated", "examples": ["charged twice"]});
        let questions = Questions::new()
            .ask(
                "duplicate",
                Noul::new()
                    .instructions(JsonContent::json(json!({"question": "Duplicate?"})))
                    .criteria(NoulCriteria::new().yes(JsonContent::json(nested.clone()))),
            )
            .ask(
                "team",
                Choice::new()
                    .instructions(JsonContent::text("Team?"))
                    .option("billing", Some(JsonContent::json(nested)))
                    .option_null("other"),
            )
            .ask(
                "risk",
                Score::new()
                    .instructions(JsonContent::text("Risk?"))
                    .criterion(JsonContent::text("low")),
            );
        let bytes = encode_system_one(&JsonContent::text("a ticket"), "custom", &questions, None)
            .expect("encode");
        let text = String::from_utf8(bytes.clone()).expect("utf8");
        let questions_at = text.find("\"questions\"").expect("questions");
        let body = &text[questions_at..];
        assert!(body.find("\"duplicate\"").unwrap() < body.find("\"team\"").unwrap());
        assert!(body.find("\"team\"").unwrap() < body.find("\"risk\"").unwrap());
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["questions"]["duplicate"]["criteria"]
                ["true"],
            json!({"summary": "duplicated", "examples": ["charged twice"]})
        );
    }

    #[test]
    fn extra_body_overrides_without_reordering_core_keys() {
        let questions = Questions::new().ask(
            "q",
            Question::raw(Map::from_iter([
                ("type".to_owned(), Value::String("noul".to_owned())),
                ("instructions".to_owned(), Value::String("?".to_owned())),
            ])),
        );
        let mut extra = Map::new();
        extra.insert("model".to_owned(), json!("override-model"));
        extra.insert("beam_width".to_owned(), json!(4));
        extra.insert("nullable".to_owned(), Value::Null);
        let bytes = encode_system_one(
            &JsonContent::text("hi"),
            "call-model",
            &questions,
            Some(&extra),
        )
        .expect("encode");
        let text = String::from_utf8(bytes.clone()).expect("utf8");
        assert!(text.find("\"state\"").unwrap() < text.find("\"model\"").unwrap());
        assert!(text.find("\"model\"").unwrap() < text.find("\"questions\"").unwrap());
        assert!(text.find("\"questions\"").unwrap() < text.find("\"beam_width\"").unwrap());
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({
                "state": "hi",
                "model": "override-model",
                "questions": {"q": {"type": "noul", "instructions": "?"}},
                "beam_width": 4,
                "nullable": null
            })
        );
    }

    #[test]
    fn raw_questions_keep_unknown_fields() {
        let mut raw = Map::new();
        raw.insert("type".to_owned(), json!("future"));
        raw.insert("nested".to_owned(), json!({"k": null}));
        let questions = Questions::new().ask("q", Question::raw(raw));
        assert_eq!(
            encode(&JsonContent::text("hi"), "jev-latest", &questions, None)["questions"]["q"],
            json!({"type": "future", "nested": {"k": null}})
        );
    }

    #[test]
    fn rejects_invalid_questions_before_encoding() {
        let empty = Questions::new();
        let error = encode_system_one(&JsonContent::text("x"), "m", &empty, None).unwrap_err();
        assert!(error.to_string().contains("At least one question"));

        let score =
            Questions::new().ask("rating", Score::new().instructions(JsonContent::text("?")));
        let error = encode_system_one(&JsonContent::text("x"), "m", &score, None).unwrap_err();
        assert!(error.to_string().contains("\"rating\" has no criteria"));

        let mut raw = Map::new();
        raw.insert("instructions".to_owned(), json!("Missing type"));
        let questions = Questions::new().ask("invalid", Question::raw(raw));
        let error = encode_system_one(&JsonContent::text("x"), "m", &questions, None).unwrap_err();
        assert!(error.to_string().contains("nonempty string"));

        let choice = Question::raw(Map::from_iter([(
            "type".to_owned(),
            Value::String("choice".to_owned()),
        )]));
        let questions = Questions::new().ask("invalid", choice);
        let error = encode_system_one(&JsonContent::text("x"), "m", &questions, None).unwrap_err();
        assert!(error.to_string().contains("requires \"criteria\""));

        let mut score_raw = Map::new();
        score_raw.insert("type".to_owned(), json!("score"));
        score_raw.insert("criteria".to_owned(), json!([]));
        let questions = Questions::new().ask("rating", Question::raw(score_raw));
        let error = encode_system_one(&JsonContent::text("x"), "m", &questions, None).unwrap_err();
        assert!(error.to_string().contains("\"rating\" has no criteria"));
    }

    #[test]
    fn replacing_a_name_keeps_its_position() {
        let questions = Questions::new()
            .ask("a", Noul::new())
            .ask("b", noul("first"))
            .ask("b", noul("second"));
        let value = encode(&JsonContent::text("x"), "m", &questions, None);
        assert_eq!(value["questions"]["b"]["instructions"], "second");
        assert_eq!(questions.len(), 2);
    }

    #[test]
    fn rejects_top_level_numbers() {
        let questions = Questions::new().ask("q", Noul::new());
        let error =
            encode_system_one(&JsonContent::json(json!(1)), "m", &questions, None).unwrap_err();
        assert!(error.to_string().contains("could not be encoded as JSON"));
    }
}
