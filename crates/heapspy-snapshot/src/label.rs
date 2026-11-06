//! Edge label encoding, rendering, and the dict-key redaction placeholder.

use std::fmt::Write as _;

use crate::error::Result;
use crate::format::{EF_KEY_REDACTED, NO_STRING};
use crate::types::{EdgeLabel, KeyLabel, StrId};

pub const KIND_OTHER: u8 = 0;
pub const KIND_DICT_VALUE: u8 = 1;
pub const KIND_DICT_KEY: u8 = 2;
pub const KIND_LIST_ITEM: u8 = 3;
pub const KIND_TUPLE_ITEM: u8 = 4;
pub const KIND_SET_ITEM: u8 = 5;
pub const KIND_ATTR: u8 = 6;
pub const KIND_TYPE: u8 = 7;
pub const KIND_CELL_CONTENTS: u8 = 8;
pub const KIND_CLOSURE_CELL: u8 = 9;
pub const KIND_FRAME_LOCAL: u8 = 10;

fn encode_key(k: KeyLabel) -> (u8, u32) {
    match k {
        KeyLabel::Unknown => (0, NO_STRING),
        KeyLabel::Repr(s) => (0, s.0),
        KeyLabel::Redacted(s) => (EF_KEY_REDACTED, s.0),
    }
}

fn decode_key(flags: u8, operand: u32) -> KeyLabel {
    if operand == NO_STRING {
        KeyLabel::Unknown
    } else if flags & EF_KEY_REDACTED != 0 {
        KeyLabel::Redacted(StrId(operand))
    } else {
        KeyLabel::Repr(StrId(operand))
    }
}

impl EdgeLabel {
    /// Encode to the on-disk `(kind, flags, operand)` triple.
    pub fn encode(self) -> (u8, u8, u32) {
        match self {
            EdgeLabel::Other(d) => (KIND_OTHER, 0, StrId::encode(d)),
            EdgeLabel::DictValue(k) => {
                let (f, o) = encode_key(k);
                (KIND_DICT_VALUE, f, o)
            }
            EdgeLabel::DictKey(k) => {
                let (f, o) = encode_key(k);
                (KIND_DICT_KEY, f, o)
            }
            EdgeLabel::ListItem(i) => (KIND_LIST_ITEM, 0, i),
            EdgeLabel::TupleItem(i) => (KIND_TUPLE_ITEM, 0, i),
            EdgeLabel::SetItem => (KIND_SET_ITEM, 0, 0),
            EdgeLabel::Attr(s) => (KIND_ATTR, 0, s.0),
            EdgeLabel::Type => (KIND_TYPE, 0, 0),
            EdgeLabel::CellContents => (KIND_CELL_CONTENTS, 0, 0),
            EdgeLabel::ClosureCell(i) => (KIND_CLOSURE_CELL, 0, i),
            EdgeLabel::FrameLocal(s) => (KIND_FRAME_LOCAL, 0, s.0),
            EdgeLabel::Unknown {
                kind,
                flags,
                operand,
            } => (kind, flags, operand),
        }
    }

    /// Decode from the on-disk triple. Never fails; unknown kinds become
    /// [`EdgeLabel::Unknown`].
    pub fn decode(kind: u8, flags: u8, operand: u32) -> EdgeLabel {
        match kind {
            KIND_OTHER => EdgeLabel::Other(StrId::decode(operand)),
            KIND_DICT_VALUE => EdgeLabel::DictValue(decode_key(flags, operand)),
            KIND_DICT_KEY => EdgeLabel::DictKey(decode_key(flags, operand)),
            KIND_LIST_ITEM => EdgeLabel::ListItem(operand),
            KIND_TUPLE_ITEM => EdgeLabel::TupleItem(operand),
            KIND_SET_ITEM => EdgeLabel::SetItem,
            KIND_ATTR => EdgeLabel::Attr(StrId(operand)),
            KIND_TYPE => EdgeLabel::Type,
            KIND_CELL_CONTENTS => EdgeLabel::CellContents,
            KIND_CLOSURE_CELL => EdgeLabel::ClosureCell(operand),
            KIND_FRAME_LOCAL => EdgeLabel::FrameLocal(StrId(operand)),
            _ => EdgeLabel::Unknown {
                kind,
                flags,
                operand,
            },
        }
    }

    /// String ids this label refers to, if any. Used for validation.
    pub fn string_ref(self) -> Option<StrId> {
        match self {
            EdgeLabel::Other(d) => d,
            EdgeLabel::DictValue(k) | EdgeLabel::DictKey(k) => match k {
                KeyLabel::Unknown => None,
                KeyLabel::Repr(s) | KeyLabel::Redacted(s) => Some(s),
            },
            EdgeLabel::Attr(s) | EdgeLabel::FrameLocal(s) => Some(s),
            _ => None,
        }
    }

    /// Render the label the way a retaining path hop shows it.
    ///
    /// | label | rendered |
    /// |---|---|
    /// | `DictValue(Repr("'cache'"))` | `['cache']` |
    /// | `DictValue(Redacted("<str len=9>"))` | `[<str len=9>]` |
    /// | `DictValue(Unknown)` | `[?]` |
    /// | `DictKey(k)` | `<key ['cache']>` |
    /// | `ListItem(3)`, `TupleItem(3)` | `[3]` |
    /// | `SetItem` | `<set item>` |
    /// | `Attr("payload")` | `.payload` |
    /// | `Type` | `.__class__` |
    /// | `CellContents` | `.cell_contents` |
    /// | `ClosureCell(0)` | `.__closure__[0]` |
    /// | `FrameLocal("pending")` | `local 'pending'` |
    /// | `Other(Some("weakref callback"))` | `<weakref callback>` |
    /// | `Other(None)` | `<?>` |
    /// | `Unknown { kind: 42, .. }` | `<edge kind=42>` |
    ///
    /// `lookup` resolves string ids, normally [`crate::Snapshot::string`].
    pub fn render<'a, F>(self, mut lookup: F) -> Result<String>
    where
        F: FnMut(StrId) -> Result<&'a str>,
    {
        fn key<'a, F: FnMut(StrId) -> Result<&'a str>>(
            k: KeyLabel,
            lookup: &mut F,
        ) -> Result<String> {
            Ok(match k {
                KeyLabel::Unknown => "[?]".to_string(),
                KeyLabel::Repr(s) | KeyLabel::Redacted(s) => format!("[{}]", lookup(s)?),
            })
        }
        Ok(match self {
            EdgeLabel::DictValue(k) => key(k, &mut lookup)?,
            EdgeLabel::DictKey(k) => format!("<key {}>", key(k, &mut lookup)?),
            EdgeLabel::ListItem(i) | EdgeLabel::TupleItem(i) => format!("[{i}]"),
            EdgeLabel::SetItem => "<set item>".to_string(),
            EdgeLabel::Attr(s) => format!(".{}", lookup(s)?),
            EdgeLabel::Type => ".__class__".to_string(),
            EdgeLabel::CellContents => ".cell_contents".to_string(),
            EdgeLabel::ClosureCell(i) => format!(".__closure__[{i}]"),
            EdgeLabel::FrameLocal(s) => format!("local '{}'", lookup(s)?),
            EdgeLabel::Other(Some(s)) => format!("<{}>", lookup(s)?),
            EdgeLabel::Other(None) => "<?>".to_string(),
            EdgeLabel::Unknown { kind, .. } => format!("<edge kind={kind}>"),
        })
    }
}

/// The placeholder stored instead of a dict key's text when the key is
/// redacted: `<str len=9>`, `<bytes len=16>`, `<int>`, `<tuple len=2>`.
///
/// `type_name` is the key type's `__qualname__` for builtins and
/// `module.qualname` otherwise. `len` is `len(key)` where the type has one.
pub fn redacted_key_placeholder(type_name: &str, len: Option<u64>) -> String {
    let mut s = String::with_capacity(type_name.len() + 12);
    s.push('<');
    s.push_str(type_name);
    if let Some(n) = len {
        let _ = write!(s, " len={n}");
    }
    s.push('>');
    s
}

/// Cut `text` to at most `max_chars` characters, appending `...` if it was
/// cut. Returns the text and whether it was cut. This is the truncation rule
/// for captured contents and for dict key reprs when contents are captured.
pub fn truncate_capture(text: &str, max_chars: usize) -> (String, bool) {
    match text.char_indices().nth(max_chars) {
        None => (text.to_string(), false),
        Some((byte_pos, _)) => {
            let mut s = text[..byte_pos].to_string();
            s.push_str("...");
            (s, true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let labels = [
            EdgeLabel::Other(None),
            EdgeLabel::Other(Some(StrId(4))),
            EdgeLabel::DictValue(KeyLabel::Unknown),
            EdgeLabel::DictValue(KeyLabel::Repr(StrId(1))),
            EdgeLabel::DictValue(KeyLabel::Redacted(StrId(2))),
            EdgeLabel::DictKey(KeyLabel::Repr(StrId(1))),
            EdgeLabel::ListItem(7),
            EdgeLabel::TupleItem(0),
            EdgeLabel::SetItem,
            EdgeLabel::Attr(StrId(9)),
            EdgeLabel::Type,
            EdgeLabel::CellContents,
            EdgeLabel::ClosureCell(2),
            EdgeLabel::FrameLocal(StrId(3)),
            EdgeLabel::Unknown {
                kind: 200,
                flags: 1,
                operand: 5,
            },
        ];
        for l in labels {
            let (k, f, o) = l.encode();
            assert_eq!(EdgeLabel::decode(k, f, o), l);
        }
    }

    #[test]
    fn render_labels() {
        let strings = ["'cache'", "<str len=9>", "payload", "pending"];
        let look = |s: StrId| Ok(strings[s.0 as usize]);
        let r = |l: EdgeLabel| l.render(look).unwrap();
        assert_eq!(
            r(EdgeLabel::DictValue(KeyLabel::Repr(StrId(0)))),
            "['cache']"
        );
        assert_eq!(
            r(EdgeLabel::DictValue(KeyLabel::Redacted(StrId(1)))),
            "[<str len=9>]"
        );
        assert_eq!(
            r(EdgeLabel::DictKey(KeyLabel::Repr(StrId(0)))),
            "<key ['cache']>"
        );
        assert_eq!(r(EdgeLabel::ListItem(3)), "[3]");
        assert_eq!(r(EdgeLabel::Attr(StrId(2))), ".payload");
        assert_eq!(r(EdgeLabel::FrameLocal(StrId(3))), "local 'pending'");
        assert_eq!(r(EdgeLabel::ClosureCell(1)), ".__closure__[1]");
    }

    #[test]
    fn placeholder_and_truncate() {
        assert_eq!(redacted_key_placeholder("str", Some(9)), "<str len=9>");
        assert_eq!(redacted_key_placeholder("int", None), "<int>");
        assert_eq!(truncate_capture("abcdef", 3), ("abc...".to_string(), true));
        assert_eq!(truncate_capture("abc", 3), ("abc".to_string(), false));
        assert_eq!(
            truncate_capture("\u{e9}\u{e9}\u{e9}\u{e9}", 2).0,
            "\u{e9}\u{e9}..."
        );
    }
}
