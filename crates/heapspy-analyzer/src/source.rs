//! Source locations of objects and types (`source_loc`, `type_location`),
//! from the extras the walker records.
//!
//! - A code object has its own `source_loc` extra (`co_filename:co_firstlineno`).
//! - A function is located through its `.__code__` edge (falling back to its
//!   own `source_loc` extra, which the walker copies from the code object).
//! - A bound method, `classmethod` or `staticmethod` goes through `.__func__`.
//! - A class has no code object at runtime. It is located through the
//!   functions in its `__dict__` (directly, or inside a `classmethod`,
//!   `staticmethod` or `property`) whose code object's `co_qualname` is
//!   `<class qualname>.<name>`: the file when they all agree, and the
//!   smallest first line (the class statement is at or before it).
//!   Functions with a generated filename (`<string>`, as for dataclass
//!   `__init__`) are ignored.
//! - A module is located through `__dict__['__file__']`, a str whose text is
//!   only stored with contents capture.
//!
//! Results are memoised per object and per type, and only computed for
//! objects and types that appear in a report.

use std::cell::RefCell;
use std::collections::HashMap;

use heapspy_snapshot::{EdgeLabel, KeyLabel, ObjectFlags, ObjectIndex, Snapshot, TypeId};

use crate::report::SourceLocation;
use crate::Result;

/// Codes for `source_loc_reason` and `type_location_reason`.
pub mod reason {
    /// A function or method whose code object is not in the snapshot or has
    /// no recorded location.
    pub const NO_CODE_OBJECT: &str = "no_code_object";
    /// A class whose `__dict__` holds no Python function defined in the
    /// class body (C types, classes with only attributes or only generated
    /// methods).
    pub const NO_PYTHON_METHODS: &str = "no_python_methods";
    /// A class whose methods were compiled from more than one file.
    pub const METHODS_DISAGREE: &str = "methods_disagree";
    /// A module, in a snapshot taken without `--capture-contents`: the text
    /// of `__file__` is not stored.
    pub const CONTENTS_NOT_CAPTURED: &str = "contents_not_captured";
    /// A module whose `__dict__` has no `__file__` str (built-in modules,
    /// `__main__` of `python -c`).
    pub const NO_FILE: &str = "no_file";
    /// A module whose `__file__` text was cut at `--max-str`.
    pub const CONTENT_TRUNCATED: &str = "content_truncated";
    /// The type object is not in the snapshot.
    pub const TYPE_NOT_IN_SNAPSHOT: &str = "type_not_in_snapshot";
    /// The object's type could not be read.
    pub const UNKNOWN_TYPE: &str = "unknown_type";
}

/// What an object is, as far as locations go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Function,
    Code,
    /// Bound method, `classmethod`, `staticmethod`: located through `__func__`.
    Method,
    Property,
    Module,
    Class,
    Other,
}

/// The location of one object or type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Loc {
    /// The object is not a kind that has a location.
    NotApplicable,
    Found(SourceLocation),
    /// It could have one, but it is not known; the reason code.
    Missing(&'static str),
}

impl Loc {
    /// `(location, reason)` as stored in the reports.
    pub fn split(self) -> (Option<SourceLocation>, Option<String>) {
        match self {
            Loc::NotApplicable => (None, None),
            Loc::Found(l) => (Some(l), None),
            Loc::Missing(r) => (None, Some(r.to_string())),
        }
    }
}

/// `path:line` from a `source_loc` extra. The line is after the last colon,
/// so Windows drive letters are kept in the path.
fn parse_loc(s: &str) -> Option<(String, u32)> {
    let (file, line) = s.rsplit_once(':')?;
    let line = line.trim().parse::<u32>().ok()?;
    (!file.is_empty()).then(|| (file.to_string(), line))
}

fn found(file: String, line: Option<u32>, exact: bool, via: &str) -> Loc {
    Loc::Found(SourceLocation {
        file,
        line,
        exact,
        via: via.to_string(),
    })
}

pub(crate) struct Locator<'s> {
    snap: &'s Snapshot,
    /// Kind of the instances of each type id.
    kinds: Vec<Kind>,
    objects: RefCell<HashMap<ObjectIndex, Loc>>,
    types: RefCell<HashMap<TypeId, Loc>>,
}

impl<'s> Locator<'s> {
    pub fn new(snap: &'s Snapshot) -> Result<Locator<'s>> {
        let mut kinds = Vec::with_capacity(snap.type_count());
        for t in 0..snap.type_count() as u32 {
            let e = snap.type_entry(TypeId(t)).expect("type id in range");
            let k = if snap.string(e.module)? == "builtins" {
                match snap.string(e.qualname)? {
                    "function" => Kind::Function,
                    "code" => Kind::Code,
                    "method" | "classmethod" | "staticmethod" => Kind::Method,
                    "property" => Kind::Property,
                    "module" => Kind::Module,
                    _ => Kind::Other,
                }
            } else {
                Kind::Other
            };
            kinds.push(k);
        }
        Ok(Locator {
            snap,
            kinds,
            objects: RefCell::new(HashMap::new()),
            types: RefCell::new(HashMap::new()),
        })
    }

    pub fn kind(&self, v: ObjectIndex) -> Kind {
        let o = self.snap.object(v);
        if o.flags.contains(ObjectFlags::IS_TYPE) {
            return Kind::Class;
        }
        self.kinds
            .get(o.type_id.0 as usize)
            .copied()
            .unwrap_or(Kind::Other)
    }

    /// Target of the first `.name` edge of `v` that is in the snapshot.
    fn attr(&self, v: ObjectIndex, name: &str) -> Result<Option<ObjectIndex>> {
        for e in self.snap.edges(v) {
            if let EdgeLabel::Attr(s) = e.label {
                if self.snap.string(s)? == name {
                    if let Some(t) = self.snap.find_object(e.target) {
                        return Ok(Some(t));
                    }
                }
            }
        }
        Ok(None)
    }

    fn qualname(&self, v: ObjectIndex) -> Result<Option<&'s str>> {
        let q = self.snap.extras(v).and_then(|x| x.qualname);
        Ok(self.snap.opt_string(q)?)
    }

    fn own_loc(&self, v: ObjectIndex) -> Result<Option<(String, u32)>> {
        let s = self.snap.extras(v).and_then(|x| x.source_loc);
        Ok(self.snap.opt_string(s)?.and_then(parse_loc))
    }

    /// The code object of function `f`, through `.__code__`.
    fn code_of(&self, f: ObjectIndex) -> Result<Option<ObjectIndex>> {
        Ok(self
            .attr(f, "__code__")?
            .filter(|&c| self.kind(c) == Kind::Code))
    }

    /// `(file, line)` of a function, through `.__code__`.
    fn function_loc(&self, f: ObjectIndex) -> Result<Option<(String, u32)>> {
        if let Some(c) = self.code_of(f)? {
            if let Some(l) = self.own_loc(c)? {
                return Ok(Some(l));
            }
        }
        self.own_loc(f)
    }

    /// Whether function `f` was compiled in the body of the class with
    /// qualname `class_q`. The code object's `co_qualname` is set by the
    /// compiler; the function's `__qualname__` is not used when the code
    /// object is known, because `functools.wraps` copies it onto wrappers
    /// defined elsewhere.
    fn defined_in(&self, f: ObjectIndex, class_q: &str) -> Result<bool> {
        let q = match self.code_of(f)? {
            Some(c) => self.qualname(c)?,
            None => None,
        };
        let Some(q) = q.or(self.qualname(f)?) else {
            // Nothing to check against.
            return Ok(true);
        };
        Ok(q.strip_prefix(class_q)
            .is_some_and(|rest| rest.starts_with('.')))
    }

    /// The function a method wrapper refers to through `.__func__`.
    fn method_func(&self, m: ObjectIndex) -> Result<Option<ObjectIndex>> {
        Ok(self
            .attr(m, "__func__")?
            .filter(|&f| self.kind(f) == Kind::Function))
    }

    /// Where the object `v` is defined. Memoised.
    pub fn object(&self, v: ObjectIndex) -> Result<Loc> {
        if let Some(l) = self.objects.borrow().get(&v) {
            return Ok(l.clone());
        }
        let l = match self.kind(v) {
            Kind::Code => match self.own_loc(v)? {
                Some((f, l)) => found(f, Some(l), true, "code_object"),
                None => Loc::Missing(reason::NO_CODE_OBJECT),
            },
            Kind::Function => match self.function_loc(v)? {
                Some((f, l)) => found(f, Some(l), true, "function"),
                None => Loc::Missing(reason::NO_CODE_OBJECT),
            },
            Kind::Method => match self.method_func(v)? {
                Some(func) => match self.function_loc(func)? {
                    Some((f, l)) => found(f, Some(l), true, "method"),
                    None => Loc::Missing(reason::NO_CODE_OBJECT),
                },
                None => Loc::Missing(reason::NO_CODE_OBJECT),
            },
            Kind::Class => self.class(v)?,
            Kind::Module => self.module(v)?,
            Kind::Property | Kind::Other => Loc::NotApplicable,
        };
        self.objects.borrow_mut().insert(v, l.clone());
        Ok(l)
    }

    /// A class, from the functions defined in its body.
    fn class(&self, v: ObjectIndex) -> Result<Loc> {
        let Some(dict) = self.attr(v, "__dict__")? else {
            return Ok(Loc::Missing(reason::NO_PYTHON_METHODS));
        };
        let class_q = self.qualname(v)?;
        let mut funcs = Vec::new();
        for e in self.snap.edges(dict) {
            if !matches!(e.label, EdgeLabel::DictValue(_)) {
                continue;
            }
            let Some(t) = self.snap.find_object(e.target) else {
                continue;
            };
            match self.kind(t) {
                Kind::Function => funcs.push(t),
                Kind::Method => funcs.extend(self.method_func(t)?),
                Kind::Property => {
                    for name in ["fget", "fset", "fdel"] {
                        if let Some(f) = self.attr(t, name)? {
                            if self.kind(f) == Kind::Function {
                                funcs.push(f);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let mut file: Option<String> = None;
        let mut line = u32::MAX;
        for f in funcs {
            // Only functions compiled in the class body, not ones assigned
            // to a class attribute from elsewhere or decorator wrappers.
            if let Some(cq) = class_q {
                if !self.defined_in(f, cq)? {
                    continue;
                }
            }
            let Some((ff, fl)) = self.function_loc(f)? else {
                continue;
            };
            if ff.starts_with('<') {
                continue;
            }
            match &file {
                Some(prev) if *prev != ff => return Ok(Loc::Missing(reason::METHODS_DISAGREE)),
                Some(_) => {}
                None => file = Some(ff),
            }
            line = line.min(fl);
        }
        Ok(match file {
            Some(f) => found(f, Some(line), false, "methods"),
            None => Loc::Missing(reason::NO_PYTHON_METHODS),
        })
    }

    /// A module, from `__dict__['__file__']`.
    fn module(&self, v: ObjectIndex) -> Result<Loc> {
        if !self.snap.info().contents_captured {
            return Ok(Loc::Missing(reason::CONTENTS_NOT_CAPTURED));
        }
        let Some(dict) = self.attr(v, "__dict__")? else {
            return Ok(Loc::Missing(reason::NO_FILE));
        };
        for e in self.snap.edges(dict) {
            let EdgeLabel::DictValue(KeyLabel::Repr(k)) = e.label else {
                continue;
            };
            if self.snap.string(k)? != "'__file__'" {
                continue;
            }
            let Some(x) = self
                .snap
                .find_object(e.target)
                .and_then(|t| self.snap.extras(t))
            else {
                break;
            };
            if x.content_truncated {
                return Ok(Loc::Missing(reason::CONTENT_TRUNCATED));
            }
            if let Some(text) = self.snap.opt_string(x.content)? {
                if !text.is_empty() {
                    return Ok(found(text.to_string(), None, true, "module_file"));
                }
            }
            break;
        }
        Ok(Loc::Missing(reason::NO_FILE))
    }

    /// Where the type `t` (a class) is defined, through its type object.
    /// Memoised.
    pub fn type_id(&self, t: TypeId) -> Result<Loc> {
        if let Some(l) = self.types.borrow().get(&t) {
            return Ok(l.clone());
        }
        let l = match self.snap.type_entry(t) {
            None => Loc::Missing(reason::UNKNOWN_TYPE),
            Some(e) => match (e.addr != 0)
                .then(|| self.snap.find_object(e.addr))
                .flatten()
            {
                None => Loc::Missing(reason::TYPE_NOT_IN_SNAPSHOT),
                Some(v) => match self.object(v)? {
                    // A type entry whose object is not flagged as a type.
                    Loc::NotApplicable => Loc::Missing(reason::NO_PYTHON_METHODS),
                    l => l,
                },
            },
        };
        self.types.borrow_mut().insert(t, l.clone());
        Ok(l)
    }

    /// Location of a set of type ids that share a display name: the first
    /// one found, else the first reason.
    pub fn types<I: IntoIterator<Item = TypeId>>(&self, ids: I) -> Result<Loc> {
        let mut first = None;
        for t in ids {
            let l = self.type_id(t)?;
            if matches!(l, Loc::Found(_)) {
                return Ok(l);
            }
            first.get_or_insert(l);
        }
        Ok(first.unwrap_or(Loc::Missing(reason::UNKNOWN_TYPE)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(parse_loc("app/a.py:12"), Some(("app/a.py".into(), 12)));
        assert_eq!(
            parse_loc(r"C:\app\a.py:3"),
            Some((r"C:\app\a.py".into(), 3))
        );
        assert_eq!(parse_loc("nocolon"), None);
        assert_eq!(parse_loc(":3"), None);
        assert_eq!(parse_loc("a.py:x"), None);
    }
}
