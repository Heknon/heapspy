//! Terminal styling for text reports: ANSI colors when enabled, plain text
//! otherwise. Reports are built the same way either way, so the plain text
//! output is the colored output with the escapes removed.

/// A color or emphasis for a piece of text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paint {
    /// Section headings.
    Heading,
    /// The thing a row is about: a root path, a type.
    Strong,
    /// Secondary text: descriptions, hints.
    Dim,
    /// Bad: growth, leaks, the largest holder.
    Bad,
    /// Worth a look.
    Warn,
    /// Fine: shrinking, flat.
    Good,
    /// Memory categories, in the order of the memory bar.
    Python,
    Native,
    Leaked,
    Free,
    Other,
    PymallocFree,
    Mapped,
    /// Type names and instance counts.
    Type,
    /// Commands the reader can run next.
    Command,
}

impl Paint {
    fn code(self) -> &'static str {
        match self {
            Paint::Heading => "1;34",
            Paint::Strong => "1",
            Paint::Dim => "2",
            Paint::Bad => "31",
            Paint::Warn => "33",
            Paint::Good => "32",
            Paint::Python => "36",
            Paint::Native => "35",
            Paint::Leaked => "91",
            Paint::Free => "93",
            Paint::Other => "37",
            Paint::PymallocFree => "92",
            Paint::Mapped => "90",
            Paint::Type => "35",
            Paint::Command => "1;36",
        }
    }
}

/// How to style text reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    /// Use ANSI escapes.
    pub color: bool,
    /// Terminal width in columns; long cells are shortened to fit.
    pub width: usize,
}

impl Default for Style {
    fn default() -> Self {
        Style::plain()
    }
}

impl Style {
    /// No color, 100 columns.
    pub fn plain() -> Style {
        Style {
            color: false,
            width: 100,
        }
    }

    /// `text` painted with `p`, or `text` itself without color.
    pub fn paint(&self, p: Paint, text: impl AsRef<str>) -> String {
        let t = text.as_ref();
        if self.color && !t.is_empty() {
            format!("\x1b[{}m{t}\x1b[0m", p.code())
        } else {
            t.to_string()
        }
    }
}

/// Visible width of `s`: characters, not counting ANSI escapes.
pub fn visible_width(s: &str) -> usize {
    let mut n = 0;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            if c == 'm' {
                esc = false;
            }
        } else if c == '\x1b' {
            esc = true;
        } else {
            n += 1;
        }
    }
    n
}

/// `s` padded with spaces on the right to `w` visible columns.
pub fn pad_right(s: &str, w: usize) -> String {
    let v = visible_width(s);
    format!("{s}{}", " ".repeat(w.saturating_sub(v)))
}

/// `s` padded with spaces on the left to `w` visible columns.
pub fn pad_left(s: &str, w: usize) -> String {
    let v = visible_width(s);
    format!("{}{s}", " ".repeat(w.saturating_sub(v)))
}

/// Plain `s` shortened to at most `w` characters, with `…` in the middle,
/// so both the root and the last hop of a long path stay visible.
pub fn shorten(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w || w < 5 {
        return s.to_string();
    }
    let keep = w - 1;
    let head = keep / 2;
    let tail = keep - head;
    let h: String = s.chars().take(head).collect();
    let t: String = s.chars().skip(n - tail).collect();
    format!("{h}…{t}")
}

/// Plain `s` shortened to at most `w` characters by cutting its start, for
/// names whose end says the most (`…events.REGISTRY.listeners`).
pub fn shorten_left(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w || w < 2 {
        return s.to_string();
    }
    let t: String = s.chars().skip(n - (w - 1)).collect();
    format!("…{t}")
}

/// A horizontal bar of `width` cells, `frac` of them filled.
pub fn bar(frac: f64, width: usize) -> (String, String) {
    let cells = (frac.clamp(0.0, 1.0) * width as f64).round() as usize;
    let cells = if frac > 0.0 { cells.max(1) } else { 0 };
    ("█".repeat(cells), "░".repeat(width - cells.min(width)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_style_adds_nothing() {
        assert_eq!(Style::plain().paint(Paint::Bad, "x"), "x");
        let c = Style {
            color: true,
            width: 80,
        };
        let s = c.paint(Paint::Bad, "abc");
        assert_ne!(s, "abc");
        assert_eq!(visible_width(&s), 3);
        assert_eq!(visible_width(&pad_left(&s, 6)), 6);
    }

    #[test]
    fn shorten_keeps_both_ends() {
        assert_eq!(shorten("abcdefghij", 20), "abcdefghij");
        let s = shorten("sys.modules['app'].__dict__['CACHE']", 15);
        assert_eq!(s.chars().count(), 15);
        assert!(s.starts_with("sys.mod"));
        assert!(s.ends_with("CACHE']"));
    }

    #[test]
    fn shorten_left_keeps_the_end() {
        assert_eq!(
            shorten_left("app.events.REGISTRY.listeners", 20),
            "….REGISTRY.listeners"
        );
        assert_eq!(shorten_left("abc", 5), "abc");
        assert_eq!(shorten_left("abcdef", 4).chars().count(), 4);
    }

    #[test]
    fn bar_fills_at_least_one_cell_for_nonzero() {
        assert_eq!(bar(0.001, 10).0, "█");
        assert_eq!(bar(0.0, 10).0, "");
        assert_eq!(bar(1.0, 4).0.chars().count(), 4);
    }
}
