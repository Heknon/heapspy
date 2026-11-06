//! Python-style `repr()` text for the scalar types whose keys and contents
//! the walker records: str, bytes, int and float.

/// `repr(s)` for a `str`, following CPython's quoting rules: single quotes
/// unless the text contains `'` and no `"`.
pub fn str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if is_unprintable(c) => {
                let v = c as u32;
                if v <= 0xff {
                    out.push_str(&format!("\\x{v:02x}"));
                } else if v <= 0xffff {
                    out.push_str(&format!("\\u{v:04x}"));
                } else {
                    out.push_str(&format!("\\U{v:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Rough version of `str.isprintable()` for the code points that matter in
/// practice: C1 controls, surrogates, private use, line / paragraph
/// separators and a few format characters.
fn is_unprintable(c: char) -> bool {
    let v = c as u32;
    matches!(v, 0x80..=0xa0 | 0xad | 0x2028 | 0x2029 | 0x200b..=0x200f | 0xfeff | 0xe000..=0xf8ff)
}

/// `repr(b)` for `bytes`.
pub fn bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::with_capacity(b.len() + 3);
    out.push('b');
    out.push(quote as char);
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c as char);
            }
            0x20..=0x7e => out.push(c as char),
            c => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out.push(quote as char);
    out
}

/// `repr(x)` for a float, matching CPython's `float_repr` (shortest
/// round-trip digits, exponent form outside `1e-4 <= |x| < 1e16`).
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    let a = x.abs();
    if (1e-4..1e16).contains(&a) {
        let s = format!("{x}");
        if s.contains('.') {
            s
        } else {
            s + ".0"
        }
    } else {
        // Rust `{:e}` gives `1e16`, `1.5e-7`; Python wants `1e+16`, `1.5e-07`.
        let s = format!("{x:e}");
        let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
        let (sign, digits) = match exp.strip_prefix('-') {
            Some(d) => ('-', d),
            None => ('+', exp),
        };
        format!("{mant}e{sign}{digits:0>2}")
    }
}

/// Decimal text of an int stored as 30-bit digits (least significant
/// first). `None` if it has more digits than `max_digits`.
pub fn long_repr(digits: &[u32], negative: bool, max_digits: usize) -> Option<String> {
    if digits.len() > max_digits {
        return None;
    }
    // Repeated division by 10^9 over base 2^30 limbs.
    let mut limbs: Vec<u32> = digits.to_vec();
    while limbs.last() == Some(&0) {
        limbs.pop();
    }
    if limbs.is_empty() {
        return Some("0".into());
    }
    let mut chunks: Vec<u32> = Vec::new();
    while !limbs.is_empty() {
        let mut rem: u64 = 0;
        for l in limbs.iter_mut().rev() {
            let cur = (rem << 30) | *l as u64;
            *l = (cur / 1_000_000_000) as u32;
            rem = cur % 1_000_000_000;
        }
        chunks.push(rem as u32);
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
    }
    let mut s = String::new();
    if negative {
        s.push('-');
    }
    let mut it = chunks.iter().rev();
    if let Some(first) = it.next() {
        s.push_str(&first.to_string());
    }
    for c in it {
        s.push_str(&format!("{c:09}"));
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reprs() {
        assert_eq!(str_repr("CACHE"), "'CACHE'");
        assert_eq!(str_repr("it's"), "\"it's\"");
        assert_eq!(str_repr("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(str_repr("x\ny\\"), "'x\\ny\\\\'");
        assert_eq!(str_repr("\u{1}é"), "'\\x01é'");
        assert_eq!(bytes_repr(b"ab\x00'"), "b\"ab\\x00'\"");
        assert_eq!(float_repr(1.5), "1.5");
        assert_eq!(float_repr(3.0), "3.0");
        assert_eq!(float_repr(1e16), "1e+16");
        assert_eq!(float_repr(1.5e-7), "1.5e-07");
        assert_eq!(float_repr(-0.0), "-0.0");
        assert_eq!(long_repr(&[], false, 10).unwrap(), "0");
        assert_eq!(long_repr(&[5], true, 10).unwrap(), "-5");
        // 2**30 + 1
        assert_eq!(long_repr(&[1, 1], false, 10).unwrap(), "1073741825");
        // 10**18 = digits of base 2**30
        let mut v: u128 = 10u128.pow(18);
        let mut d = Vec::new();
        while v > 0 {
            d.push((v & ((1 << 30) - 1)) as u32);
            v >>= 30;
        }
        assert_eq!(long_repr(&d, false, 10).unwrap(), "1000000000000000000");
        assert!(long_repr(&[1; 20], false, 10).is_none());
    }
}
