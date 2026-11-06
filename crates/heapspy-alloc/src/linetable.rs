//! Decoding CPython's `co_linetable` (the location table of 3.11 to 3.14).
//!
//! A recorder stores each frame as (code object, instruction offset). The
//! code table keeps the code object's raw `co_linetable` bytes and
//! `co_firstlineno`, and this module turns an offset into a source position
//! the same way `PyCode_Addr2Line` and `code.co_positions()` do.
//!
//! # The format
//!
//! The table is a sequence of entries, each covering 1 to 8 code units
//! (2 bytes each) of `co_code`, in order. The first byte of an entry has bit
//! 7 set; continuation bytes have it clear:
//!
//! ```text
//! 1 cccc lll   c = code (0..=15), l = length in code units - 1
//! ```
//!
//! | code | form | line | following bytes |
//! |---:|---|---|---|
//! | 0-9 | short | unchanged | 1 byte `b`: column = `code << 3 \| b >> 4`, end column = column + `b & 15` |
//! | 10-12 | one line | + (code - 10) | column byte, end column byte |
//! | 13 | no columns | + svarint | none further; columns unknown |
//! | 14 | long | + svarint | end line delta varint, column + 1 varint, end column + 1 varint |
//! | 15 | none | unchanged, reported as no line | none |
//!
//! A varint is little-endian 6-bit groups, bit 6 (0x40) set on every group
//! but the last. An svarint is a varint `v` read as `v >> 1`, negated when
//! `v & 1`. The running line starts at `co_firstlineno`. Short and one-line
//! forms end on the line they start on.
//!
//! This is `Objects/locations.md` in the CPython tree, implemented by
//! `advance_with_locations` in `Objects/codeobject.c`. The format is the
//! same in 3.11, 3.12, 3.13 and 3.14; the tests check it against code
//! objects compiled by each of 3.12, 3.13 and 3.14.

use crate::types::LineTableFormat;

/// A source position: what one element of `co_positions()` holds.
/// `None` where CPython reports `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Position {
    pub line: Option<u32>,
    pub end_line: Option<u32>,
    pub column: Option<u32>,
    pub end_column: Option<u32>,
}

/// One table entry: the bytecode range `[start, end)` (in bytes) and its position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocationEntry {
    pub start: u32,
    pub end: u32,
    pub position: Position,
}

/// The table could not be decoded at byte `at`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorruptLineTable {
    pub at: usize,
}

impl std::fmt::Display for CorruptLineTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line table is corrupt at byte {}", self.at)
    }
}

impl std::error::Error for CorruptLineTable {}

/// Iterator over the entries of a location table. After the first error it
/// yields nothing more.
#[derive(Clone, Debug)]
pub struct Locations<'a> {
    table: &'a [u8],
    pos: usize,
    line: i64,
    addr: u64,
    done: bool,
}

impl<'a> Locations<'a> {
    pub fn new(table: &'a [u8], firstlineno: i32) -> Self {
        Self {
            table,
            pos: 0,
            line: firstlineno as i64,
            addr: 0,
            done: false,
        }
    }

    fn byte(&mut self) -> Result<u8, CorruptLineTable> {
        let b = *self
            .table
            .get(self.pos)
            .ok_or(CorruptLineTable { at: self.pos })?;
        // Continuation bytes never have bit 7 set.
        if b & 0x80 != 0 {
            return Err(CorruptLineTable { at: self.pos });
        }
        self.pos += 1;
        Ok(b)
    }

    fn varint(&mut self) -> Result<u64, CorruptLineTable> {
        let start = self.pos;
        let mut b = self.byte()?;
        let mut val = (b & 63) as u64;
        let mut shift = 0u32;
        while b & 64 != 0 {
            shift += 6;
            if shift > 36 {
                return Err(CorruptLineTable { at: start });
            }
            b = self.byte()?;
            val |= ((b & 63) as u64) << shift;
        }
        Ok(val)
    }

    fn svarint(&mut self) -> Result<i64, CorruptLineTable> {
        let v = self.varint()?;
        Ok(if v & 1 != 0 {
            -((v >> 1) as i64)
        } else {
            (v >> 1) as i64
        })
    }

    fn entry(&mut self) -> Result<LocationEntry, CorruptLineTable> {
        let at = self.pos;
        let first = self.table[at];
        if first & 0x80 == 0 {
            return Err(CorruptLineTable { at });
        }
        self.pos += 1;
        let code = (first >> 3) & 15;
        let start = self.addr;
        let end = start + ((first & 7) as u64 + 1) * 2;
        if end > u32::MAX as u64 {
            return Err(CorruptLineTable { at });
        }
        let line = |l: i64| u32::try_from(l).ok();
        let col = |c: i64| u32::try_from(c).ok();
        let position = match code {
            15 => Position::default(),
            14 => {
                self.line += self.svarint()?;
                let end_line = self.line + self.varint()? as i64;
                let c = self.varint()? as i64 - 1;
                let ec = self.varint()? as i64 - 1;
                Position {
                    line: line(self.line),
                    end_line: line(end_line),
                    column: col(c),
                    end_column: col(ec),
                }
            }
            13 => {
                self.line += self.svarint()?;
                Position {
                    line: line(self.line),
                    end_line: line(self.line),
                    column: None,
                    end_column: None,
                }
            }
            10..=12 => {
                self.line += (code - 10) as i64;
                let c = self.byte()?;
                let ec = self.byte()?;
                Position {
                    line: line(self.line),
                    end_line: line(self.line),
                    column: Some(c as u32),
                    end_column: Some(ec as u32),
                }
            }
            _ => {
                let b = self.byte()?;
                let c = ((code as u32) << 3) | (b as u32 >> 4);
                Position {
                    line: line(self.line),
                    end_line: line(self.line),
                    column: Some(c),
                    end_column: Some(c + (b as u32 & 15)),
                }
            }
        };
        // Keep the running line inside i32, as CPython's int does.
        if self.line.unsigned_abs() > i32::MAX as u64 {
            return Err(CorruptLineTable { at });
        }
        self.addr = end;
        Ok(LocationEntry {
            start: start as u32,
            end: end as u32,
            position,
        })
    }
}

impl Iterator for Locations<'_> {
    type Item = Result<LocationEntry, CorruptLineTable>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.pos >= self.table.len() {
            return None;
        }
        let r = self.entry();
        if r.is_err() {
            self.done = true;
        }
        Some(r)
    }
}

/// The position of the instruction at byte `offset` of `co_code`, or `None`
/// if the offset is past the end of the table or the table is corrupt
/// before reaching it. An odd offset is rounded down to its code unit.
pub fn position_at(table: &[u8], firstlineno: i32, offset: u32) -> Option<Position> {
    let offset = offset & !1;
    for e in Locations::new(table, firstlineno) {
        let e = e.ok()?;
        if offset < e.end {
            return Some(e.position);
        }
    }
    None
}

/// The line of the instruction at byte `offset`, as `PyCode_Addr2Line`
/// computes it. `None` for instructions with no line (CPython's -1).
pub fn line_at(table: &[u8], firstlineno: i32, offset: u32) -> Option<u32> {
    position_at(table, firstlineno, offset)?.line
}

/// Line for a frame: dispatches on the table format. Without an offset
/// (the frame had not started, or the pointer was unreadable) this is
/// `co_firstlineno`, which is what `PyCode_Addr2Line` returns for a
/// negative offset.
pub fn line_for(
    format: LineTableFormat,
    table: &[u8],
    firstlineno: i32,
    offset: Option<u32>,
) -> Option<u32> {
    let Some(offset) = offset else {
        return u32::try_from(firstlineno).ok();
    };
    match format {
        LineTableFormat::Locations311 => line_at(table, firstlineno, offset),
        LineTableFormat::None | LineTableFormat::Unknown(_) => None,
    }
}

/// Build a location table from `(byte length, line)` runs, for tests and
/// synthetic profiles. Lines use the no-columns form (code 13) and `None`
/// the no-location form (code 15). Each run's length is rounded up to whole
/// code units and split into entries of at most 8 units.
pub fn encode_lines(firstlineno: i32, runs: &[(u32, Option<u32>)]) -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 64 {
            out.push(0x40 | (v & 63) as u8);
            v >>= 6;
        }
        out.push(v as u8);
    }
    let mut out = Vec::new();
    let mut cur = firstlineno as i64;
    for &(bytes, line) in runs {
        let mut units = bytes.div_ceil(2);
        while units > 0 {
            let n = units.min(8);
            units -= n;
            match line {
                None => out.push(0x80 | (15 << 3) | (n - 1) as u8),
                Some(l) => {
                    out.push(0x80 | (13 << 3) | (n - 1) as u8);
                    let d = l as i64 - cur;
                    cur = l as i64;
                    let v = if d < 0 {
                        (d.unsigned_abs() << 1) | 1
                    } else {
                        (d as u64) << 1
                    };
                    varint(&mut out, v);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_round_trips() {
        let t = encode_lines(5, &[(4, Some(5)), (20, Some(200)), (2, None), (6, Some(3))]);
        assert_eq!(line_at(&t, 5, 0), Some(5));
        assert_eq!(line_at(&t, 5, 2), Some(5));
        assert_eq!(line_at(&t, 5, 4), Some(200));
        assert_eq!(line_at(&t, 5, 22), Some(200));
        assert_eq!(line_at(&t, 5, 24), None);
        assert_eq!(line_at(&t, 5, 26), Some(3));
        assert_eq!(line_at(&t, 5, 31), Some(3));
        assert_eq!(line_at(&t, 5, 32), None);
        assert!(Locations::new(&t, 5).all(|e| e.is_ok()));
    }

    #[test]
    fn hand_built_table() {
        // firstlineno 10:
        //   short form code 0, 1 unit, col 2..5        -> line 10
        //   one-line +1 (code 11), 2 units, col 4..9   -> line 11
        //   no-columns (13), 1 unit, delta -1 (svarint 3) -> line 10
        //   long (14), 1 unit, +100 (svarint 200 = 0x48 0x03), end +2, col 0 (1), end col 7 (8)
        //   none (15), 1 unit                          -> None
        let t = [
            0x80, 0x25, // short
            0xd9, 4, 9, // one line +1, len 2
            0xe8, 3, // no columns, -1
            0xf0, 0x48, 0x03, 2, 1, 8,    // long
            0xf8, // none
        ];
        let es: Vec<_> = Locations::new(&t, 10).map(|e| e.unwrap()).collect();
        assert_eq!(es.len(), 5);
        assert_eq!((es[0].start, es[0].end), (0, 2));
        assert_eq!(
            es[0].position,
            Position {
                line: Some(10),
                end_line: Some(10),
                column: Some(2),
                end_column: Some(7)
            }
        );
        assert_eq!((es[1].start, es[1].end), (2, 6));
        assert_eq!(es[1].position.line, Some(11));
        assert_eq!(es[1].position.column, Some(4));
        assert_eq!(es[2].position.line, Some(10));
        assert_eq!(es[2].position.column, None);
        assert_eq!(
            es[3].position,
            Position {
                line: Some(110),
                end_line: Some(112),
                column: Some(0),
                end_column: Some(7)
            }
        );
        assert_eq!(es[4].position, Position::default());
        assert_eq!(line_at(&t, 10, 0), Some(10));
        assert_eq!(line_at(&t, 10, 3), Some(11));
        assert_eq!(line_at(&t, 10, 5), Some(11));
        assert_eq!(line_at(&t, 10, 6), Some(10));
        assert_eq!(line_at(&t, 10, 8), Some(110));
        assert_eq!(line_at(&t, 10, 10), None);
        assert_eq!(position_at(&t, 10, 12), None);
        assert_eq!(
            line_for(LineTableFormat::Locations311, &t, 10, None),
            Some(10)
        );
        assert_eq!(line_for(LineTableFormat::Unknown(9), &t, 10, Some(0)), None);
    }

    #[test]
    fn corrupt_tables_do_not_panic() {
        let bad: &[&[u8]] = &[
            &[0x00],
            &[0x80],
            &[0xf0],
            &[0xf0, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x01],
            &[0xd0, 1],
            &[0x80, 0x80],
        ];
        for t in bad {
            assert!(
                Locations::new(t, 1).any(|e| e.is_err()),
                "{t:?} decoded without error"
            );
            let _ = line_at(t, 1, 0);
        }
        // Every byte string up to length 3 decodes or errors, never panics.
        for a in 0..=255u8 {
            for b in [0u8, 1, 0x3f, 0x40, 0x7f, 0x80, 0xff] {
                for c in [0u8, 0x40, 0x80, 0xff] {
                    let t = [a, b, c];
                    for e in Locations::new(&t, i32::MAX) {
                        let _ = e;
                    }
                    let _ = line_at(&t, i32::MIN, 4);
                }
            }
        }
    }
}
