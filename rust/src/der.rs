// SPDX-License-Identifier: EUPL-1.2

//! A deliberately tiny, strict DER reader.
//!
//! We only need to walk X.509 certificates and the Android KeyDescription
//! extension, so a full ASN.1 stack would be more attack surface than value.

use crate::error::{Error, Result};

pub const CLASS_UNIVERSAL: u8 = 0;
pub const CLASS_CONTEXT: u8 = 2;

pub const TAG_BOOLEAN: u32 = 0x01;
pub const TAG_INTEGER: u32 = 0x02;
pub const TAG_BIT_STRING: u32 = 0x03;
pub const TAG_OCTET_STRING: u32 = 0x04;
pub const TAG_NULL: u32 = 0x05;
pub const TAG_OID: u32 = 0x06;
pub const TAG_ENUMERATED: u32 = 0x0a;
pub const TAG_SEQUENCE: u32 = 0x10;
pub const TAG_SET: u32 = 0x11;

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub value: &'a [u8],
    /// The complete encoding (header + value).
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn is(&self, class: u8, tag: u32) -> bool {
        self.class == class && self.tag == tag
    }

    pub fn expect(self, class: u8, tag: u32, what: &str) -> Result<Self> {
        if self.is(class, tag) {
            Ok(self)
        } else {
            Err(Error::data(format!(
                "DER: expected {what} (class {class}, tag {tag}), got class {}, tag {}",
                self.class, self.tag
            )))
        }
    }

    /// Parse the contents of a constructed element as a list of children.
    pub fn children(&self) -> Result<Vec<Tlv<'a>>> {
        if !self.constructed {
            return Err(Error::data("DER: element is not constructed"));
        }
        read_all(self.value)
    }

    /// The single child of an EXPLICIT context-specific tag.
    pub fn explicit_inner(&self) -> Result<Tlv<'a>> {
        let (inner, rest) = read(self.value)?;
        if !rest.is_empty() {
            return Err(Error::data("DER: trailing data in explicit tag"));
        }
        Ok(inner)
    }

    /// Small non-negative INTEGER / ENUMERATED value.
    pub fn as_u64(&self) -> Result<u64> {
        if !(self.is(CLASS_UNIVERSAL, TAG_INTEGER) || self.is(CLASS_UNIVERSAL, TAG_ENUMERATED)) {
            return Err(Error::data("DER: expected INTEGER/ENUMERATED"));
        }
        let v = self.value;
        if v.is_empty() || v[0] & 0x80 != 0 {
            return Err(Error::data("DER: negative or empty integer"));
        }
        let v = if v.len() > 1 && v[0] == 0 { &v[1..] } else { v };
        if v.len() > 8 {
            return Err(Error::data("DER: integer too large"));
        }
        Ok(v.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    pub fn as_bool(&self) -> Result<bool> {
        let t = self.expect(CLASS_UNIVERSAL, TAG_BOOLEAN, "BOOLEAN")?;
        match t.value {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(Error::data("DER: invalid BOOLEAN")),
        }
    }
}

/// Read one TLV from the front of `input`, returning it and the remainder.
pub fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    let mut i = 0usize;
    let first = *input.first().ok_or_else(|| Error::data("DER: unexpected end"))?;
    i += 1;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let mut tag = u32::from(first & 0x1f);
    if tag == 0x1f {
        // High tag number form (base-128), e.g. KeyMint tags like [702].
        tag = 0;
        loop {
            let b = *input.get(i).ok_or_else(|| Error::data("DER: truncated tag"))?;
            i += 1;
            if tag > (u32::MAX >> 7) {
                return Err(Error::data("DER: tag overflow"));
            }
            tag = (tag << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let lb = *input.get(i).ok_or_else(|| Error::data("DER: truncated length"))?;
    i += 1;
    let len = if lb & 0x80 == 0 {
        usize::from(lb)
    } else {
        let n = usize::from(lb & 0x7f);
        if n == 0 || n > 4 {
            return Err(Error::data("DER: unsupported length encoding"));
        }
        let bytes = input
            .get(i..i + n)
            .ok_or_else(|| Error::data("DER: truncated length"))?;
        i += n;
        bytes.iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
    };
    let end = i
        .checked_add(len)
        .filter(|e| *e <= input.len())
        .ok_or_else(|| Error::data("DER: length exceeds input"))?;
    Ok((
        Tlv {
            class,
            constructed,
            tag,
            value: &input[i..end],
            raw: &input[..end],
        },
        &input[end..],
    ))
}

pub fn read_all(mut input: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let (t, rest) = read(input)?;
        out.push(t);
        input = rest;
    }
    Ok(out)
}

/// Parse exactly one TLV spanning the whole input.
pub fn read_one(input: &[u8]) -> Result<Tlv<'_>> {
    let (t, rest) = read(input)?;
    if !rest.is_empty() {
        return Err(Error::data("DER: trailing data"));
    }
    Ok(t)
}
