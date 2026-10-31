// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Wire-level DNS message encoding, decoding, truncation, and length helpers.

pub(crate) use codec::*;
pub(crate) use compression::*;
pub(crate) use length::*;
pub(crate) use rdata::*;

mod codec;
mod compression;
mod length;
mod rdata;

/// Decoded fixed 12-byte DNS wire header.
///
/// This view intentionally stops at the RFC 1035 header and does not inspect
/// questions or resource-record sections, making it suitable for cheap ingress
/// classification before allocating a full [`crate::Message`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireHeader {
    header: crate::Header,
    low_rcode: u16,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl WireHeader {
    #[inline]
    pub fn header(&self) -> &crate::Header {
        &self.header
    }

    #[inline]
    pub fn question_count(&self) -> u16 {
        self.question_count
    }

    #[inline]
    pub fn answer_count(&self) -> u16 {
        self.answer_count
    }

    #[inline]
    pub fn authority_count(&self) -> u16 {
        self.authority_count
    }

    #[inline]
    pub fn additional_count(&self) -> u16 {
        self.additional_count
    }
}

/// Decode only the fixed DNS header without parsing any variable-length
/// sections. The returned header contains the low four RCODE bits available in
/// the fixed header; extended EDNS RCODE bits require full message decoding.
#[inline]
pub fn decode_header(packet: &[u8]) -> crate::Result<WireHeader> {
    let (mut header, _, low_rcode, question_count, answer_count, authority_count, additional_count) =
        codec::parse_header(packet)?;
    header.set_rcode(crate::Rcode::from_parts(0, low_rcode as u8));
    Ok(WireHeader {
        header,
        low_rcode,
        question_count,
        answer_count,
        authority_count,
        additional_count,
    })
}

pub fn decode_rdata_from_wire(
    rr_type: crate::RecordType,
    data: &[u8],
) -> crate::Result<crate::RData> {
    parse_rdata(
        data,
        &crate::Name::root(),
        rr_type,
        u16::from(crate::DNSClass::IN),
        0,
        0,
        data.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MessageType, Opcode, Rcode};

    #[test]
    fn decode_header_reads_only_fixed_dns_header() {
        let packet = [
            0x12, 0x34, // id
            0x01, 0x10, // QUERY, RD=1, CD=1
            0x00, 0x02, // qdcount
            0x00, 0x03, // ancount
            0x00, 0x04, // nscount
            0x00, 0x05, // arcount
            0xFF, // deliberately malformed section body
        ];

        let decoded = decode_header(&packet).expect("fixed header should decode");
        assert!(crate::Message::from_bytes(&packet).is_err());

        assert_eq!(decoded.header().id(), 0x1234);
        assert_eq!(decoded.header().message_type(), MessageType::Query);
        assert_eq!(decoded.header().opcode(), Opcode::Query);
        assert_eq!(decoded.header().rcode(), Rcode::NoError);
        assert!(decoded.header().recursion_desired());
        assert!(decoded.header().checking_disabled());
        assert_eq!(decoded.question_count(), 2);
        assert_eq!(decoded.answer_count(), 3);
        assert_eq!(decoded.authority_count(), 4);
        assert_eq!(decoded.additional_count(), 5);
    }

    #[test]
    fn full_decode_can_reuse_predecoded_wire_header() {
        let packet = [
            0x12, 0x34, 0x01, 0x00, // id + RD query flags
            0x00, 0x01, 0x00, 0x00, // qd=1, an=0
            0x00, 0x00, 0x00, 0x00, // ns=0, ar=0
            0x00, // root qname
            0x00, 0x01, // A
            0x00, 0x01, // IN
        ];
        let header = decode_header(&packet).expect("fixed header should decode");
        let normal = crate::Message::from_bytes(&packet).expect("message should decode");
        let reused = crate::Message::from_bytes_with_wire_header(&packet, &header)
            .expect("message should decode with predecoded header");
        assert_eq!(reused, normal);
    }

    #[test]
    fn decode_header_rejects_short_dns_datagram() {
        assert!(decode_header(&[0u8; 11]).is_err());
    }
}
