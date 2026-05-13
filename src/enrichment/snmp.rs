use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time::timeout;

const SNMP_PORT: u16 = 161;
const COMMUNITY: &[u8] = b"public";
const SYS_DESCR_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
const SYS_NAME_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00];
const RESPONSE_PDU_TAG: u8 = 0xa2;
const GET_REQUEST_PDU_TAG: u8 = 0xa0;
const SEQUENCE_TAG: u8 = 0x30;
const INTEGER_TAG: u8 = 0x02;
const OCTET_STRING_TAG: u8 = 0x04;
const NULL_TAG: u8 = 0x05;
const OBJECT_IDENTIFIER_TAG: u8 = 0x06;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpResult {
    pub sys_descr: Option<String>,
    pub sys_name: Option<String>,
}

pub async fn probe_snmp(ip: IpAddr, timeout_ms: u64) -> Option<SnmpResult> {
    let request_id = request_id();
    let packet = build_get_request(request_id, &[SYS_DESCR_OID, SYS_NAME_OID]);
    let target = SocketAddr::new(ip, SNMP_PORT);

    let result = timeout(Duration::from_millis(timeout_ms), async move {
        let bind_addr = match ip {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|error| {
                tracing::debug!(%ip, %error, "SNMP socket bind failed");
            })
            .ok()?;
        socket
            .send_to(&packet, target)
            .await
            .map_err(|error| {
                tracing::debug!(%ip, %error, "SNMP request send failed");
            })
            .ok()?;

        let mut buffer = [0u8; 2048];
        let (bytes_read, _) = socket
            .recv_from(&mut buffer)
            .await
            .map_err(|error| {
                tracing::debug!(%ip, %error, "SNMP response receive failed");
            })
            .ok()?;
        parse_snmp_response(&buffer[..bytes_read], request_id).or_else(|| {
            tracing::debug!(%ip, "SNMP response parse failed");
            None
        })
    })
    .await;

    match result {
        Ok(value) => value,
        Err(error) => {
            tracing::debug!(%ip, %timeout_ms, %error, "SNMP probe timed out");
            None
        }
    }
}

fn request_id() -> i32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| (duration.as_millis() & i32::MAX as u128) as i32)
        .unwrap_or(1)
}

fn build_get_request(request_id: i32, oids: &[&[u8]]) -> Vec<u8> {
    let varbinds = oids.iter().flat_map(|oid| encode_varbind(oid)).collect::<Vec<_>>();

    let pdu_body = [
        encode_integer(request_id),
        encode_integer(0),
        encode_integer(0),
        encode_sequence(varbinds),
    ]
    .concat();

    encode_sequence(
        [
            encode_integer(0),
            encode_octet_string(COMMUNITY),
            encode_tlv(GET_REQUEST_PDU_TAG, pdu_body),
        ]
        .concat(),
    )
}

fn encode_varbind(oid: &[u8]) -> Vec<u8> {
    encode_sequence([encode_oid(oid), encode_tlv(NULL_TAG, Vec::new())].concat())
}

fn encode_sequence(content: Vec<u8>) -> Vec<u8> {
    encode_tlv(SEQUENCE_TAG, content)
}

fn encode_integer(value: i32) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 == 0x80))
    {
        bytes.remove(0);
    }
    encode_tlv(INTEGER_TAG, bytes)
}

fn encode_octet_string(bytes: &[u8]) -> Vec<u8> {
    encode_tlv(OCTET_STRING_TAG, bytes.to_vec())
}

fn encode_oid(oid: &[u8]) -> Vec<u8> {
    encode_tlv(OBJECT_IDENTIFIER_TAG, oid.to_vec())
}

fn encode_tlv(tag: u8, content: Vec<u8>) -> Vec<u8> {
    let mut encoded = vec![tag];
    encoded.extend(encode_length(content.len()));
    encoded.extend(content);
    encoded
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut value = len;
        while value > 0 {
            bytes.push((value & 0xff) as u8);
            value >>= 8;
        }
        bytes.reverse();

        let mut encoded = vec![0x80 | bytes.len() as u8];
        encoded.extend(bytes);
        encoded
    }
}

fn parse_snmp_response(bytes: &[u8], expected_request_id: i32) -> Option<SnmpResult> {
    let mut parser = BerReader::new(bytes);
    let message = parser.read_tlv(SEQUENCE_TAG)?;
    let mut message = BerReader::new(message);

    let version = message.read_integer()?;
    if version != 0 {
        return None;
    }

    let _community = message.read_octet_string()?;
    let pdu = message.read_tlv(RESPONSE_PDU_TAG)?;
    let mut pdu = BerReader::new(pdu);

    if pdu.read_integer()? != expected_request_id {
        return None;
    }

    if pdu.read_integer()? != 0 || pdu.read_integer()? != 0 {
        return None;
    }

    let varbind_list = pdu.read_tlv(SEQUENCE_TAG)?;
    let mut varbinds = BerReader::new(varbind_list);
    let mut result = SnmpResult {
        sys_descr: None,
        sys_name: None,
    };

    while !varbinds.is_empty() {
        let varbind = varbinds.read_tlv(SEQUENCE_TAG)?;
        let mut varbind = BerReader::new(varbind);
        let oid = varbind.read_oid()?;
        let value = varbind.read_value_as_string()?;

        if oid == SYS_DESCR_OID {
            result.sys_descr = value;
        } else if oid == SYS_NAME_OID {
            result.sys_name = value;
        }
    }

    Some(result)
}

struct BerReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> BerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn is_empty(&self) -> bool {
        self.cursor >= self.bytes.len()
    }

    fn read_tlv(&mut self, expected_tag: u8) -> Option<&'a [u8]> {
        let tag = *self.bytes.get(self.cursor)?;
        if tag != expected_tag {
            return None;
        }
        self.cursor += 1;
        let len = self.read_length()?;
        let start = self.cursor;
        let end = start.checked_add(len)?;
        let content = self.bytes.get(start..end)?;
        self.cursor = end;
        Some(content)
    }

    fn read_length(&mut self) -> Option<usize> {
        let first = *self.bytes.get(self.cursor)?;
        self.cursor += 1;
        if first & 0x80 == 0 {
            return Some(first as usize);
        }

        let count = (first & 0x7f) as usize;
        if count == 0 {
            return None;
        }

        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | (*self.bytes.get(self.cursor)? as usize);
            self.cursor += 1;
        }
        Some(len)
    }

    fn read_integer(&mut self) -> Option<i32> {
        let bytes = self.read_tlv(INTEGER_TAG)?;
        if bytes.is_empty() || bytes.len() > 4 {
            return None;
        }

        let negative = bytes[0] & 0x80 != 0;
        let mut value = if negative { -1i32 } else { 0i32 };
        for byte in bytes {
            value = (value << 8) | i32::from(*byte);
        }
        Some(value)
    }

    fn read_octet_string(&mut self) -> Option<&'a [u8]> {
        self.read_tlv(OCTET_STRING_TAG)
    }

    fn read_oid(&mut self) -> Option<&'a [u8]> {
        self.read_tlv(OBJECT_IDENTIFIER_TAG)
    }

    fn read_value_as_string(&mut self) -> Option<Option<String>> {
        let tag = *self.bytes.get(self.cursor)?;
        match tag {
            OCTET_STRING_TAG => {
                let value = self.read_octet_string()?;
                Some(Some(String::from_utf8_lossy(value).trim().to_string()))
            }
            NULL_TAG => {
                let _ = self.read_tlv(NULL_TAG)?;
                Some(None)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SYS_DESCR_OID, SYS_NAME_OID, SnmpResult, build_get_request, parse_snmp_response};

    #[test]
    fn build_get_request_encodes_expected_bytes() {
        let packet = build_get_request(0x01020304, &[SYS_DESCR_OID, SYS_NAME_OID]);

        assert_eq!(
            packet,
            vec![
                0x30, 0x37, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x2a, 0x02, 0x04,
                0x01, 0x02, 0x03, 0x04, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x1c, 0x30, 0x0c, 0x06, 0x08, 0x2b,
                0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
                0x01, 0x01, 0x05, 0x00, 0x05, 0x00,
            ]
        );
    }

    #[test]
    fn parse_snmp_response_extracts_sysdescr_and_sysname() {
        let response = vec![
            0x30, 0x40, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x33, 0x02, 0x04, 0x01,
            0x02, 0x03, 0x04, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x25, 0x30, 0x13, 0x06, 0x08, 0x2b, 0x06, 0x01,
            0x02, 0x01, 0x01, 0x01, 0x00, 0x04, 0x07, b'R', b'o', b'u', b't', b'e', b'r', b'X', 0x30, 0x0e, 0x06, 0x08,
            0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x04, 0x02, b'g', b'w',
        ];

        let parsed = parse_snmp_response(&response, 0x01020304);

        assert_eq!(
            parsed,
            Some(SnmpResult {
                sys_descr: Some("RouterX".into()),
                sys_name: Some("gw".into()),
            })
        );
    }
}
