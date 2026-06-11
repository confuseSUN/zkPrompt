const AEAD_TAG_LEN: usize = 16;

/// Drain complete TLS records from `pending` and return concatenated
/// application-data (0x17) ciphertext (Poly1305 tag stripped per record).
/// Incomplete trailing bytes stay in `pending`.
pub fn drain_application_data(pending: &mut Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offset = 0;

    // TLS record header is 5 bytes: type(1) + version(2) + length(2)

    while offset + 5 <= pending.len() {
        let record_type = pending[offset];
        let length = u16::from_be_bytes([pending[offset + 3], pending[offset + 4]]) as usize;
        let record_end = offset + 5 + length;
        if record_end > pending.len() {
            break;
        }

        if record_type == 0x17 && pending[4] != 53 {
            let payload = &pending[offset + 5..record_end];
            if payload.len() >= AEAD_TAG_LEN {
                out.extend_from_slice(&payload[..payload.len() - AEAD_TAG_LEN]);
            }
        }

        offset = record_end;
    }

    if offset > 0 {
        pending.drain(..offset);
    }

    out
}

#[cfg(test)]
mod test {
    use super::drain_application_data;

    fn tls_record(record_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = vec![record_type, 0x03, 0x03];
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn app_record(ciphertext: &[u8]) -> Vec<u8> {
        let mut payload = Vec::from(ciphertext);
        payload.extend_from_slice(&[0xAA; super::AEAD_TAG_LEN]);
        tls_record(0x17, &payload)
    }

    #[test]
    fn extracts_only_application_data() {
        let mut pending = tls_record(0x16, b"handshake");
        pending.extend(app_record(b"app-one"));
        pending.extend(app_record(b"app-two"));

        let app_data = drain_application_data(&mut pending);
        assert_eq!(app_data, b"app-oneapp-two");
        assert!(pending.is_empty());
    }

    #[test]
    fn strips_aead_tag_per_record() {
        let mut pending = app_record(b"first");
        pending.extend(app_record(b"second"));

        let app_data = drain_application_data(&mut pending);
        assert_eq!(app_data, b"firstsecond");
    }

    #[test]
    fn keeps_incomplete_record_in_pending() {
        let mut pending = app_record(b"complete");
        pending.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02]);

        let app_data = drain_application_data(&mut pending);
        assert_eq!(app_data, b"complete");
        assert_eq!(pending, &[0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02]);
    }
}
