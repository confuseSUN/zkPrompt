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
