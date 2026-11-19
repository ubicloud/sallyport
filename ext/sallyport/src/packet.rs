//! The tunnel reads these things from an IP packet that carries TCP.

use std::net::{IpAddr, SocketAddr};

/// Returns where the TCP header starts in an IP packet. A later fragment
/// has no TCP header. Of the extension headers of IPv6, smoltcp looks
/// behind one hop-by-hop header and behind no other, and so does this.
fn tcp_offset(p: &[u8]) -> Option<usize> {
    match p.first()? >> 4 {
        4 => {
            let header = ((p[0] & 15) as usize) * 4;
            let fragment = u16::from_be_bytes([*p.get(6)?, *p.get(7)?]) & 0x1fff;
            (header >= 20 && *p.get(9)? == 6 && fragment == 0).then_some(header)
        }
        6 => match *p.get(6)? {
            6 => Some(40),
            0 => {
                let header = (usize::from(*p.get(41)?) + 1) * 8;
                (*p.get(40)? == 6).then_some(40 + header)
            }
            _ => None,
        },
        _ => None,
    }
}

/// Returns the TCP segment of an IP packet, if it holds a whole header.
fn tcp(p: &[u8]) -> Option<&[u8]> {
    let t = p.get(tcp_offset(p)?..)?;
    let header = ((*t.get(12)? >> 4) as usize) * 4;
    (header >= 20 && t.len() >= header).then_some(t)
}

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// Returns the source and the destination address of an IP packet.
fn addrs(p: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let v4 = |at: usize| Some(IpAddr::from(<[u8; 4]>::try_from(p.get(at..at + 4)?).ok()?));
    let v6 = |at: usize| Some(IpAddr::from(<[u8; 16]>::try_from(p.get(at..at + 16)?).ok()?));
    match p.first()? >> 4 {
        4 => Some((v4(12)?, v4(16)?)),
        _ => Some((v6(8)?, v6(24)?)),
    }
}

/// Returns where a TCP packet comes from, and where it goes.
pub fn ends(p: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let t = tcp(p)?;
    let (from, to) = addrs(p)?;
    let port = |at: usize| u16::from_be_bytes([t[at], t[at + 1]]);
    Some((SocketAddr::new(from, port(0)), SocketAddr::new(to, port(2))))
}

/// Returns the ends of a packet that opens a connection.
pub fn syn(p: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    ends(p).filter(|_| tcp(p).is_some_and(|t| t[13] & (SYN | ACK) == SYN))
}

/// Says whether a packet resets a TCP connection.
pub fn rst(p: &[u8]) -> bool {
    tcp(p).is_some_and(|t| t[13] & RST != 0)
}

const NOP: u8 = 1;
const SACK_PERMITTED: u8 = 4;
const SACK: u8 = 5;

/// Calls `f` with the kind of each TCP option that has a length, where
/// the option starts in the segment, and how long it is. An option that
/// is malformed ends the walk.
fn options(t: &[u8], mut f: impl FnMut(u8, usize, usize)) {
    let end = ((t[12] >> 4) as usize) * 4;
    let mut i = 20;
    while i < end {
        match t[i] {
            // These two are the end of the options and a byte of padding.
            0 => break,
            NOP => i += 1,
            kind => {
                let Some(&len) = t.get(i + 1) else { break };
                let len = len as usize;
                if len < 2 || i + len > end {
                    break;
                }
                f(kind, i, len);
                i += len;
            }
        }
    }
}

/// Returns a checksum corrected for a 16-bit word of what it covers that
/// was `old` and is `new`, as RFC 1624 has it: HC' = ~(~HC + ~m + m').
fn corrected(sum: u16, old: u16, new: u16) -> u16 {
    let mut x = u32::from(!sum) + u32::from(!old) + u32::from(new);
    x = (x & 0xffff) + (x >> 16);
    x = (x & 0xffff) + (x >> 16);
    !(x as u16)
}

/// Takes the offer of selective acknowledgement out of a SYN or a
/// SYN-ACK, and corrects the checksum. Padding takes the offer's place.
pub fn without_sack(p: &mut [u8]) {
    let Some(at) = tcp_offset(p) else { return };
    let Some(t) = tcp(p) else { return };
    if t[13] & SYN == 0 {
        return;
    }
    let mut offers = Vec::new();
    options(t, |kind, i, len| {
        if kind == SACK_PERMITTED && len == 2 {
            offers.push(i);
        }
    });
    let t = &mut p[at..];
    for i in offers {
        for j in [i, i + 1] {
            // The checksum is corrected for the 16-bit word that the byte
            // is in.
            let word = j & !1;
            let old = u16::from_be_bytes([t[word], t[word + 1]]);
            t[j] = NOP;
            let new = u16::from_be_bytes([t[word], t[word + 1]]);
            let sum = u16::from_be_bytes([t[16], t[17]]);
            t[16..18].copy_from_slice(&corrected(sum, old, new).to_be_bytes());
        }
    }
}

/// Takes the FIN off a segment that has data too, and returns a packet
/// that has the FIN and no data, at the place in the stream where the
/// data ends. A peer may send the two packets in place of the one, as
/// this library does. Each checksum is corrected and not worked out
/// afresh, so a packet that arrived damaged makes two that are damaged.
/// Any other packet is left as it is.
pub fn split_fin(p: &mut [u8]) -> Option<Vec<u8>> {
    let at = tcp_offset(p)?;
    let t = tcp(p)?;
    let word = |b: &[u8], i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    let header = ((t[12] >> 4) as usize) * 4;
    // The data is known to end where the packet ends only if the IP
    // header gives the packet's length as it is, and if no more of the
    // segment follows in another fragment.
    let whole = match p[0] >> 4 {
        4 => usize::from(word(p, 2)) == p.len() && p[6] & 0x20 == 0,
        _ => usize::from(word(p, 4)) + 40 == p.len(),
    };
    if !whole || t.len() == header || t[13] & (FIN | SYN | RST) != FIN {
        return None;
    }
    // The packet of the FIN has the headers of the segment. Its checksum
    // is that of the segment, corrected for the data that it does not
    // have, for its length, and for its sequence number, which is the one
    // that follows the data.
    let mut fin = p[..at + header].to_vec();
    let mut sum = word(t, 16);
    for pair in t[header..].chunks(2) {
        sum = corrected(sum, u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]), 0);
    }
    sum = corrected(sum, t.len() as u16, header as u16);
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]).wrapping_add((t.len() - header) as u32);
    sum = corrected(sum, word(t, 4), (seq >> 16) as u16);
    sum = corrected(sum, word(t, 6), seq as u16);
    fin[at + 4..at + 8].copy_from_slice(&seq.to_be_bytes());
    fin[at + 16..at + 18].copy_from_slice(&sum.to_be_bytes());
    // The IP header gives the length of the packet, and that of IPv4 has
    // a checksum of its own.
    if p[0] >> 4 == 4 {
        let total = fin.len() as u16;
        let sum = corrected(word(p, 10), word(p, 2), total);
        fin[2..4].copy_from_slice(&total.to_be_bytes());
        fin[10..12].copy_from_slice(&sum.to_be_bytes());
    } else {
        let payload = (fin.len() - 40) as u16;
        fin[4..6].copy_from_slice(&payload.to_be_bytes());
    }
    let sum = corrected(word(t, 16), word(t, 12), word(t, 12) & !u16::from(FIN));
    p[at + 13] &= !FIN;
    p[at + 16..at + 18].copy_from_slice(&sum.to_be_bytes());
    Some(fin)
}

/// Describes a TCP packet in one line, much as tcpdump would: its ports,
/// its flags with a dot for ACK, and its numbers.
pub fn describe(p: &[u8]) -> Option<String> {
    let t = tcp(p)?;
    let word = |i: usize| u32::from_be_bytes([t[i], t[i + 1], t[i + 2], t[i + 3]]);
    let flags: String = [(SYN, 'S'), (0x01, 'F'), (0x04, 'R'), (0x08, 'P'), (ACK, '.')]
        .iter()
        .filter(|(bit, _)| t[13] & bit != 0)
        .map(|(_, letter)| *letter)
        .collect();
    let header = ((t[12] >> 4) as usize) * 4;
    let mut line = format!(
        "{}>{} {flags} seq {} ack {} win {} len {}",
        u16::from_be_bytes([t[0], t[1]]),
        u16::from_be_bytes([t[2], t[3]]),
        word(4),
        word(8),
        u16::from_be_bytes([t[14], t[15]]),
        t.len() - header
    );
    options(t, |kind, i, len| {
        if kind == SACK {
            for block in t[i + 2..i + len].as_chunks::<8>().0 {
                let edge = |k: usize| u32::from_be_bytes([block[k], block[k + 1], block[k + 2], block[k + 3]]);
                line += &format!(" sack {}-{}", edge(0), edge(4));
            }
        }
    });
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sums 16-bit words as a checksum does.
    fn sum(data: &[u8], mut acc: u32) -> u32 {
        for pair in data.chunks(2) {
            acc += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
        acc
    }

    /// Computes the TCP checksum of an IP packet from nothing, with the
    /// checksum's field taken as zero.
    fn checksum(p: &[u8]) -> u16 {
        let t = &p[tcp_offset(p).unwrap()..];
        let mut acc = if p[0] >> 4 == 4 { sum(&p[12..20], 0) } else { sum(&p[8..40], 0) };
        acc += 6 + t.len() as u32;
        acc = sum(&t[..16], acc);
        acc = sum(&t[18..], acc);
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        !(acc as u16)
    }

    /// Builds an IP packet around a TCP segment from port 51000 to port
    /// 7000 that has these flags, options and payload, and checksums
    /// that are right.
    fn packet(version: u8, flags: u8, opts: &[u8], payload: &[u8]) -> Vec<u8> {
        packet_at(0x0102_0304, version, flags, opts, payload)
    }

    /// Builds the same packet with a sequence number of its own.
    fn packet_at(seq: u32, version: u8, flags: u8, opts: &[u8], payload: &[u8]) -> Vec<u8> {
        assert_eq!(opts.len() % 4, 0);
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&51000u16.to_be_bytes());
        t[2..4].copy_from_slice(&7000u16.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&0x0a0b_0c0du32.to_be_bytes());
        t[12] = ((20 + opts.len()) as u8 / 4) << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&4096u16.to_be_bytes());
        t.extend_from_slice(opts);
        t.extend_from_slice(payload);
        let mut p = if version == 4 {
            let mut h = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 9, 0, 1, 10, 9, 0, 2];
            h[2..4].copy_from_slice(&((20 + t.len()) as u16).to_be_bytes());
            // The header has a checksum of its own.
            let mut acc = sum(&h, 0);
            while acc >> 16 != 0 {
                acc = (acc & 0xffff) + (acc >> 16);
            }
            h[10..12].copy_from_slice(&(!(acc as u16)).to_be_bytes());
            h
        } else {
            let mut h = vec![0x60, 0, 0, 0, 0, 0, 6, 64];
            h[4..6].copy_from_slice(&(t.len() as u16).to_be_bytes());
            h.extend_from_slice(&[0xfd, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            h.extend_from_slice(&[0xfd, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
            h
        };
        p.extend_from_slice(&t);
        let at = p.len() - t.len();
        let right = checksum(&p);
        p[at + 16..at + 18].copy_from_slice(&right.to_be_bytes());
        p
    }

    const MSS: [u8; 4] = [2, 4, 5, 0x50];

    /// Puts a hop-by-hop header before the TCP header of an IPv6 packet.
    /// It is 8 bytes long, and has one option of padding.
    fn behind_hop_by_hop(mut p: Vec<u8>) -> Vec<u8> {
        assert_eq!((p[0] >> 4, p[6]), (6, 6));
        p[6] = 0;
        let length = u16::from_be_bytes([p[4], p[5]]) + 8;
        p[4..6].copy_from_slice(&length.to_be_bytes());
        p.splice(40..40, [6, 0, 1, 4, 0, 0, 0, 0]);
        p
    }

    #[test]
    fn a_syn_names_both_its_ends() {
        let ends = [(4, "10.9.0.1:51000", "10.9.0.2:7000"), (6, "[fd09::1]:51000", "[fd09::2]:7000")];
        for (version, from, to) in ends {
            let both = Some((from.parse().unwrap(), to.parse().unwrap()));
            assert_eq!(syn(&packet(version, SYN, &MSS, &[])), both);
            assert_eq!(syn(&packet(version, SYN, &[], &[])), both);
            assert_eq!(syn(&packet(version, SYN | ACK, &MSS, &[])), None);
            assert_eq!(syn(&packet(version, ACK, &[], b"data")), None);
            if version == 6 {
                assert_eq!(syn(&behind_hop_by_hop(packet(version, SYN, &MSS, &[]))), both);
            }
        }
    }

    #[test]
    fn a_reset_is_told_from_other_packets() {
        for version in [4, 6] {
            assert!(rst(&packet(version, RST | ACK, &[], &[])));
            assert!(rst(&packet(version, RST, &[], &[])));
            assert!(!rst(&packet(version, SYN, &MSS, &[])));
            assert!(!rst(&packet(version, ACK, &[], b"data")));
        }
        assert!(!rst(&[]));
    }

    #[test]
    fn what_is_not_a_whole_tcp_header_is_not_a_syn() {
        let whole = packet(4, SYN, &MSS, &[]);
        assert_eq!(syn(&whole[..43]), None, "the options are cut short");
        assert_eq!(syn(&whole[..30]), None);
        assert_eq!(syn(&whole[..8]), None);
        assert_eq!(syn(&[]), None);
        let mut udp = whole.clone();
        udp[9] = 17;
        assert_eq!(syn(&udp), None);
        // A later fragment has bytes of the stream where the header would
        // be.
        let mut fragment = whole.clone();
        fragment[7] = 1;
        assert_eq!(syn(&fragment), None);
        let mut short = whole;
        short[20 + 12] = 4 << 4;
        assert_eq!(syn(&short), None, "the header claims 16 bytes");
        // An extension header that smoltcp does not look behind comes
        // before the TCP header.
        let mut extended = packet(6, SYN, &MSS, &[]);
        extended[6] = 60;
        assert_eq!(syn(&extended), None);
        // A hop-by-hop header gives a length that the packet does not
        // have, or something other than TCP follows it.
        let mut long = behind_hop_by_hop(packet(6, SYN, &MSS, &[]));
        long[41] = 200;
        assert_eq!(syn(&long), None);
        let mut udp = behind_hop_by_hop(packet(6, SYN, &MSS, &[]));
        udp[40] = 17;
        assert_eq!(syn(&udp), None);
    }

    #[test]
    fn a_packet_is_described_much_as_tcpdump_would() {
        let acked = packet(4, ACK | 0x08, &[1, 1, 5, 10, 0, 0, 0, 100, 0, 0, 0, 200], b"abc");
        assert_eq!(describe(&acked).unwrap(), "51000>7000 P. seq 16909060 ack 168496141 win 4096 len 3 sack 100-200");
        assert_eq!(
            describe(&packet(6, SYN, &MSS, &[])).unwrap(),
            "51000>7000 S seq 16909060 ack 168496141 win 4096 len 0"
        );
        assert_eq!(
            describe(&packet(4, 0x04 | ACK, &[], &[])).unwrap(),
            "51000>7000 R. seq 16909060 ack 168496141 win 4096 len 0"
        );
        assert_eq!(describe(&acked[..25]), None);
        // An option that claims more than the header holds ends the walk.
        let cut = packet(4, ACK, &[5, 18, 0, 0, 0, 100, 0, 0, 0, 200, 1, 1], &[]);
        assert_eq!(describe(&cut).unwrap(), "51000>7000 . seq 16909060 ack 168496141 win 4096 len 0");
    }

    const OFFER: [u8; 2] = [SACK_PERMITTED, 2];

    #[test]
    fn the_offer_goes_and_the_checksum_holds() {
        // The offer starts on an even byte, on an odd one, and at the end.
        let layouts: [&[u8]; 4] = [
            &[2, 4, 5, 0x50, 4, 2, 1, 1],
            &[2, 4, 5, 0x50, 1, 4, 2, 1],
            &[1, 1, 4, 2],
            &[2, 4, 5, 0x50, 1, 3, 3, 7, 1, 1, 4, 2],
        ];
        for version in [4, 6] {
            for flags in [SYN, SYN | ACK] {
                for opts in layouts {
                    let before = packet(version, flags, opts, &[]);
                    let mut after = before.clone();
                    without_sack(&mut after);
                    let at = tcp_offset(&after).unwrap();
                    assert_eq!(u16::from_be_bytes([after[at + 16], after[at + 17]]), checksum(&after));
                    let changed: Vec<usize> = (0..before.len()).filter(|&i| before[i] != after[i]).collect();
                    let offer = at + 20 + opts.windows(2).position(|w| w == OFFER).unwrap();
                    assert!(changed.contains(&offer) && changed.contains(&(offer + 1)));
                    assert!(changed.iter().all(|i| [offer, offer + 1, at + 16, at + 17].contains(i)));
                    assert_eq!(after[offer..offer + 2], [NOP, NOP]);
                }
            }
        }
        // The offer behind a hop-by-hop header goes too.
        let mut after = behind_hop_by_hop(packet(6, SYN, layouts[0], &[]));
        without_sack(&mut after);
        let at = tcp_offset(&after).unwrap();
        assert_eq!(at, 48);
        assert_eq!(u16::from_be_bytes([after[at + 16], after[at + 17]]), checksum(&after));
        assert!(!after[at + 20..].windows(2).any(|w| w == OFFER));
    }

    #[test]
    fn the_checksum_holds_at_its_extremes() {
        // The payload is varied until the checksum has been every value
        // near 0x0000 and 0xffff that 16 bits of payload can make it.
        let mut seen = 0;
        for v in 0..=u16::MAX {
            let before = packet(4, SYN, &[2, 4, 5, 0x50, 4, 2, 1, 1], &v.to_be_bytes());
            let was = u16::from_be_bytes([before[36], before[37]]);
            if was > 2 && was < 0xfffd {
                continue;
            }
            seen += 1;
            let mut after = before;
            without_sack(&mut after);
            let (got, want) = (u16::from_be_bytes([after[36], after[37]]), checksum(&after));
            // 0x0000 and 0xffff are the same sum in ones' complement.
            assert!(got == want || (got == 0xffff && want == 0) || (got == 0 && want == 0xffff));
        }
        assert!(seen >= 4);
    }

    const PSH: u8 = 0x08;

    #[test]
    fn a_fin_with_data_becomes_the_data_and_then_the_fin() {
        // The second set of options is a timestamp.
        let layouts: [&[u8]; 2] = [&[], &[1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9]];
        for version in [4, 6] {
            for opts in layouts {
                // The data is of an odd and of an even length, and the
                // sequence number that follows it has passed zero or not.
                for len in [1, 2, 699, 1380] {
                    for seq in [0x0102_0304, u32::MAX - 1] {
                        let payload: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                        let mut data = packet_at(seq, version, FIN | PSH | ACK, opts, &payload);
                        let fin = split_fin(&mut data).unwrap();
                        assert_eq!(data, packet_at(seq, version, PSH | ACK, opts, &payload));
                        assert_eq!(fin, packet_at(seq.wrapping_add(len as u32), version, FIN | PSH | ACK, opts, &[]));
                    }
                }
            }
        }
        // A hop-by-hop header stays before both.
        let mut data = behind_hop_by_hop(packet(6, FIN | ACK, &[], b"data"));
        let fin = split_fin(&mut data).unwrap();
        assert_eq!(data, behind_hop_by_hop(packet(6, ACK, &[], b"data")));
        assert_eq!(fin, behind_hop_by_hop(packet_at(0x0102_0308, 6, FIN | ACK, &[], &[])));
        // A packet that arrived with a byte changed makes two whose
        // checksums are both wrong.
        let mut data = packet(4, FIN | ACK, &[], b"data");
        *data.last_mut().unwrap() ^= 1;
        let fin = split_fin(&mut data).unwrap();
        for p in [data, fin] {
            assert_ne!(u16::from_be_bytes([p[36], p[37]]), checksum(&p));
        }
    }

    #[test]
    fn nothing_but_a_fin_with_data_is_split() {
        let mut fragment = packet(4, FIN | ACK, &[], b"data");
        fragment[6] |= 0x20;
        let mut udp = packet(4, FIN | ACK, &[], b"data");
        udp[9] = 17;
        let mut untouched = vec![
            packet(4, FIN | ACK, &[], &[]),
            packet(6, PSH | ACK, &[], b"data"),
            packet(4, SYN | FIN, &MSS, b"data"),
            packet(6, RST | FIN | ACK, &[], b"data"),
            fragment,
            udp,
        ];
        // The IP header gives a length that the packet does not have.
        for version in [4, 6] {
            let mut long = packet(version, FIN | ACK, &[], b"data");
            long.push(0);
            untouched.push(long);
        }
        for before in untouched {
            let mut after = before.clone();
            assert_eq!(split_fin(&mut after), None);
            assert_eq!(after, before);
        }
    }

    #[test]
    fn nothing_but_an_offer_in_a_syn_is_touched() {
        let untouched = [
            packet(4, ACK, &[1, 1, 4, 2], b"not a SYN"),
            packet(6, SYN, &MSS, &[]),
            // An option that claims more than the header holds ends the
            // walk before the offer.
            packet(4, SYN, &[2, 9, 5, 0x50, 4, 2, 1, 1], &[]),
        ];
        for before in untouched {
            let mut after = before.clone();
            without_sack(&mut after);
            assert_eq!(after, before);
        }
        // A header that claims more than the packet holds is no TCP
        // header, and an offer in what there is of it is left alone.
        let whole = packet(4, SYN, &[1, 4, 2, 1], &[]);
        let mut cut = whole[..whole.len() - 1].to_vec();
        without_sack(&mut cut);
        assert_eq!(cut, whole[..whole.len() - 1]);
    }
}
