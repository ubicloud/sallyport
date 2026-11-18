//! The tunnel reads these things from an IP packet that carries TCP.

use std::net::{IpAddr, SocketAddr};

/// Returns where the TCP header starts in an IP packet. A later fragment
/// has no TCP header, and an IPv6 packet with extension headers is not
/// looked into, so both count as not TCP.
fn tcp_offset(p: &[u8]) -> Option<usize> {
    match p.first()? >> 4 {
        4 => {
            let header = ((p[0] & 15) as usize) * 4;
            let fragment = u16::from_be_bytes([*p.get(6)?, *p.get(7)?]) & 0x1fff;
            (header >= 20 && *p.get(9)? == 6 && fragment == 0).then_some(header)
        }
        6 => (*p.get(6)? == 6).then_some(40),
        _ => None,
    }
}

/// Returns the TCP segment of an IP packet, if it holds a whole header.
fn tcp(p: &[u8]) -> Option<&[u8]> {
    let t = p.get(tcp_offset(p)?..)?;
    let header = ((*t.get(12)? >> 4) as usize) * 4;
    (header >= 20 && t.len() >= header).then_some(t)
}

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

/// Returns where a packet that opens a connection comes from, and where
/// it goes.
pub fn syn(p: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let t = tcp(p)?;
    let (from, to) = addrs(p)?;
    let port = |at: usize| u16::from_be_bytes([t[at], t[at + 1]]);
    (t[13] & (SYN | ACK) == SYN).then(|| (SocketAddr::new(from, port(0)), SocketAddr::new(to, port(2))))
}

/// Says whether a packet resets a TCP connection.
pub fn rst(p: &[u8]) -> bool {
    tcp(p).is_some_and(|t| t[13] & RST != 0)
}

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
            1 => i += 1,
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

    /// Builds an IP packet around a TCP segment from port 51000 to port
    /// 7000 that has these flags, options and payload.
    fn packet(version: u8, flags: u8, opts: &[u8], payload: &[u8]) -> Vec<u8> {
        assert_eq!(opts.len() % 4, 0);
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&51000u16.to_be_bytes());
        t[2..4].copy_from_slice(&7000u16.to_be_bytes());
        t[4..8].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        t[8..12].copy_from_slice(&0x0a0b_0c0du32.to_be_bytes());
        t[12] = ((20 + opts.len()) as u8 / 4) << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&4096u16.to_be_bytes());
        t.extend_from_slice(opts);
        t.extend_from_slice(payload);
        let mut p = if version == 4 {
            let mut h = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 9, 0, 1, 10, 9, 0, 2];
            h[2..4].copy_from_slice(&((20 + t.len()) as u16).to_be_bytes());
            h
        } else {
            let mut h = vec![0x60, 0, 0, 0, 0, 0, 6, 64];
            h[4..6].copy_from_slice(&(t.len() as u16).to_be_bytes());
            h.extend_from_slice(&[0xfd, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            h.extend_from_slice(&[0xfd, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
            h
        };
        p.extend_from_slice(&t);
        p
    }

    const MSS: [u8; 4] = [2, 4, 5, 0x50];

    #[test]
    fn a_syn_names_both_its_ends() {
        let ends = [(4, "10.9.0.1:51000", "10.9.0.2:7000"), (6, "[fd09::1]:51000", "[fd09::2]:7000")];
        for (version, from, to) in ends {
            let both = Some((from.parse().unwrap(), to.parse().unwrap()));
            assert_eq!(syn(&packet(version, SYN, &MSS, &[])), both);
            assert_eq!(syn(&packet(version, SYN, &[], &[])), both);
            assert_eq!(syn(&packet(version, SYN | ACK, &MSS, &[])), None);
            assert_eq!(syn(&packet(version, ACK, &[], b"data")), None);
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
        // An extension header comes before the TCP header.
        let mut extended = packet(6, SYN, &MSS, &[]);
        extended[6] = 60;
        assert_eq!(syn(&extended), None);
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
}
