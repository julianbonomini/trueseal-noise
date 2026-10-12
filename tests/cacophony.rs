/// Cacophony spec-vector conformance tests.
///
/// Verifies that trueseal-noise (via snow) produces byte-exact ciphertext for every
/// Noise_NK and Noise_XX vector in testdata/cacophony.json. The vectors fix
/// both static and ephemeral keys so outputs are fully deterministic.
use serde::Deserialize;
use std::path::PathBuf;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Suite {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    protocol_name: String,
    init_prologue: String,
    /// Only present for XX (initiator has a static key).
    init_static: Option<String>,
    init_ephemeral: String,
    /// Only present for NK (initiator knows responder's static public key).
    init_remote_static: Option<String>,
    resp_prologue: String,
    resp_static: String,
    resp_ephemeral: String,
    handshake_hash: String,
    messages: Vec<Message>,
}

#[derive(Deserialize)]
struct Message {
    payload: String,
    ciphertext: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_suite() -> Suite {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("testdata/cacophony.json");
    let raw = std::fs::read_to_string(&path).expect("testdata/cacophony.json not found");
    serde_json::from_str(&raw).expect("failed to parse cacophony.json")
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|_| panic!("bad hex in test vector: {s}"))
}

/// Number of handshake-phase messages for a given protocol name.
fn hs_msg_count(protocol_name: &str) -> usize {
    if protocol_name.contains("_NK_") {
        2
    } else {
        3
    }
}

// ── Core runner ───────────────────────────────────────────────────────────────

fn run_vector(v: &Vector) {
    let proto: snow::params::NoiseParams = v
        .protocol_name
        .parse()
        .unwrap_or_else(|_| panic!("unknown protocol: {}", v.protocol_name));

    // Pre-bind all byte slices so they live long enough for the builder.
    let init_prologue_bytes = h(&v.init_prologue);
    let init_ephemeral_bytes = h(&v.init_ephemeral);
    let init_static_bytes = v.init_static.as_deref().map(h);
    let init_remote_static_bytes = v.init_remote_static.as_deref().map(h);
    let resp_prologue_bytes = h(&v.resp_prologue);
    let resp_static_bytes = h(&v.resp_static);
    let resp_ephemeral_bytes = h(&v.resp_ephemeral);

    // ── Build initiator ──────────────────────────────────────────────────────
    let mut init_b = snow::Builder::new(proto.clone())
        .prologue(&init_prologue_bytes)
        .expect("init prologue")
        .fixed_ephemeral_key_for_testing_only(&init_ephemeral_bytes);

    if let Some(ref s) = init_static_bytes {
        init_b = init_b.local_private_key(s).expect("init static key");
    }
    if let Some(ref rs) = init_remote_static_bytes {
        init_b = init_b.remote_public_key(rs).expect("init remote static");
    }
    let mut init_hs = init_b.build_initiator().expect("build initiator");

    // ── Build responder ──────────────────────────────────────────────────────
    let mut resp_hs = snow::Builder::new(proto)
        .prologue(&resp_prologue_bytes)
        .expect("resp prologue")
        .local_private_key(&resp_static_bytes)
        .expect("resp static key")
        .fixed_ephemeral_key_for_testing_only(&resp_ephemeral_bytes)
        .build_responder()
        .expect("build responder");

    // ── Handshake phase ──────────────────────────────────────────────────────
    let n_hs = hs_msg_count(&v.protocol_name);
    let mut buf = vec![0u8; 65535];

    for (i, msg) in v.messages[..n_hs].iter().enumerate() {
        let payload = h(&msg.payload);
        let expected_ct = h(&msg.ciphertext);
        let init_sends = i % 2 == 0;

        if init_sends {
            let len = init_hs
                .write_message(&payload, &mut buf)
                .unwrap_or_else(|e| panic!("[{}] init write hs msg {i}: {e:?}", v.protocol_name));
            assert_eq!(
                &buf[..len],
                expected_ct.as_slice(),
                "[{}] handshake msg {i} ciphertext mismatch",
                v.protocol_name
            );
            let mut tmp = vec![0u8; 65535];
            resp_hs
                .read_message(&buf[..len], &mut tmp)
                .unwrap_or_else(|e| panic!("[{}] resp read hs msg {i}: {e:?}", v.protocol_name));
        } else {
            let len = resp_hs
                .write_message(&payload, &mut buf)
                .unwrap_or_else(|e| panic!("[{}] resp write hs msg {i}: {e:?}", v.protocol_name));
            assert_eq!(
                &buf[..len],
                expected_ct.as_slice(),
                "[{}] handshake msg {i} ciphertext mismatch",
                v.protocol_name
            );
            let mut tmp = vec![0u8; 65535];
            init_hs
                .read_message(&buf[..len], &mut tmp)
                .unwrap_or_else(|e| panic!("[{}] init read hs msg {i}: {e:?}", v.protocol_name));
        }
    }

    // Verify handshake hash before consuming the HandshakeStates.
    let expected_hash = h(&v.handshake_hash);
    assert_eq!(
        init_hs.get_handshake_hash(),
        expected_hash.as_slice(),
        "[{}] handshake_hash mismatch (init side)",
        v.protocol_name
    );
    assert_eq!(
        resp_hs.get_handshake_hash(),
        expected_hash.as_slice(),
        "[{}] handshake_hash mismatch (resp side)",
        v.protocol_name
    );

    // Transition to transport mode.
    let mut init_t = init_hs
        .into_transport_mode()
        .expect("init into_transport_mode");
    let mut resp_t = resp_hs
        .into_transport_mode()
        .expect("resp into_transport_mode");

    // ── Transport phase ──────────────────────────────────────────────────────
    //
    // Convention: the party that *received* the last handshake message sends
    // the first transport message.
    // NK  (n_hs=2, last hs msg sent by resp → init received it) → init sends first.
    // XX  (n_hs=3, last hs msg sent by init → resp received it) → resp sends first.
    let resp_sends_first = (n_hs - 1).is_multiple_of(2); // last hs sender is init ↔ resp sends first

    for (t_idx, msg) in v.messages[n_hs..].iter().enumerate() {
        let payload = h(&msg.payload);
        let expected_ct = h(&msg.ciphertext);
        // With resp_sends_first, odd t_idx = init sends; even = resp sends.
        let init_sends = if resp_sends_first {
            t_idx % 2 != 0
        } else {
            t_idx % 2 == 0
        };

        if init_sends {
            let len = init_t
                .write_message(&payload, &mut buf)
                .unwrap_or_else(|e| {
                    panic!(
                        "[{}] init write transport msg {t_idx}: {e:?}",
                        v.protocol_name
                    )
                });
            assert_eq!(
                &buf[..len],
                expected_ct.as_slice(),
                "[{}] transport msg {t_idx} ciphertext mismatch",
                v.protocol_name
            );
            let mut pt = vec![0u8; 65535];
            let pt_len = resp_t
                .read_message(&buf[..len], &mut pt)
                .unwrap_or_else(|e| {
                    panic!(
                        "[{}] resp read transport msg {t_idx}: {e:?}",
                        v.protocol_name
                    )
                });
            assert_eq!(
                &pt[..pt_len],
                payload.as_slice(),
                "[{}] transport msg {t_idx} plaintext mismatch",
                v.protocol_name
            );
        } else {
            let len = resp_t
                .write_message(&payload, &mut buf)
                .unwrap_or_else(|e| {
                    panic!(
                        "[{}] resp write transport msg {t_idx}: {e:?}",
                        v.protocol_name
                    )
                });
            assert_eq!(
                &buf[..len],
                expected_ct.as_slice(),
                "[{}] transport msg {t_idx} ciphertext mismatch",
                v.protocol_name
            );
            let mut pt = vec![0u8; 65535];
            let pt_len = init_t
                .read_message(&buf[..len], &mut pt)
                .unwrap_or_else(|e| {
                    panic!(
                        "[{}] init read transport msg {t_idx}: {e:?}",
                        v.protocol_name
                    )
                });
            assert_eq!(
                &pt[..pt_len],
                payload.as_slice(),
                "[{}] transport msg {t_idx} plaintext mismatch",
                v.protocol_name
            );
        }
    }
}

// ── Test entry point ──────────────────────────────────────────────────────────

#[test]
fn cacophony_noise_nk_and_xx_spec_vectors() {
    let suite = load_suite();
    assert!(
        !suite.vectors.is_empty(),
        "cacophony.json loaded zero vectors"
    );
    for v in &suite.vectors {
        run_vector(v);
    }
}
