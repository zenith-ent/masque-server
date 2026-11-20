//! Synthetic ECH material and a ClientHello hook for the local test clients.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::ex_data::Index;
use boring::pkey::{PKey, Private};
use boring::ssl::{SslContext, SslContextBuilder, SslRef};
use boring::x509::{X509, extension::SubjectAlternativeName};
use foreign_types::ForeignTypeRef as _;

pub const INNER_NAME: &str = "proxy.example.test";
pub const OUTER_NAME: &str = "public.example.test";

pub fn certificate(key: &PKey<Private>, template: &X509, include_public_name: bool) -> X509 {
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(template.serial_number()).unwrap();
    builder.set_subject_name(template.subject_name()).unwrap();
    builder.set_issuer_name(template.issuer_name()).unwrap();
    builder.set_not_before(template.not_before()).unwrap();
    builder.set_not_after(template.not_after()).unwrap();
    builder.set_pubkey(key).unwrap();
    let mut names = SubjectAlternativeName::new();
    names.dns(INNER_NAME);
    if include_public_name {
        names.dns(OUTER_NAME);
    }
    let extension = names.build(&builder.x509v3_context(None, None)).unwrap();
    builder.append_extension(extension).unwrap();
    builder
        .sign(key, boring::hash::MessageDigest::sha256())
        .unwrap();
    builder.build()
}

pub fn write_bundle(path: &Path, id: u8) -> Vec<u8> {
    // PKCS#8 header and an independently generated X25519 scalar.
    let mut der = vec![
        0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 4, 0x22, 4, 0x20,
    ];
    der.extend_from_slice(
        &ring::rand::generate::<[u8; 32]>(&ring::rand::SystemRandom::new())
            .unwrap()
            .expose(),
    );
    let key = PKey::private_key_from_pkcs8(&der).unwrap();
    let mut public = [0; 32];
    key.raw_public_key(&mut public).unwrap();

    let mut config = vec![id, 0, 0x20, 0, 32];
    config.extend_from_slice(&public);
    config.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0]); // HKDF-SHA256, AES-128-GCM, no name padding.
    config.push(OUTER_NAME.len() as u8);
    config.extend_from_slice(OUTER_NAME.as_bytes());
    config.extend_from_slice(&[0, 0]); // No extensions.
    let mut list = Vec::new();
    list.extend_from_slice(&((config.len() + 4) as u16).to_be_bytes());
    list.extend_from_slice(&0xfe0du16.to_be_bytes());
    list.extend_from_slice(&(config.len() as u16).to_be_bytes());
    list.extend(&config);

    std::fs::write(
        path,
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n-----BEGIN ECHCONFIG-----\n{}\n-----END ECHCONFIG-----\n",
            STANDARD.encode(der),
            STANDARD.encode(&list)
        )
    ).unwrap();
    list
}

struct EchClient {
    list: Vec<u8>,
    accepted: Arc<AtomicBool>,
}

static CLIENT_ECH: LazyLock<Index<SslContext, EchClient>> =
    LazyLock::new(|| SslContext::new_ex_index().expect("failed to allocate ECH test index"));

pub fn configure_client(builder: &mut SslContextBuilder, list: &[u8]) -> Arc<AtomicBool> {
    let accepted = Arc::new(AtomicBool::new(false));
    builder.replace_ex_data(
        *CLIENT_ECH,
        EchClient {
            list: list.to_vec(),
            accepted: Arc::clone(&accepted),
        },
    );
    // SAFETY: the builder owns a live context and this callback receives SSL
    // objects owned by that context for the duration of each call.
    unsafe { boring_sys::SSL_CTX_set_info_callback(builder.as_ptr(), Some(ech_info)) };
    accepted
}

unsafe extern "C" fn ech_info(ssl: *const boring_sys::SSL, event: i32, _ret: i32) {
    // SAFETY: the callback references a live SSL. The SSL owns a reference to
    // its SslContext, whose ex-data holds the list through the callback.
    let ssl = unsafe { SslRef::from_ptr(ssl.cast_mut()) };
    let Some(ech) = ssl.ssl_context().ex_data(*CLIENT_ECH) else {
        return;
    };
    if event == boring_sys::SSL_CB_HANDSHAKE_START {
        // SAFETY: this runs immediately before the client constructs ClientHello.
        // BoringSSL copies the list before the call returns.
        unsafe {
            boring_sys::SSL_set1_ech_config_list(ssl.as_ptr(), ech.list.as_ptr(), ech.list.len())
        };
    } else if event == boring_sys::SSL_CB_HANDSHAKE_DONE {
        // SAFETY: the completed handshake's SSL is still live.
        let accepted = unsafe { boring_sys::SSL_ech_accepted(ssl.as_ptr()) } == 1;
        ech.accepted.store(accepted, Ordering::Relaxed);
    }
}
