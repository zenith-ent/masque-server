//! Server-side RFC 9849 keys loaded from RFC 9934 PEM bundles.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;
use std::ptr::NonNull;

use anyhow::{Context as _, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::error::ErrorStack;
use boring::pkey::{Id, PKey};
use boring::ssl::SslContextBuilder;
use boring::x509::X509Ref;
use boring::x509::verify::X509CheckFlags;
use foreign_types::ForeignTypeRef as _;
use zeroize::Zeroizing;

use crate::config::EchSection;

const ECH_VERSION: u16 = 0xfe0d;
const X25519_KEM: u16 = 0x0020;
const X25519_KEY_LEN: usize = 32;
// An ECHConfigList has a 16-bit length, plus PEM expansion and the private key.
const MAX_PEM_BYTES: u64 = 128 * 1024;
// Bound the number of configurations BoringSSL may try in a handshake.
const MAX_CONFIGS: usize = 8;

pub(super) struct EchKeys {
    server_name: String,
    active: KeyBundle,
    previous: Vec<KeyBundle>,
}

struct KeyBundle {
    private_key: Zeroizing<[u8; X25519_KEY_LEN]>,
    configs: Vec<EchConfig>,
}

struct EchConfig {
    public_name: String,
    encoded: Box<[u8]>,
}

impl EchKeys {
    pub(super) fn load(config: &EchSection) -> anyhow::Result<Self> {
        ensure!(
            valid_dns_name(&config.server_name),
            "tls.ech.server_name must be a DNS hostname"
        );
        ensure!(
            config.previous_key_files.len() < MAX_CONFIGS,
            "at most {MAX_CONFIGS} ECH configurations are supported"
        );
        let active = KeyBundle::load(&config.key_file)?;
        let previous = config
            .previous_key_files
            .iter()
            .map(|path| KeyBundle::load(path))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let count =
            active.configs.len() + previous.iter().map(|key| key.configs.len()).sum::<usize>();
        ensure!(
            count <= MAX_CONFIGS,
            "at most {MAX_CONFIGS} ECH configurations are supported"
        );
        Ok(Self {
            server_name: config.server_name.clone(),
            active,
            previous,
        })
    }

    /// Identify the effective public configs and which ones are sent on retry.
    pub(super) fn fingerprint(&self) -> [u8; 32] {
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        for (bundle, retry) in
            std::iter::once((&self.active, 1)).chain(self.previous.iter().map(|bundle| (bundle, 0)))
        {
            for config in &bundle.configs {
                digest.update(&[retry]);
                // Each encoded ECHConfig includes its own length.
                digest.update(&config.encoded);
            }
        }
        digest.finish().as_ref().try_into().unwrap()
    }

    pub(super) fn validate_certificate(&self, leaf: &X509Ref) -> anyhow::Result<()> {
        let public_names = std::iter::once(&self.active)
            .chain(&self.previous)
            .flat_map(|bundle| {
                bundle
                    .configs
                    .iter()
                    .map(|config| config.public_name.as_str())
            });
        for name in std::iter::once(self.server_name.as_str()).chain(public_names) {
            // SAFETY: the live certificate and the explicit-length host bytes
            // are borrowed for the synchronous check. No matched-name output
            // is requested or allocated.
            let matched = unsafe {
                boring_sys::X509_check_host(
                    leaf.as_ptr(),
                    name.as_ptr().cast(),
                    name.len(),
                    (X509CheckFlags::NEVER_CHECK_SUBJECT | X509CheckFlags::NO_PARTIAL_WILDCARDS)
                        .bits(),
                    std::ptr::null_mut(),
                )
            };
            ensure!(
                matched == 1,
                "TLS certificate must cover ECH name {name} in its DNS SANs"
            );
        }
        Ok(())
    }

    pub(super) fn install(&self, builder: &mut SslContextBuilder) -> anyhow::Result<()> {
        // SAFETY: the library returns ownership. Check for null before
        // creating the RAII wrapper.
        let keys = unsafe { boring_sys::SSL_ECH_KEYS_new() };
        let keys = NativeEchKeys(
            NonNull::new(keys)
                .ok_or_else(ErrorStack::get)
                .context("failed to allocate ECH key set")?,
        );
        // SAFETY: the library returns ownership. Check for null before
        // creating the RAII wrapper.
        let hpke = unsafe { boring_sys::EVP_HPKE_KEY_new() };
        let hpke = HpkeKey(
            NonNull::new(hpke)
                .ok_or_else(ErrorStack::get)
                .context("failed to allocate HPKE key")?,
        );
        for (bundle, retry) in
            std::iter::once((&self.active, 1)).chain(self.previous.iter().map(|bundle| (bundle, 0)))
        {
            // SAFETY: hpke is uniquely owned here, the KEM is library-static,
            // and initialization reads and copies the fixed-size key bytes.
            let initialized = unsafe {
                boring_sys::EVP_HPKE_KEY_init(
                    hpke.0.as_ptr(),
                    boring_sys::EVP_hpke_x25519_hkdf_sha256(),
                    bundle.private_key.as_ptr(),
                    bundle.private_key.len(),
                )
            };
            if initialized != 1 {
                return Err(ErrorStack::get()).context("failed to initialize ECH private key");
            }
            for config in &bundle.configs {
                // SAFETY: keys is still private and mutable. BoringSSL parses
                // and copies both the config bytes and the initialized key.
                let added = unsafe {
                    boring_sys::SSL_ECH_KEYS_add(
                        keys.0.as_ptr(),
                        retry,
                        config.encoded.as_ptr(),
                        config.encoded.len(),
                        hpke.0.as_ptr(),
                    )
                };
                if added != 1 {
                    return Err(ErrorStack::get()).context("invalid server ECHConfig");
                }
            }
            // SAFETY: the object is live and initialized. No config retains a
            // borrow of it. Cleanup resets it for the next key or for Drop.
            unsafe { boring_sys::EVP_HPKE_KEY_cleanup(hpke.0.as_ptr()) };
        }

        // SAFETY: both handles are live. The context takes its own reference
        // to the completed immutable key set on success.
        let installed =
            unsafe { boring_sys::SSL_CTX_set1_ech_keys(builder.as_ptr(), keys.0.as_ptr()) };
        if installed != 1 {
            return Err(ErrorStack::get()).context("failed to configure server ECH");
        }
        Ok(())
    }
}

impl KeyBundle {
    fn load(path: &Path) -> anyhow::Result<Self> {
        Self::read(path).with_context(|| format!("invalid ECH key bundle {}", path.display()))
    }

    fn read(path: &Path) -> anyhow::Result<Self> {
        let mut pem = Zeroizing::new(Vec::new());
        File::open(path)?
            .take(MAX_PEM_BYTES + 1)
            .read_to_end(&mut pem)?;
        ensure!(
            pem.len() as u64 <= MAX_PEM_BYTES,
            "ECH PEM bundle exceeds 128 KiB"
        );
        let pem = std::str::from_utf8(&pem)
            .context("ECH PEM is not UTF-8")?
            .trim_start();
        let (key_pem, rest) = pem_block(pem, "PRIVATE KEY")?;
        let key_der = decode_pem_body(key_pem)?;
        let key =
            PKey::private_key_from_pkcs8(&key_der).context("invalid ECH PKCS#8 private key")?;
        ensure!(key.id() == Id::X25519, "ECH private key must use X25519");
        let mut public_key = [0; X25519_KEY_LEN];
        let public_key = key.raw_public_key(&mut public_key)?;
        let mut private_key = Zeroizing::new([0; X25519_KEY_LEN]);
        key.raw_private_key(&mut *private_key)?;

        let (config_pem, _) = pem_block(rest.trim_start(), "ECHCONFIG")?;
        let encoded = decode_pem_body(config_pem)?;
        let (mut list, tail) = take_vector(&encoded).context("missing ECHConfigList length")?;
        ensure!(tail.is_empty(), "invalid ECHConfigList length");
        let mut configs = Vec::new();
        while !list.is_empty() {
            let (version, fields) = list
                .split_first_chunk::<2>()
                .context("truncated ECHConfig version")?;
            let (contents, next) = take_vector(fields).context("truncated ECHConfig")?;
            if u16::from_be_bytes(*version) == ECH_VERSION
                && let Some(public_name) = matching_public_name(contents, public_key)
                    .context("invalid ECHConfig fields")?
            {
                configs.push(EchConfig {
                    public_name: public_name.to_owned(),
                    encoded: list[..list.len() - next.len()].into(),
                });
            }
            list = next;
        }
        ensure!(
            !configs.is_empty(),
            "ECHConfigList has no supported config matching its private key"
        );
        Ok(Self {
            private_key,
            configs,
        })
    }
}

fn pem_block<'a>(pem: &'a str, label: &str) -> anyhow::Result<(&'a str, &'a str)> {
    pem.strip_prefix(&format!("-----BEGIN {label}-----"))
        .and_then(|rest| rest.split_once(&format!("-----END {label}-----")))
        .with_context(|| format!("missing PEM {label} block"))
}

fn decode_pem_body(body: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let compact = Zeroizing::new(
        body.bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>(),
    );
    // Decode into a zeroizing output so a malformed private PEM never leaves
    // a partially decoded key in a freed allocation.
    let mut decoded = Zeroizing::new(vec![0; compact.len()]);
    let len = STANDARD.decode_slice(&*compact, &mut decoded)?;
    decoded.truncate(len);
    Ok(decoded)
}

fn take_vector(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, contents) = bytes.split_first_chunk::<2>()?;
    contents.split_at_checked(u16::from_be_bytes(*len).into())
}

// Parse just enough of RFC 9849's ECHConfigContents to identify the matching
// key and the name that the listener's certificate must cover. BoringSSL
// validates the full selected records before installing them.
fn matching_public_name<'a>(contents: &'a [u8], expected_key: &[u8]) -> Option<Option<&'a str>> {
    let (_, contents) = contents.split_first()?; // config_id
    let (kem, contents) = contents.split_first_chunk::<2>()?;
    let (public_key, contents) = take_vector(contents)?;
    if u16::from_be_bytes(*kem) != X25519_KEM || public_key != expected_key {
        return Some(None);
    }
    let (_, contents) = take_vector(contents)?; // cipher_suites
    let (_, contents) = contents.split_first()?; // maximum_name_length
    let (&name_len, contents) = contents.split_first()?;
    let (name, _) = contents.split_at_checked(name_len.into())?;
    let name = std::str::from_utf8(name).ok()?;
    valid_dns_name(name).then_some(Some(name))
}

fn valid_dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && name.rsplit('.').next().is_some_and(|last| {
            !last.bytes().all(|byte| byte.is_ascii_digit())
                && !last.get(..2).is_some_and(|prefix| {
                    prefix.eq_ignore_ascii_case("0x")
                        && last[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        })
}

struct HpkeKey(NonNull<boring_sys::EVP_HPKE_KEY>);

impl Drop for HpkeKey {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the pointer from EVP_HPKE_KEY_new.
        unsafe { boring_sys::EVP_HPKE_KEY_free(self.0.as_ptr()) }
    }
}

struct NativeEchKeys(NonNull<boring_sys::SSL_ECH_KEYS>);

impl Drop for NativeEchKeys {
    fn drop(&mut self) {
        // SAFETY: this releases the wrapper's owned reference from SSL_ECH_KEYS_new.
        unsafe { boring_sys::SSL_ECH_KEYS_free(self.0.as_ptr()) }
    }
}
