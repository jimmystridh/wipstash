//! Narrow cryptographic profile for managed pairing.
//!
//! PKCS#10 and X.509 parsing is delegated to x509-parser. Pairing accepts only
//! ECDSA P-256/SHA-256, a self-signed root, and extension-free CSRs. Caller subject
//! names are discarded; certificates bind the complete immutable invitation scope.
//! This module does not read/write files, grant access, or open network listeners.

use crate::{error, fingerprint, Result};
use crate::pairing::{EnrollmentResponse, InvitePurpose, InviteScope};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PublicKey, PublicKeyData, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use ring::{rand::{SecureRandom, SystemRandom}, signature};
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_parser::{
    certificate::X509Certificate,
    certification_request::X509CertificationRequest,
    extensions::ParsedExtension,
    prelude::FromDer,
    x509::{AlgorithmIdentifier, SubjectPublicKeyInfo},
};

pub const CSR_MAX: usize = 8 * 1024;
pub const CERTIFICATE_MAX: usize = 8 * 1024;
pub const MAX_CERTIFICATE_LIFETIME_SECS: u64 = crate::pairing::MAX_CERTIFICATE_SECONDS;
const BOOTSTRAP_SERVER_LIFETIME_SECS: i64 = 365 * 24 * 60 * 60;
const PEM_MAX: usize = 32 * 1024;
const CLOCK_SKEW_SECS: i64 = 60;
const SCOPE_DOMAIN: &[u8] = b"wipstash-pairing/client-scope/v1\0";

/// Private material is intentionally neither Debug nor Serialize.
pub struct LocalCsr {
    pub key_pem: String,
    pub csr_der: Vec<u8>,
}

/// A verified public key only. None of the caller's requested certificate
/// parameters survive this boundary. Private fields prevent unchecked creation.
pub struct VerifiedCsr {
    public_key: PublicKey,
    spki_der: Vec<u8>,
}
impl VerifiedCsr {
    pub fn public_key_digest(&self) -> String {
        fingerprint(&self.spki_der)
    }
}

/// Validated signing authority. The original root DER is retained verbatim;
/// rcgen's reconstructed certificate is used only as its signing parameter set.
/// No API exports or serializes the issuer's private key.
pub struct Issuer {
    certificate: Certificate,
    key: KeyPair,
    ca_der: Vec<u8>,
}
impl Issuer {
    pub fn from_pem(ca_pem: &str, key_pem: &str, now: i64) -> Result<Self> {
        let ca_der = one_certificate_pem(ca_pem)?;
        let ca = validate_ca(&ca_der, now)?;
        let key = p256_key_from_pem(key_pem)?;
        if ca.public_key().raw != key.public_key_der().as_slice() {
            return Err(error("pairing_ca_key_mismatch"));
        }
        let params = CertificateParams::from_ca_cert_der(&CertificateDer::from(ca_der.as_slice()))
            .map_err(|_| error("pairing_ca_profile"))?;
        let certificate = params.self_signed(&key).map_err(|_| error("pairing_ca_profile"))?;
        // Fail closed for imported roots whose subject cannot be preserved by
        // rcgen 0.13.2's issuer reconstruction. Never silently change the issuer.
        let reconstructed = parse_certificate(certificate.der())?;
        if reconstructed.subject().as_raw() != ca.subject().as_raw() {
            return Err(error("pairing_ca_subject_encoding"));
        }
        Ok(Self { certificate, key, ca_der })
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.ca_der
    }
}

/// Generate a key and the exact signed CSR to durably journal BEFORE enrollment.
/// Retries must reload these bytes, rather than invoke this function again.
pub fn generate_local_csr() -> Result<LocalCsr> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|_| error("pairing_key_generation"))?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let request = params.serialize_request(&key).map_err(|_| error("pairing_csr_generation"))?;
    let csr_der = request.der().to_vec();
    verify_csr(&csr_der)?;
    Ok(LocalCsr { key_pem: key.serialize_pem(), csr_der })
}

/// Check restart journal consistency without sending or installing credentials.
pub fn validate_local_key_csr(key_pem: &str, csr_der: &[u8]) -> Result<()> {
    let key = p256_key_from_pem(key_pem)?;
    let csr = verify_csr(csr_der)?;
    if key.public_key_der() != csr.spki_der {
        return Err(error("pairing_local_key_csr_mismatch"));
    }
    Ok(())
}

pub fn verify_csr(csr_der: &[u8]) -> Result<VerifiedCsr> {
    if csr_der.is_empty() || csr_der.len() > CSR_MAX {
        return Err(error("pairing_csr_bound"));
    }
    let (remainder, csr) = X509CertificationRequest::from_der(csr_der)
        .map_err(|_| error("pairing_invalid_csr"))?;
    if !remainder.is_empty() || csr.certification_request_info.version.0 != 0 {
        return Err(error("pairing_invalid_csr"));
    }
    let info = &csr.certification_request_info;
    // Reject all attributes, including extensionRequest, challengePassword,
    // duplicate requests, malformed/unknown extensions and SAN/CA/role requests.
    // This deliberately does not rely on requested_extensions(), which can
    // conceal unknown or unsuccessfully parsed attributes.
    if !info.attributes().is_empty() {
        return Err(error("pairing_csr_attributes_forbidden"));
    }
    validate_p256_spki(&info.subject_pki)?;
    validate_signature_algorithm(&csr.signature_algorithm)?;
    if csr.signature_value.unused_bits != 0 {
        return Err(error("pairing_invalid_csr_signature"));
    }
    csr.verify_signature().map_err(|_| error("pairing_invalid_csr_signature"))?;
    let parsed = CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(csr_der))
        .map_err(|_| error("pairing_invalid_csr"))?;
    if parsed.public_key.algorithm() != &PKCS_ECDSA_P256_SHA256
        || parsed.public_key.der_bytes() != info.subject_pki.subject_public_key.data.as_ref()
    {
        return Err(error("pairing_csr_key_mismatch"));
    }
    Ok(VerifiedCsr { public_key: parsed.public_key, spki_der: info.subject_pki.raw.to_vec() })
}

pub fn issue_client_certificate(
    csr: &VerifiedCsr,
    scope: &InviteScope,
    issuer: &Issuer,
    now: i64,
) -> Result<Vec<u8>> {
    scope.validate()?;
    if scope.ca_certificate_der != issuer.ca_der {
        return Err(error("pairing_ca_scope_mismatch"));
    }
    // Recheck on every issuance: a long-lived Issuer does not extend CA expiry.
    let ca = validate_ca(&issuer.ca_der, now)?;
    let params = client_parameters(scope, &ca, now)?;
    let certificate = params.signed_by(&csr.public_key, &issuer.certificate, &issuer.key)
        .map_err(|_| error("pairing_certificate_signing"))?;
    Ok(certificate.der().to_vec())
}

/// Verify a proof over the server's complete domain-separated challenge bytes.
/// Challenge freshness, single-use consumption and request binding live in the
/// transactional store, rather than in this stateless cryptographic primitive.
pub fn verify_recovery_signature(csr_der: &[u8], message: &[u8], signature_bytes: &[u8]) -> Result<()> {
    if message.is_empty() || message.len() > 4096 || signature_bytes.len() > 80 {
        return Err(error("pairing_recovery_bound"));
    }
    let csr = verify_csr(csr_der)?;
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, csr.public_key.der_bytes())
        .verify(message, signature_bytes)
        .map_err(|_| error("pairing_recovery_signature"))
}

pub fn sign_recovery(key_pem: &str, message: &[u8]) -> Result<Vec<u8>> {
    if message.is_empty() || message.len() > 4096 {
        return Err(error("pairing_recovery_bound"));
    }
    let key = p256_key_from_pem(key_pem)?;
    let der = zeroize::Zeroizing::new(key.serialize_der());
    let rng = SystemRandom::new();
    let signer = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING, &der, &rng,
    ).map_err(|_| error("pairing_private_key"))?;
    signer.sign(&rng, message).map(|value| value.as_ref().to_vec())
        .map_err(|_| error("pairing_recovery_signature"))
}

/// Validate the full enrollment result before installing a certificate/config.
/// `expected_scope` is the exact invitation previously approved by the user.
/// This is not a substitute for authenticating the enrollment TLS connection.
pub fn validate_enrollment_response(
    response: &EnrollmentResponse,
    csr_der: &[u8],
    expected_scope: &InviteScope,
    request_id: &str,
    now: i64,
) -> Result<()> {
    expected_scope.validate()?;
    let expected_generation = match &expected_scope.purpose {
        InvitePurpose::New => 1,
        InvitePurpose::Rotate { expected_generation } => expected_generation.checked_add(1)
            .ok_or_else(|| error("pairing_generation_overflow"))?,
    };
    if response.version != 1 || request_id.is_empty() || request_id.len() > 128
        || response.request_id != request_id || response.generation != expected_generation
        || response.scope != *expected_scope
        || response.ca_certificate_der != expected_scope.ca_certificate_der
        || response.fingerprint != fingerprint(&response.certificate_der)
    {
        return Err(error("pairing_response_binding"));
    }
    validate_lifetime(expected_scope.certificate_lifetime_secs)?;
    let csr = verify_csr(csr_der)?;
    let ca = validate_ca(&response.ca_certificate_der, now)?;
    let leaf = parse_certificate(&response.certificate_der)?;
    validate_certificate_structure(&leaf)?;
    validate_p256_spki(leaf.public_key())?;
    if leaf.public_key().raw != csr.spki_der.as_slice()
        || leaf.issuer().as_raw() != ca.subject().as_raw()
    {
        return Err(error("pairing_response_key_or_issuer"));
    }
    leaf.verify_signature(Some(ca.public_key())).map_err(|_| error("pairing_response_signature"))?;
    validate_leaf_profile(&leaf, expected_scope)?;
    let validity = leaf.validity();
    let start = validity.not_before.timestamp();
    let end = validity.not_after.timestamp();
    let lifetime = i64::try_from(expected_scope.certificate_lifetime_secs)
        .map_err(|_| error("pairing_certificate_lifetime"))?;
    let duration = end.checked_sub(start).ok_or_else(|| error("pairing_certificate_validity"))?;
    if now < start || now >= end || start < ca.validity().not_before.timestamp()
        || end > ca.validity().not_after.timestamp() || duration < lifetime
        || duration > lifetime + CLOCK_SKEW_SECS
    {
        return Err(error("pairing_certificate_validity"));
    }
    Ok(())
}

fn client_parameters(scope: &InviteScope, ca: &X509Certificate<'_>, now: i64) -> Result<CertificateParams> {
    validate_lifetime(scope.certificate_lifetime_secs)?;
    let end = now.checked_add(scope.certificate_lifetime_secs as i64)
        .ok_or_else(|| error("pairing_certificate_lifetime"))?;
    if end > ca.validity().not_after.timestamp() {
        return Err(error("pairing_ca_expires_before_client"));
    }
    let start = now.saturating_sub(CLOCK_SKEW_SECS).max(ca.validity().not_before.timestamp());
    let mut params = CertificateParams::default();
    params.not_before = timestamp(start)?;
    params.not_after = timestamp(end)?;
    params.serial_number = Some(random_serial()?);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, scope_digest(scope)?);
    params.distinguished_name.push(DnType::OrganizationalUnitName, "Wipstash client");
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.use_authority_key_identifier_extension = true;
    Ok(params)
}

fn scope_digest(scope: &InviteScope) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(SCOPE_DOMAIN);
    hash.update(serde_json::to_vec(scope)?);
    Ok(format!("{:x}", hash.finalize()))
}

fn validate_leaf_profile(leaf: &X509Certificate<'_>, scope: &InviteScope) -> Result<()> {
    validate_extension_profile(leaf, true)?;
    let constraints = leaf.basic_constraints().map_err(|_| error("pairing_leaf_constraints"))?
        .ok_or_else(|| error("pairing_leaf_constraints"))?;
    if !constraints.critical || constraints.value.ca || constraints.value.path_len_constraint.is_some() {
        return Err(error("pairing_leaf_constraints"));
    }
    let usage = leaf.key_usage().map_err(|_| error("pairing_leaf_usage"))?
        .ok_or_else(|| error("pairing_leaf_usage"))?;
    if !usage.critical || usage.value.flags != 1 {
        return Err(error("pairing_leaf_usage"));
    }
    let eku = leaf.extended_key_usage().map_err(|_| error("pairing_leaf_usage"))?
        .ok_or_else(|| error("pairing_leaf_usage"))?;
    let eku = eku.value;
    if !eku.client_auth || eku.server_auth || eku.any || eku.code_signing || eku.email_protection
        || eku.time_stamping || eku.ocsp_signing || !eku.other.is_empty()
    {
        return Err(error("pairing_leaf_usage"));
    }
    let digest = scope_digest(scope)?;
    let subject = leaf.subject();
    let mut common_names = subject.iter_common_name();
    let mut units = subject.iter_organizational_unit();
    if subject.iter_attributes().count() != 2
        || common_names.next().and_then(|value| value.as_str().ok()) != Some(digest.as_str())
        || common_names.next().is_some()
        || units.next().and_then(|value| value.as_str().ok()) != Some("Wipstash client")
        || units.next().is_some()
    {
        return Err(error("pairing_leaf_scope"));
    }
    Ok(())
}

fn parse_certificate(der: &[u8]) -> Result<X509Certificate<'_>> {
    if der.is_empty() || der.len() > CERTIFICATE_MAX {
        return Err(error("pairing_certificate_bound"));
    }
    let (remainder, certificate) = X509Certificate::from_der(der)
        .map_err(|_| error("pairing_invalid_certificate"))?;
    if !remainder.is_empty() {
        return Err(error("pairing_invalid_certificate"));
    }
    Ok(certificate)
}

fn validate_ca(der: &[u8], now: i64) -> Result<X509Certificate<'_>> {
    let ca = parse_certificate(der)?;
    validate_certificate_structure(&ca)?;
    validate_p256_spki(ca.public_key())?;
    validate_extension_profile(&ca, false)?;
    let constraints = ca.basic_constraints().map_err(|_| error("pairing_ca_constraints"))?
        .ok_or_else(|| error("pairing_ca_constraints"))?;
    let usage = ca.key_usage().map_err(|_| error("pairing_ca_usage"))?
        .ok_or_else(|| error("pairing_ca_usage"))?;
    if !constraints.critical || !constraints.value.ca || !usage.value.key_cert_sign()
        || ca.issuer().as_raw() != ca.subject().as_raw()
    {
        return Err(error("pairing_ca_profile"));
    }
    if now < ca.validity().not_before.timestamp() || now >= ca.validity().not_after.timestamp() {
        return Err(error("pairing_ca_validity"));
    }
    ca.verify_signature(None).map_err(|_| error("pairing_ca_signature"))?;
    Ok(ca)
}

fn validate_certificate_structure(cert: &X509Certificate<'_>) -> Result<()> {
    validate_signature_algorithm(&cert.signature_algorithm)?;
    validate_signature_algorithm(&cert.tbs_certificate.signature)?;
    if cert.version().0 != 2 || cert.signature_algorithm != cert.tbs_certificate.signature
        || cert.signature_value.unused_bits != 0 || cert.issuer_uid.is_some() || cert.subject_uid.is_some()
        || cert.raw_serial().is_empty() || cert.raw_serial().len() > 20
        || cert.raw_serial()[0] & 0x80 != 0 || cert.raw_serial().iter().all(|value| *value == 0)
    {
        return Err(error("pairing_certificate_profile"));
    }
    Ok(())
}

fn validate_extension_profile(cert: &X509Certificate<'_>, leaf: bool) -> Result<()> {
    cert.extensions_map().map_err(|_| error("pairing_duplicate_extensions"))?;
    for extension in cert.extensions() {
        let allowed = match extension.parsed_extension() {
            ParsedExtension::BasicConstraints(_) | ParsedExtension::KeyUsage(_)
            | ParsedExtension::SubjectKeyIdentifier(_) | ParsedExtension::AuthorityKeyIdentifier(_) => true,
            ParsedExtension::ExtendedKeyUsage(_) => leaf,
            _ => false,
        };
        if !allowed {
            return Err(error("pairing_certificate_extensions"));
        }
    }
    Ok(())
}

fn validate_p256_spki(spki: &SubjectPublicKeyInfo<'_>) -> Result<()> {
    let curve = spki.algorithm.parameters.as_ref().and_then(|value| value.as_oid().ok());
    if spki.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
        || curve.map(|value| value.to_id_string()).as_deref() != Some("1.2.840.10045.3.1.7")
        || spki.subject_public_key.unused_bits != 0 || spki.subject_public_key.data.len() != 65
        || spki.subject_public_key.data.first().copied() != Some(4)
    {
        return Err(error("pairing_unsupported_public_key"));
    }
    Ok(())
}

fn validate_signature_algorithm(algorithm: &AlgorithmIdentifier<'_>) -> Result<()> {
    if algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.2" || algorithm.parameters.is_some() {
        return Err(error("pairing_unsupported_signature"));
    }
    Ok(())
}

fn validate_lifetime(seconds: u64) -> Result<()> {
    if seconds == 0 || seconds > MAX_CERTIFICATE_LIFETIME_SECS {
        return Err(error("pairing_certificate_lifetime"));
    }
    Ok(())
}

fn timestamp(value: i64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(value).map_err(|_| error("pairing_invalid_time"))
}

fn random_serial() -> Result<SerialNumber> {
    let mut bytes = [0u8; 20];
    SystemRandom::new().fill(&mut bytes).map_err(|_| error("pairing_randomness"))?;
    // Positive, nonzero, at most 20 DER INTEGER octets (RFC 5280).
    bytes[0] = (bytes[0] & 0x7f) | 1;
    Ok(SerialNumber::from_slice(&bytes))
}

fn one_certificate_pem(pem: &str) -> Result<Vec<u8>> {
    if pem.is_empty() || pem.len() > PEM_MAX {
        return Err(error("pairing_ca_bound"));
    }
    let mut source = pem.as_bytes();
    let mut certificate = None;
    for item in rustls_pemfile::read_all(&mut source) {
        let next = match item.map_err(|_| error("pairing_ca_pem"))? {
            rustls_pemfile::Item::X509Certificate(der) => der.to_vec(),
            _ => return Err(error("pairing_ca_pem")),
        };
        if certificate.replace(next).is_some() {
            return Err(error("pairing_ca_pem"));
        }
    }
    certificate.ok_or_else(|| error("pairing_ca_pem"))
}

fn p256_key_from_pem(pem: &str) -> Result<KeyPair> {
    if pem.is_empty() || pem.len() > PEM_MAX {
        return Err(error("pairing_private_key_bound"));
    }
    let mut source = pem.as_bytes();
    let mut key: Option<PrivatePkcs8KeyDer<'static>> = None;
    for item in rustls_pemfile::read_all(&mut source) {
        let next = match item.map_err(|_| error("pairing_private_key"))? {
            rustls_pemfile::Item::Pkcs8Key(value) => value,
            _ => return Err(error("pairing_private_key")),
        };
        if key.replace(next).is_some() {
            return Err(error("pairing_private_key"));
        }
    }
    let key = key.ok_or_else(|| error("pairing_private_key"))?;
    KeyPair::from_pkcs8_der_and_sign_algo(&key, &PKCS_ECDSA_P256_SHA256)
        .map_err(|_| error("pairing_private_key"))
}

/// Returned only to explicit local setup, which must protect every private-key
/// output before writing. This function itself does no provisioning or I/O.
pub struct BootstrapMaterial {
    pub ca_pem: String,
    pub ca_key_pem: String,
    pub ca_certificate_der: Vec<u8>,
    pub server_pem: String,
    pub server_key_pem: String,
    pub server_certificate_der: Vec<u8>,
}

pub fn generate_bootstrap(server_names: &[String], now: i64) -> Result<BootstrapMaterial> {
    if server_names.is_empty() || server_names.len() > 8 {
        return Err(error("pairing_server_names"));
    }
    for name in server_names {
        if name.is_empty() || name.len() > 253 || name.contains('*')
            || rustls::pki_types::ServerName::try_from(name.clone()).is_err()
        {
            return Err(error("pairing_server_names"));
        }
    }
    let start = timestamp(now.checked_sub(CLOCK_SKEW_SECS).ok_or_else(|| error("pairing_invalid_time"))?)?;
    let ca_end = timestamp(now.checked_add(5 * BOOTSTRAP_SERVER_LIFETIME_SECS)
        .ok_or_else(|| error("pairing_invalid_time"))?)?;
    let server_end = timestamp(now.checked_add(BOOTSTRAP_SERVER_LIFETIME_SECS)
        .ok_or_else(|| error("pairing_invalid_time"))?)?;
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| error("pairing_key_generation"))?;
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(DnType::CommonName, "Wipstash pairing authority");
    ca_params.not_before = start;
    ca_params.not_after = ca_end;
    ca_params.serial_number = Some(random_serial()?);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).map_err(|_| error("pairing_ca_generation"))?;
    let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| error("pairing_key_generation"))?;
    let mut server_params = CertificateParams::new(server_names.to_vec()).map_err(|_| error("pairing_server_names"))?;
    server_params.distinguished_name = DistinguishedName::new();
    server_params.distinguished_name.push(DnType::CommonName, "Wipstash transport");
    server_params.not_before = start;
    server_params.not_after = server_end;
    server_params.serial_number = Some(random_serial()?);
    server_params.is_ca = IsCa::ExplicitNoCa;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.use_authority_key_identifier_extension = true;
    let server = server_params.signed_by(&server_key, &ca, &ca_key)
        .map_err(|_| error("pairing_server_generation"))?;
    Ok(BootstrapMaterial {
        ca_pem: ca.pem(), ca_key_pem: ca_key.serialize_pem(), ca_certificate_der: ca.der().to_vec(),
        server_pem: server.pem(), server_key_pem: server_key.serialize_pem(), server_certificate_der: server.der().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{Attribute, CustomExtension, PKCS_ED25519};

    const NOW: i64 = 1_800_000_000;
    const REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixture() -> (BootstrapMaterial, Issuer, InviteScope, LocalCsr) {
        let bootstrap = generate_bootstrap(&["localhost".to_owned()], NOW).unwrap();
        let issuer = Issuer::from_pem(&bootstrap.ca_pem, &bootstrap.ca_key_pem, NOW).unwrap();
        let scope = InviteScope {
            project: "test_project".to_owned(), authority: "test_authority".to_owned(), epoch: 1,
            authority_device: "coordinator".to_owned(), client_device: "test_client".to_owned(),
            purpose: InvitePurpose::New,
            enrollment_address: "127.0.0.1:4443".parse().unwrap(),
            enrollment_server_name: "localhost".to_owned(), enrollment_leaf_pin: fingerprint(&bootstrap.server_certificate_der),
            sync_address: "127.0.0.1:4444".parse().unwrap(), sync_server_name: "localhost".to_owned(),
            sync_leaf_pin: fingerprint(&bootstrap.server_certificate_der),
            ca_certificate_der: bootstrap.ca_certificate_der.clone(), certificate_lifetime_secs: 86400,
        };
        (bootstrap, issuer, scope, generate_local_csr().unwrap())
    }

    fn response(issuer: &Issuer, scope: &InviteScope, csr_der: &[u8]) -> EnrollmentResponse {
        let csr = verify_csr(csr_der).unwrap();
        let der = issue_client_certificate(&csr, scope, issuer, NOW).unwrap();
        let generation = match &scope.purpose { InvitePurpose::New => 1, InvitePurpose::Rotate { expected_generation } => expected_generation + 1 };
        EnrollmentResponse { version: 1, fingerprint: fingerprint(&der), certificate_der: der,
            ca_certificate_der: scope.ca_certificate_der.clone(), scope: scope.clone(), generation, request_id: REQUEST.to_owned() }
    }

    fn replace_leaf(response: &mut EnrollmentResponse, der: Vec<u8>) {
        response.fingerprint = fingerprint(&der);
        response.certificate_der = der;
    }

    fn rejected(response: &EnrollmentResponse, local: &LocalCsr, scope: &InviteScope) {
        assert!(validate_enrollment_response(response, &local.csr_der, scope, REQUEST, NOW).is_err());
    }

    #[test]
    fn issuer_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Issuer>();
    }

    #[test]
    fn csr_signature_and_recovery_require_the_exact_private_key_and_message() {
        let local = generate_local_csr().unwrap();
        let verified = verify_csr(&local.csr_der).unwrap();
        validate_local_key_csr(&local.key_pem, &local.csr_der).unwrap();
        assert_eq!(verified.public_key_digest().len(), 64);
        let message = b"wipstash/enrollment/recovery/v1\0synthetic-challenge";
        let signature = sign_recovery(&local.key_pem, message).unwrap();
        verify_recovery_signature(&local.csr_der, message, &signature).unwrap();
        assert!(verify_recovery_signature(&local.csr_der, b"changed challenge", &signature).is_err());
        let other = generate_local_csr().unwrap();
        assert!(validate_local_key_csr(&other.key_pem, &local.csr_der).is_err());
        assert!(verify_recovery_signature(&other.csr_der, message, &signature).is_err());
        let wrong_signature = sign_recovery(&other.key_pem, message).unwrap();
        assert!(verify_recovery_signature(&local.csr_der, message, &wrong_signature).is_err());
        assert!(verify_recovery_signature(&local.csr_der, message, &[]).is_err());
        let mut forged = local.csr_der.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(verify_csr(&forged).is_err());
    }

    #[test]
    fn csr_requires_full_der_and_respects_the_size_bound() {
        let local = generate_local_csr().unwrap();
        let mut trailing = local.csr_der.clone();
        trailing.extend_from_slice(&[0, 1, 2]);
        assert!(verify_csr(&trailing).is_err());
        let mut concatenated = local.csr_der.clone();
        concatenated.extend_from_slice(&local.csr_der);
        assert!(verify_csr(&concatenated).is_err());
        assert!(verify_csr(&local.csr_der[..local.csr_der.len() - 1]).is_err());
        assert!(verify_csr(&vec![0; CSR_MAX + 1]).is_err());
        assert!(verify_csr(&[]).is_err());
    }

    #[test]
    fn csr_rejects_san_ca_roles_custom_extensions_and_unknown_attributes() {
        let key = KeyPair::generate().unwrap();
        let mut cases = Vec::new();
        cases.push(CertificateParams::new(vec!["attacker.example".to_owned()]).unwrap());
        let mut key_usage = CertificateParams::default();
        key_usage.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        cases.push(key_usage);
        let mut server_auth = CertificateParams::default();
        server_auth.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        cases.push(server_auth);
        let mut ca = CertificateParams::default();
        ca.custom_extensions.push(CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x30, 0x03, 0x01, 0x01, 0xff]));
        cases.push(ca);
        let mut custom = CertificateParams::default();
        custom.custom_extensions.push(CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], vec![0x05, 0]));
        cases.push(custom);
        for params in cases {
            let csr = params.serialize_request(&key).unwrap();
            assert!(verify_csr(csr.der()).is_err());
        }
        let csr = CertificateParams::default().serialize_request_with_attributes(&key, vec![Attribute {
            oid: &[1, 2, 840, 113549, 1, 9, 7],
            values: vec![0x31, 0x03, 0x0c, 0x01, b'x'],
        }]).unwrap();
        assert!(verify_csr(csr.der()).is_err());
    }

    #[test]
    fn csr_rejects_other_supported_rcgen_algorithms() {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let csr = CertificateParams::default().serialize_request(&key).unwrap();
        assert!(verify_csr(csr.der()).is_err());
        assert!(sign_recovery(&key.serialize_pem(), b"challenge").is_err());
    }

    #[test]
    fn issuer_rejects_wrong_key_non_ca_missing_signing_usage_and_invalid_time() {
        let (bootstrap, _, _, local) = fixture();
        assert!(Issuer::from_pem(&bootstrap.ca_pem, &local.key_pem, NOW).is_err());
        assert!(Issuer::from_pem(&bootstrap.server_pem, &bootstrap.server_key_pem, NOW).is_err());
        assert!(Issuer::from_pem(&bootstrap.ca_pem, &bootstrap.ca_key_pem, NOW - 61).is_err());
        assert!(Issuer::from_pem(&bootstrap.ca_pem, &bootstrap.ca_key_pem, NOW + 5 * BOOTSTRAP_SERVER_LIFETIME_SECS).is_err());
        assert!(Issuer::from_pem(&(bootstrap.ca_pem.clone() + &bootstrap.ca_pem), &bootstrap.ca_key_pem, NOW).is_err());
        assert!(Issuer::from_pem(&bootstrap.ca_pem, &(bootstrap.ca_key_pem.clone() + &bootstrap.ca_key_pem), NOW).is_err());
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let bad_ca = params.self_signed(&key).unwrap();
        assert!(Issuer::from_pem(&bad_ca.pem(), &key.serialize_pem(), NOW).is_err());
        let mut trailing = bootstrap.ca_certificate_der.clone();
        trailing.push(0);
        assert!(validate_ca(&trailing, NOW).is_err());
    }

    #[test]
    fn issuance_replaces_caller_subject_and_is_client_auth_only() {
        let (_, issuer, scope, local) = fixture();
        let key = p256_key_from_pem(&local.key_pem).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, "coordinator-admin");
        params.distinguished_name.push(DnType::OrganizationName, "attacker");
        let csr = params.serialize_request(&key).unwrap();
        let enrolled = response(&issuer, &scope, csr.der());
        validate_enrollment_response(&enrolled, csr.der(), &scope, REQUEST, NOW).unwrap();
        let cert = parse_certificate(&enrolled.certificate_der).unwrap();
        assert_eq!(cert.subject().iter_common_name().next().unwrap().as_str().unwrap(), scope_digest(&scope).unwrap());
        assert_eq!(cert.subject().iter_organization().count(), 0);
        assert!(cert.subject_alternative_name().unwrap().is_none());
        assert!(!cert.is_ca());
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth);
        assert!(!eku.server_auth && !eku.any);
        assert_eq!(cert.key_usage().unwrap().unwrap().value.flags, 1);
    }

    #[test]
    fn response_rejects_wrong_request_key_fingerprint_version_generation_and_ca() {
        let (bootstrap, issuer, scope, local) = fixture();
        let valid = response(&issuer, &scope, &local.csr_der);
        validate_enrollment_response(&valid, &local.csr_der, &scope, REQUEST, NOW).unwrap();
        let other = generate_local_csr().unwrap();
        assert!(validate_enrollment_response(&valid, &other.csr_der, &scope, REQUEST, NOW).is_err());
        assert!(validate_enrollment_response(&valid, &local.csr_der, &scope, "different", NOW).is_err());
        let mut changed = valid.clone(); changed.request_id.push('b'); rejected(&changed, &local, &scope);
        let mut changed = valid.clone(); changed.version = 2; rejected(&changed, &local, &scope);
        let mut changed = valid.clone(); changed.generation = 2; rejected(&changed, &local, &scope);
        let mut changed = valid.clone(); changed.fingerprint = "0".repeat(64); rejected(&changed, &local, &scope);
        let mut changed = valid.clone(); changed.ca_certificate_der = bootstrap.server_certificate_der.clone(); rejected(&changed, &local, &scope);
        let mut changed = valid.clone(); replace_leaf(&mut changed, bootstrap.ca_certificate_der); rejected(&changed, &local, &scope);
        let mut changed = valid.clone(); replace_leaf(&mut changed, bootstrap.server_certificate_der); rejected(&changed, &local, &scope);
        let mut changed = valid.clone(); changed.certificate_der.push(0); changed.fingerprint = fingerprint(&changed.certificate_der); rejected(&changed, &local, &scope);
        assert!(validate_enrollment_response(&valid, &local.csr_der, &scope, REQUEST, NOW + 86400).is_err());
    }

    #[test]
    fn response_rejects_every_mutated_scope_field_even_with_consistent_outer_scope() {
        let (_, issuer, scope, local) = fixture();
        let valid = response(&issuer, &scope, &local.csr_der);
        let mut variants = Vec::new();
        let mut s = scope.clone(); s.project.push('x'); variants.push(s);
        let mut s = scope.clone(); s.authority.push('x'); variants.push(s);
        let mut s = scope.clone(); s.epoch += 1; variants.push(s);
        let mut s = scope.clone(); s.authority_device.push('x'); variants.push(s);
        let mut s = scope.clone(); s.client_device.push('x'); variants.push(s);
        let mut s = scope.clone(); s.purpose = InvitePurpose::Rotate { expected_generation: 1 }; variants.push(s);
        let mut s = scope.clone(); s.enrollment_address.set_port(5555); variants.push(s);
        let mut s = scope.clone(); s.enrollment_server_name = "other.example".to_owned(); variants.push(s);
        let mut s = scope.clone(); s.enrollment_leaf_pin = "0".repeat(64); variants.push(s);
        let mut s = scope.clone(); s.sync_address.set_port(5556); variants.push(s);
        let mut s = scope.clone(); s.sync_server_name = "other.example".to_owned(); variants.push(s);
        let mut s = scope.clone(); s.sync_leaf_pin = "0".repeat(64); variants.push(s);
        let mut s = scope.clone(); s.ca_certificate_der.push(0); variants.push(s);
        let mut s = scope.clone(); s.certificate_lifetime_secs -= 1; variants.push(s);
        for altered in variants {
            let mut changed = valid.clone(); changed.scope = altered.clone();
            rejected(&changed, &local, &scope);
            // A copied certificate cannot be rebound by changing both the
            // expected invitation and outer response to another valid scope.
            changed.ca_certificate_der = altered.ca_certificate_der.clone();
            changed.generation = match &altered.purpose { InvitePurpose::New => 1, InvitePurpose::Rotate { expected_generation } => expected_generation + 1 };
            rejected(&changed, &local, &altered);
        }
    }

    #[test]
    fn response_rejects_ca_server_and_extension_escalation_even_signed_by_real_ca() {
        let (_, issuer, scope, local) = fixture();
        let csr = verify_csr(&local.csr_der).unwrap();
        let valid = response(&issuer, &scope, &local.csr_der);
        let ca = validate_ca(issuer.certificate_der(), NOW).unwrap();
        for case in 0..6 {
            let mut params = client_parameters(&scope, &ca, NOW).unwrap();
            match case {
                0 => { params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0)); },
                1 => { params.extended_key_usages.push(ExtendedKeyUsagePurpose::ServerAuth); },
                2 => { params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Any]; },
                3 => { params.key_usages.push(KeyUsagePurpose::KeyCertSign); },
                4 => { params.subject_alt_names = CertificateParams::new(vec!["other.example".to_owned()]).unwrap().subject_alt_names; },
                _ => { params.custom_extensions.push(CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], vec![0x05, 0])); },
            }
            let signed = params.signed_by(&csr.public_key, &issuer.certificate, &issuer.key).unwrap();
            let mut bad = valid.clone(); replace_leaf(&mut bad, signed.der().to_vec());
            rejected(&bad, &local, &scope);
        }
    }

    #[test]
    fn rotation_is_bound_to_expected_generation_and_new_fingerprint() {
        let (_, issuer, mut scope, local) = fixture();
        let first = response(&issuer, &scope, &local.csr_der);
        scope.purpose = InvitePurpose::Rotate { expected_generation: 1 };
        let next = generate_local_csr().unwrap();
        let rotated = response(&issuer, &scope, &next.csr_der);
        assert_eq!(rotated.generation, 2);
        assert_ne!(first.fingerprint, rotated.fingerprint);
        validate_enrollment_response(&rotated, &next.csr_der, &scope, REQUEST, NOW).unwrap();
        assert!(validate_enrollment_response(&first, &local.csr_der, &scope, REQUEST, NOW).is_err());
    }

    #[test]
    fn issuance_respects_lifetime_root_binding_and_root_expiration() {
        let (_, issuer, mut scope, local) = fixture();
        let csr = verify_csr(&local.csr_der).unwrap();
        scope.certificate_lifetime_secs = MAX_CERTIFICATE_LIFETIME_SECS + 1;
        assert!(issue_client_certificate(&csr, &scope, &issuer, NOW).is_err());
        scope.certificate_lifetime_secs = 0;
        assert!(issue_client_certificate(&csr, &scope, &issuer, NOW).is_err());
        scope.certificate_lifetime_secs = 86400;
        let near_expiry = NOW + 5 * BOOTSTRAP_SERVER_LIFETIME_SECS - 1;
        assert!(issue_client_certificate(&csr, &scope, &issuer, near_expiry).is_err());
        assert!(issue_client_certificate(&csr, &scope, &issuer, near_expiry + 1).is_err());
        scope.ca_certificate_der = generate_bootstrap(&["localhost".to_owned()], NOW).unwrap().ca_certificate_der;
        assert!(issue_client_certificate(&csr, &scope, &issuer, NOW).is_err());
    }

    #[test]
    fn bootstrap_is_server_only_and_accepts_only_explicit_valid_names() {
        let fixture = generate_bootstrap(&["localhost".to_owned(), "127.0.0.1".to_owned()], NOW).unwrap();
        let server = parse_certificate(&fixture.server_certificate_der).unwrap();
        let eku = server.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth && !eku.client_auth && !eku.any);
        assert!(!server.is_ca());
        assert_eq!(server.subject_alternative_name().unwrap().unwrap().value.general_names.len(), 2);
        assert!(generate_bootstrap(&[], NOW).is_err());
        assert!(generate_bootstrap(&["*.example.com".to_owned()], NOW).is_err());
        assert!(generate_bootstrap(&["https://example.com".to_owned()], NOW).is_err());
    }
}
