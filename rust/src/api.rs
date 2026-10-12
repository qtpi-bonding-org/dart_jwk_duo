use flutter_rust_bridge::frb;
use rust_jwk_duo as j;
use rust_jwk_duo::KeyPair;

pub enum RErrorKind { Format, State, Argument }
pub struct RError { pub kind: RErrorKind, pub message: String }
impl From<j::Error> for RError {
    fn from(e: j::Error) -> Self {
        match e {
            j::Error::Format(m) => RError { kind: RErrorKind::Format, message: m },
            j::Error::State(m) => RError { kind: RErrorKind::State, message: m },
            j::Error::Argument(m) => RError { kind: RErrorKind::Argument, message: m },
        }
    }
}
// flutter_rust_bridge 2.11.1 does not see through type aliases: every pub fn
// must spell out Result<T, RError>. The alias is for private helpers only.
type R<T> = Result<T, RError>;

#[frb(opaque)] pub struct RSigningKeyPair(pub(crate) j::SigningKeyPair);
#[frb(opaque)] pub struct REncryptionKeyPair(pub(crate) j::EncryptionKeyPair);
#[frb(opaque)] pub struct RSymmetricKey(pub(crate) j::SymmetricKey);
#[frb(non_opaque)] pub struct RDuoParts { pub signing: RSigningKeyPair, pub encryption: REncryptionKeyPair }
fn parts(d: j::KeyDuo) -> RDuoParts { let (s, e) = d.into_parts(); RDuoParts { signing: RSigningKeyPair(s), encryption: REncryptionKeyPair(e) } }
fn jwk_string(e: j::ExportedJwk) -> String { serde_json::Value::Object(e.to_json()).to_string() }
fn json_value(s: &str) -> R<serde_json::Value> { serde_json::from_str(s).map_err(|_| RError { kind: RErrorKind::Format, message: "Invalid JSON format".into() }) }
fn json_object(s: &str) -> R<serde_json::Map<String, serde_json::Value>> {
    match json_value(s)? { serde_json::Value::Object(m) => Ok(m), _ => Err(RError { kind: RErrorKind::Format, message: "Invalid JSON format".into() }) }
}

// meta
#[frb(sync)] pub fn format_version() -> u32 { j::constants::FORMAT_VERSION }
// generation / import (GenerationService, KeyDuoSerializer, key pairs)
#[frb(sync)] pub fn generate_key_duo() -> RDuoParts { parts(j::GenerationService::generate_key_duo()) }
#[frb(sync)] pub fn import_key_duo_jwk(json: String) -> Result<RDuoParts, RError> { Ok(parts(j::KeyDuoSerializer::import_key_duo_jwk(&json)?)) }
#[frb(sync)] pub fn import_public_key_duo_jwk(json: String) -> Result<RDuoParts, RError> { Ok(parts(j::KeyDuoSerializer::import_public_key_duo_jwk(&json)?)) }
#[frb(sync)] pub fn signing_import_public_raw(raw: Vec<u8>) -> Result<RSigningKeyPair, RError> { Ok(RSigningKeyPair(j::SigningKeyPair::import_public_key_raw(&raw)?)) }
#[frb(sync)] pub fn encryption_import_public_raw(raw: Vec<u8>) -> Result<REncryptionKeyPair, RError> { Ok(REncryptionKeyPair(j::EncryptionKeyPair::import_public_key_raw(&raw)?)) }
// signing pair
#[frb(sync)] pub fn signing_has_private_key(kp: &RSigningKeyPair) -> bool { kp.0.has_private_key() }
#[frb(sync)] pub fn signing_public_raw(kp: &RSigningKeyPair) -> Vec<u8> { kp.0.export_public_key_raw().to_vec() }
#[frb(sync)] pub fn signing_key_id(kp: &RSigningKeyPair) -> Result<String, RError> { Ok(kp.0.calculate_key_id()?) }
#[frb(sync)] pub fn signing_export_private_jwk(kp: &RSigningKeyPair) -> Result<String, RError> { Ok(jwk_string(kp.0.export_private_key()?)) }
#[frb(sync)] pub fn signing_export_public_jwk(kp: &RSigningKeyPair) -> Result<String, RError> { Ok(jwk_string(kp.0.export_public_key()?)) }
#[frb(sync)] pub fn sign_bytes(kp: &RSigningKeyPair, data: Vec<u8>) -> Result<Vec<u8>, RError> { Ok(kp.0.sign_bytes(&data)?.to_vec()) }
#[frb(sync)] pub fn verify_bytes(kp: &RSigningKeyPair, signature: Vec<u8>, data: Vec<u8>) -> bool { kp.0.verify_bytes(&signature, &data) }
#[frb(sync)] pub fn signature_from_der(der: Vec<u8>) -> Result<Vec<u8>, RError> { Ok(j::SigningKeyPair::signature_from_der(&der)?.to_vec()) }
#[frb(sync)] pub fn signature_to_der(sig: Vec<u8>) -> Result<Vec<u8>, RError> {
    let a: [u8; 64] = sig.try_into().map_err(|_| RError { kind: RErrorKind::Format, message: "Signature must be 64 bytes".into() })?;
    Ok(j::SigningKeyPair::signature_to_der(&a)?)
}
// encryption pair
#[frb(sync)] pub fn encryption_has_private_key(kp: &REncryptionKeyPair) -> bool { kp.0.has_private_key() }
#[frb(sync)] pub fn encryption_public_raw(kp: &REncryptionKeyPair) -> Vec<u8> { kp.0.export_public_key_raw().to_vec() }
#[frb(sync)] pub fn encryption_key_id(kp: &REncryptionKeyPair) -> Result<String, RError> { Ok(kp.0.calculate_key_id()?) }
#[frb(sync)] pub fn encryption_export_private_jwk(kp: &REncryptionKeyPair) -> Result<String, RError> { Ok(jwk_string(kp.0.export_private_key()?)) }
#[frb(sync)] pub fn encryption_export_public_jwk(kp: &REncryptionKeyPair) -> Result<String, RError> { Ok(jwk_string(kp.0.export_public_key()?)) }
#[frb(sync)] pub fn hpke_encrypt(data: Vec<u8>, recipient: &REncryptionKeyPair, info: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, RError> { Ok(j::CryptoService::encrypt(&data, &recipient.0, &info, &aad)?) }
#[frb(sync)] pub fn hpke_decrypt(data: Vec<u8>, recipient: &REncryptionKeyPair, info: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, RError> { Ok(j::CryptoService::decrypt(&data, &recipient.0, &info, &aad)?) }
// symmetric
#[frb(sync)] pub fn symmetric_generate() -> RSymmetricKey { RSymmetricKey(j::GenerationService::generate_symmetric_key()) }
#[frb(sync)] pub fn symmetric_from_jwk(json: String) -> Result<RSymmetricKey, RError> { Ok(RSymmetricKey(j::SymmetricKey::from_jwk(&json)?)) }
#[frb(sync)] pub fn symmetric_to_jwk(k: &RSymmetricKey) -> String { k.0.to_jwk() }
#[frb(sync)] pub fn symmetric_encrypt(data: Vec<u8>, k: &RSymmetricKey, aad: Vec<u8>) -> Result<Vec<u8>, RError> { Ok(j::CryptoService::encrypt_symmetric(&data, &k.0, &aad)?) }
#[frb(sync)] pub fn symmetric_decrypt(data: Vec<u8>, k: &RSymmetricKey, aad: Vec<u8>) -> Result<Vec<u8>, RError> { Ok(j::CryptoService::decrypt_symmetric(&data, &k.0, &aad)?) }
// thumbprint + validation (inputs are JSON strings)
#[frb(sync)] pub fn jwk_thumbprint(jwk_json: String) -> Result<String, RError> { Ok(j::calculate_jwk_thumbprint(&json_object(&jwk_json)?)?) }
#[frb(sync)] pub fn validate_key_duo_jwk_structure(set_json: String) -> Result<(), RError> { Ok(j::ValidationService::validate_key_duo_jwk_structure(&json_value(&set_json)?)?) }
#[frb(sync)] pub fn validate_signing_key(key_json: String, require_private: bool) -> Result<(), RError> { Ok(j::ValidationService::validate_signing_key(&json_object(&key_json)?, require_private)?) }
#[frb(sync)] pub fn validate_encryption_key(key_json: String, require_private: bool) -> Result<(), RError> { Ok(j::ValidationService::validate_encryption_key(&json_object(&key_json)?, require_private)?) }
#[frb(sync)] pub fn validate_symmetric_key_jwk(key_json: String) -> Result<(), RError> { Ok(j::ValidationService::validate_symmetric_key_jwk(&json_object(&key_json)?)?) }
#[frb(sync)] pub fn validate_no_private_key_material(set_json: String) -> Result<(), RError> { Ok(j::ValidationService::validate_no_private_key_material(&json_value(&set_json)?)?) }
#[frb(sync)] pub fn extract_public_key_set(set_json: String) -> Result<String, RError> { Ok(j::ValidationService::extract_public_key_set(&json_value(&set_json)?)?.to_string()) }
#[frb(sync)] pub fn validate_key_duo_jwk(set_json: String) -> Result<(), RError> { Ok(j::ValidationService::validate_key_duo_jwk(&set_json)?) }
#[frb(sync)] pub fn validate_symmetric_key_jwk_string(json: String) -> Result<(), RError> { Ok(j::ValidationService::validate_symmetric_key_jwk_string(&json)?) }
// verification self-tests
#[frb(sync)] pub fn verify_signing_key_pair(kp: &RSigningKeyPair) -> Result<bool, RError> { Ok(j::VerificationService::verify_signing_key_pair(&kp.0)?) }
#[frb(sync)] pub fn verify_encryption_key_pair(kp: &REncryptionKeyPair) -> Result<bool, RError> { Ok(j::VerificationService::verify_encryption_key_pair(&kp.0)?) }
#[frb(sync)] pub fn verify_symmetric_key(k: &RSymmetricKey) -> bool { j::VerificationService::verify_symmetric_key(&k.0) }
