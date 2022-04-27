use zei_algebra::collections::BTreeMap;

#[cfg(not(feature = "no_urs"))]
pub static BULLETPROOF_URS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/bulletproof-urs.bin"));

#[cfg(feature = "no_urs")]
pub static BULLETPROOF_URS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_srs"))]
pub static SRS: Option<&'static [u8]> = Some(include_bytes!("../parameters/srs.bin"));

#[cfg(feature = "no_srs")]
pub static SRS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static VERIFIER_COMMON_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/transfer-vk-common.bin"));

#[cfg(feature = "no_vk")]
pub static VERIFIER_COMMON_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static VERIFIER_SPECIALS_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/transfer-vk-specials.bin"));

#[cfg(feature = "no_vk")]
pub static VERIFIER_SPECIALS_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static ABAR_TO_BAR_VERIFIER_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/abar-to-bar-vk.bin"));

#[cfg(feature = "no_vk")]
pub static ABAR_TO_BAR_VERIFIER_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static BAR_TO_ABAR_VERIFIER_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/bar-to-abar-vk.bin"));

#[cfg(feature = "no_vk")]
pub static BAR_TO_ABAR_VERIFIER_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static AR_TO_ABAR_VERIFIER_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/ar-to-abar-vk.bin"));

#[cfg(feature = "no_vk")]
pub static AR_TO_ABAR_VERIFIER_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static ANON_FEE_VERIFIER_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/anon-fee-vk.bin"));

#[cfg(feature = "no_vk")]
pub static ANON_FEE_VERIFIER_PARAMS: Option<&'static [u8]> = None;

#[cfg(feature = "no_srs")]
lazy_static! {
    pub static ref LAGRANGE_BASES: BTreeMap<usize, &'static [u8]> = BTreeMap::default();
}

#[cfg(not(feature = "no_srs"))]
static LAGRANGE_BASE_4096: &'static [u8] = include_bytes!("../parameters/lagrange-srs-4096.bin");
#[cfg(not(feature = "no_srs"))]
static LAGRANGE_BASE_8192: &'static [u8] = include_bytes!("../parameters/lagrange-srs-8192.bin");
#[cfg(not(feature = "no_srs"))]
static LAGRANGE_BASE_16384: &'static [u8] = include_bytes!("../parameters/lagrange-srs-16384.bin");
#[cfg(not(feature = "no_srs"))]
static LAGRANGE_BASE_32768: &'static [u8] = include_bytes!("../parameters/lagrange-srs-32768.bin");

#[cfg(not(feature = "no_srs"))]
lazy_static! {
    pub static ref LAGRANGE_BASES: BTreeMap<usize, &'static [u8]> = {
        let mut m = BTreeMap::new();
        m.insert(4096, LAGRANGE_BASE_4096);
        m.insert(8192, LAGRANGE_BASE_8192);
        m.insert(16384, LAGRANGE_BASE_16384);
        m.insert(32768, LAGRANGE_BASE_32768);
        m
    };
}