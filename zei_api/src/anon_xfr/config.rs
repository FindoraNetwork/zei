use crate::xfr::structs::{AssetType, ASSET_TYPE_LENGTH};

const ASSET_TYPE_FRA: AssetType = AssetType([0; ASSET_TYPE_LENGTH]);
pub const FEE_TYPE: AssetType = ASSET_TYPE_FRA;

pub const FEE_CALCULATING_FUNC: fn(u32, u32) -> u32 = |x: u32, y: u32| {
    let extra_outputs = y.checked_sub(x).unwrap_or(0);
    50_0000 + 10_0000 * x + 20_0000 * y + (10_000 * extra_outputs)
};
