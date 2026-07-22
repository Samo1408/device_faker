//! SemH — Hook `android.os.SemSystemProperties` (Samsung-specific).

//! Values spoofed: getCountryCode(), getCountryIso(), getDeviceSerialNumber(),
//! getSalesCode(), ro.hardware.chipname, ro.bootloader, ro.baseband.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    // SemSystemProperties values are backed by regular system properties.
    // We rely on companion resetprop to set: ro.csc.country_code, ro.csc.countryiso_code,
    // ro.serialno, ro.csc.sales_code, ro.hardware.chipname, ro.bootloader, ro.baseband.
    let _ = config;
    Ok(())
}