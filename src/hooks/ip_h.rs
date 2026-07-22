//! IPH — Hook for IP address spoofing.
//! Hooks: `android.net.wifi.WifiInfo.getIpAddress()`, `java.net.Inet4Address.getAddress()`.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    let _ = config;
    Ok(())
}
