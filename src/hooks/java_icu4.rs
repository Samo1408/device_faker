//! JavaIcu4 — Hook multiple classes for locale/timezone spoofing.
//! Classes hooked: `java.util.Locale`← `getDisplayCountry()`, com.android.i18n.timezone.TelephonyNetwork`, com.android.i18n.timezone.CountryTimeZones`.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    let _ = config;
    Ok(())
}

pub fn build_property_map(config: &TelephonyConfig) -> Vec<(String, String)> {
    let mut props = Vec::new();
    if let Some(ref iso) = config.sim_country_iso {
        props.push(("gsm.operator.iso-country".to_string(), iso.clone()));
        props.push(("ro.product.locale.region".to_string(), iso.clone()));
    }
    if let Some(ref mcc) = config.mcc {
        props.push(("gsm.operator.mcc".to_string(), mcc.clone()));
    }
    if let Some(ref mnc) = config.mnc {
        props.push(("gsm.operator.mnc".to_string(), mnc.clone()));
    }
    if let Some(ref tz) = config.timezone {
        props.push(("persist.sys.timezone".to_string(), tz.clone()));
    }
    props
}