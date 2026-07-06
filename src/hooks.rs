use anyhow::Context;
use jni::{
    Env, EnvUnowned, jni_sig, jni_str,
    objects::{JClass, JValue},
    strings::JNIStr,
};

use crate::config::MergedAppConfig;

/// 根据合并配置 Hook android.os.Build 的静态字段。
pub fn hook_build_fields(
    env: &mut EnvUnowned,
    merged_config: &MergedAppConfig,
) -> anyhow::Result<()> {
    env.with_env(|jenv| -> Result<(), jni::errors::Error> {
        let build_class = jenv.find_class(jni_str!("android/os/Build"))?;

        if let Some(manufacturer) = &merged_config.manufacturer
            && !manufacturer.is_empty()
        {
            set_build_field(jenv, &build_class, jni_str!("MANUFACTURER"), manufacturer)
                .map_err(|_e| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;
        }

        if let Some(brand) = &merged_config.brand
            && !brand.is_empty()
        {
            set_build_field(jenv, &build_class, jni_str!("BRAND"), brand)
                .map_err(|_e| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;
        }

        if let Some(model) = &merged_config.model
            && !model.is_empty()
        {
            set_build_field(jenv, &build_class, jni_str!("MODEL"), model)
                .map_err(|_e| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;
        }

        if let Some(device) = &merged_config.device
            && !device.is_empty()
        {
            set_build_field(jenv, &build_class, jni_str!("DEVICE"), device)
                .map_err(|_e| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;
        }

        if let Some(product) = &merged_config.product
            && !product.is_empty()
        {
            set_build_field(jenv, &build_class, jni_str!("PRODUCT"), product)
                .map_err(|_e| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;
        }

        // HARDWARE 字段
        if let Some(hardware) = &merged_config.hardware
            && !hardware.is_empty()
        {
            set_build_field(jenv, &build_class, jni_str!("HARDWARE"), hardware)
                .map_err(|_e| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;
        }

        if let Some(fingerprint) = &merged_config.fingerprint
            && !fingerprint.is_empty()
        {
            set_build_field(jenv, &build_class, jni_str!("FINGERPRINT"), fingerprint)
                .map_err(|_e| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;
        }

        if let Some(build_id) = &merged_config.build_id
            && !build_id.is_empty()
        {
            set_build_field(jenv, &build_class, jni_str!("ID"), build_id)
                .map_err(|_e| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;
        }

        hook_version_fields(jenv, &build_class, merged_config)
            .map_err(|_e| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;

        Ok(())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>();
    Ok(())
}

fn hook_version_fields(
    env: &mut Env,
    _build_class: &JClass,
    merged_config: &MergedAppConfig,
) -> anyhow::Result<()> {
    let version_class = env
        .find_class(jni_str!("android/os/Build$VERSION"))
        .context("Failed to find Build.VERSION class")?;

    if let Some(android_version) = &merged_config.android_version
        && !android_version.is_empty()
    {
        set_build_field(env, &version_class, jni_str!("RELEASE"), android_version)?;
    }

    if let Some(sdk_int) = merged_config.sdk_int {
        set_build_int_field(env, &version_class, jni_str!("SDK_INT"), sdk_int as i32)?;
    }

    Ok(())
}

fn set_build_field(
    env: &mut Env,
    build_class: &JClass,
    field_name: &JNIStr,
    value: &str,
) -> anyhow::Result<()> {
    let _field_id = env
        .get_static_field_id(build_class, field_name, jni_sig!("Ljava/lang/String;"))
        .with_context(|| "Failed to get field ID".to_string())?;

    let new_value = env
        .new_string(value)
        .with_context(|| format!("Failed to create string for {value}"))?;

    env.set_static_field(
        build_class,
        field_name,
        jni_sig!("Ljava/lang/String;"),
        JValue::Object(&new_value),
    )
    .with_context(|| "Failed to set field".to_string())?;

    Ok(())
}

fn set_build_int_field(
    env: &mut Env,
    build_class: &JClass,
    field_name: &JNIStr,
    value: i32,
) -> anyhow::Result<()> {
    let _field_id = env
        .get_static_field_id(build_class, field_name, jni_sig!("I"))
        .with_context(|| "Failed to get field ID".to_string())?;

    env.set_static_field(build_class, field_name, jni_sig!("I"), JValue::Int(value))
        .with_context(|| "Failed to set field".to_string())?;

    Ok(())
}
