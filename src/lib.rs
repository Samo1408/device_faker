#[cfg(target_os = "android")]
mod atexit;
mod companion;
mod config;
mod cow_props;
mod cpu_spoof;
#[cfg(target_os = "android")]
mod file_logger;
mod hooks;
mod state;

use std::{collections::HashMap, fs, path::Path};

use anyhow::Context;
use companion::{
    handle_companion_request, restore_previous_resetprop_if_needed,
    spoof_system_props_via_companion,
};
use config::{Config, MergedAppConfig};
use cpu_spoof::apply_cpu_spoof;
use hooks::{hook_build_fields, hook_native_property_get, hook_system_properties};
use jni::{EnvUnowned, errors::ThrowRuntimeExAndDefault};
use log::{LevelFilter, error, info};
use state::{FAKE_PROPS, IS_FULL_MODE};
use zygisk_api::{
    ZygiskModule,
    api::{V4, ZygiskApi, v4::ZygiskOption},
    raw::ZygiskRaw,
};

const CONFIG_PATH: &str = "/data/adb/device_faker/config/config.toml";

#[derive(Default)]
struct MyModule;

impl ZygiskModule for MyModule {
    type Api = V4;

    fn on_load(&self, _api: ZygiskApi<V4>, _env: EnvUnowned) {
        #[cfg(target_os = "android")]
        file_logger::init_buffer_only();
    }

    fn pre_app_specialize(
        &self,
        mut api: ZygiskApi<V4>,
        mut env: EnvUnowned,
        args: &mut <V4 as ZygiskRaw>::AppSpecializeArgs,
    ) {
        if let Err(err) = self.handle_app_specialize(&mut api, &mut env, args) {
            error!("pre_app_specialize failed: {err:?}");
        }
    }

    fn post_app_specialize(
        &self,
        mut api: ZygiskApi<V4>,
        _env: EnvUnowned,
        _args: &<V4 as ZygiskRaw>::AppSpecializeArgs,
    ) {
        if !IS_FULL_MODE.load(std::sync::atomic::Ordering::Relaxed) {
            api.set_option(ZygiskOption::DlCloseModuleLibrary);
        }
    }

    fn pre_server_specialize(
        &self,
        mut api: ZygiskApi<V4>,
        _env: EnvUnowned,
        _args: &mut <V4 as ZygiskRaw>::ServerSpecializeArgs,
    ) {
        api.set_option(ZygiskOption::DlCloseModuleLibrary);
    }
}

impl MyModule {
    fn handle_app_specialize(
        &self,
        api: &mut ZygiskApi<V4>,
        env: &mut EnvUnowned,
        args: &mut <V4 as ZygiskRaw>::AppSpecializeArgs,
    ) -> anyhow::Result<()> {
        let result = self.do_handle_app_specialize(api, env, args);

        // 在 pre_app_specialize 退出前统一 flush，确保 on_load + specialize 期间
        // 产生的所有日志都能发给 companion 落盘。
        if let Err(e) = flush_log_buffer_to_companion(api) {
            // 这里不能用 error!，否则会产生新的日志又无法 flush。
            // 静默失败，日志将丢失。
            let _ = e;
        }

        result
    }

    fn do_handle_app_specialize(
        &self,
        api: &mut ZygiskApi<V4>,
        env: &mut EnvUnowned,
        args: &mut <V4 as ZygiskRaw>::AppSpecializeArgs,
    ) -> anyhow::Result<()> {
        let package_name = Self::extract_package_name(env, args)?;
        let user_id = Self::extract_android_user_id(args);
        let package_with_user = format!("{package_name}@{user_id}");
        restore_previous_resetprop_if_needed(api, &package_with_user)?;

        let config = match load_config() {
            Ok(Some(cfg)) => cfg,
            Ok(None) => {
                api.set_option(ZygiskOption::DlCloseModuleLibrary);
                return Ok(());
            }
            Err(err) => {
                error!("Failed to load config: {err:#}");
                api.set_option(ZygiskOption::DlCloseModuleLibrary);
                return Ok(());
            }
        };

        configure_log_level(config.debug);

        if config.debug {
            info!(
                "Config loaded with {} apps and {} templates",
                config.apps.len(),
                config.templates.len()
            );
        }

        let merged = config
            .get_merged_config(&package_with_user)
            .or_else(|| config.get_merged_config(&package_name));

        let Some(merged) = merged else {
            if config.debug {
                info!("App {package_name} (user {user_id}) not in config, unloading module");
            }
            api.set_option(ZygiskOption::DlCloseModuleLibrary);
            return Ok(());
        };

        if merged.force_denylist_unmount {
            api.set_option(ZygiskOption::ForceDenylistUnmount);
            if config.debug {
                info!("Force denylist unmount enabled for {package_name}");
            }
        }

        // ── 降级路径：显式 mode = "full" 时使用旧 PLT hook 实现 ──────────────
        if merged.mode == "full" {
            return Self::apply_full_mode_legacy(api, env, &merged, config.debug);
        }

        // ── 统一执行流（按需调度）──────────────────────────────────────────
        // ① JNI 字段覆写（始终执行）
        hook_build_fields(env, &merged)?;
        if config.debug {
            info!("Build fields faked successfully");
        }

        // ①-bis 清除 /proc/self/maps 中匹配模式的属性映射（anti-detection）
        if !merged.hide_maps.is_empty() {
            cow_props::unmap_prop_areas(&merged.hide_maps);
        }

        // ② COW 属性伪造（per-process，覆盖 native 读取，零模块驻留）
        //    返回未找到的属性列表，交给 companion resetprop 处理
        let prop_map = Config::build_merged_property_map(&merged);
        if config.debug {
            info!("Property map: {} entries", prop_map.len());
        }
        let unfound_props = match cow_props::apply_cow_spoof(&prop_map) {
            Ok(unfound) => unfound,
            Err(e) => {
                error!("COW spoof failed: {e:?}");
                Vec::new()
            }
        };

        // ③ Companion 按需：未找到属性 + __DELETE__ 属性
        //    companion resetprop 有 restore watcher，切后台自动恢复
        let delete_props = Config::build_delete_props_list(&merged);
        if !unfound_props.is_empty() || !delete_props.is_empty() {
            let unfound_map: HashMap<String, String> = unfound_props.into_iter().collect();
            if let Err(e) =
                spoof_system_props_via_companion(api, &unfound_map, &delete_props, &package_name)
            {
                error!("Companion resetprop failed: {e:?}");
            } else if config.debug {
                info!(
                    "Companion resetprop: {} new + {} delete for {package_name}",
                    unfound_map.len(),
                    delete_props.len()
                );
            }
        }

        // ④ Companion 按需：CPU spoof（仅 cpu_spoof 配置时）
        if merged.cpuinfo_content.is_some() {
            if let Err(e) = apply_cpu_spoof(api, &merged, &package_name, config.debug) {
                error!("CPU spoof failed: {e:?}");
            } else if config.debug {
                info!("CPU spoof applied for {package_name}");
            }
        }

        // ⑤ DlClose（始终执行）
        api.set_option(ZygiskOption::DlCloseModuleLibrary);
        Ok(())
    }

    fn extract_android_user_id(args: &<V4 as ZygiskRaw>::AppSpecializeArgs) -> u32 {
        // Android 的 app UID = userId * 100000 + appId
        // 这里的 userId 对应 /data/user/<userId>/... 里的数字
        const AID_USER_OFFSET: u32 = 100_000;
        let uid = *args.uid;
        if uid <= 0 {
            return 0;
        }
        (uid as u32) / AID_USER_OFFSET
    }

    fn extract_package_name(
        env: &mut EnvUnowned,
        args: &<V4 as ZygiskRaw>::AppSpecializeArgs,
    ) -> anyhow::Result<String> {
        let result: String = env
            .with_env(|_jenv| -> Result<String, jni::errors::Error> {
                let app_data_dir = args.app_data_dir.to_string();

                if let Some(package) = app_data_dir.rsplit('/').next()
                    && !package.is_empty()
                {
                    return Ok(package.to_string());
                }

                let nice_name = args.nice_name.to_string();

                let mut nice_name: String = nice_name;
                if let Some(idx) = nice_name.find(':') {
                    nice_name.truncate(idx);
                }

                Ok(nice_name)
            })
            .resolve::<ThrowRuntimeExAndDefault>();
        Ok(result)
    }

    /// 降级路径：显式 `mode = "full"` 时使用旧 PLT hook 实现。
    ///
    /// 当 COW 在某设备不兼容时，用户可设置 `mode = "full"` 回退到此路径。
    /// 保留 hooks.rs 中的 `hook_system_properties` / `hook_native_property_get`。
    fn apply_full_mode_legacy(
        api: &mut ZygiskApi<V4>,
        env: &mut EnvUnowned,
        merged: &MergedAppConfig,
        debug: bool,
    ) -> anyhow::Result<()> {
        if debug {
            info!("Full mode (legacy PLT hook): faking SystemProperties");
        }

        hook_build_fields(env, merged)?;
        if debug {
            info!("Build fields faked successfully");
        }

        if !merged.hide_maps.is_empty() {
            cow_props::unmap_prop_areas(&merged.hide_maps);
        }

        let prop_map = Config::build_merged_property_map(merged);
        if debug {
            info!("Property map created with {} entries", prop_map.len());
        }

        *FAKE_PROPS.lock().unwrap() = prop_map;
        IS_FULL_MODE.store(true, std::sync::atomic::Ordering::Relaxed);
        hook_system_properties(api, env)?;
        hook_native_property_get(api)?;

        if debug {
            info!("SystemProperties faked successfully, module will stay loaded");
        }

        Ok(())
    }
}

fn load_config() -> anyhow::Result<Option<Config>> {
    if !Path::new(CONFIG_PATH).exists() {
        return Ok(None);
    }

    let config_content = fs::read_to_string(CONFIG_PATH)
        .with_context(|| format!("Failed to read config at {CONFIG_PATH}"))?;
    let config = Config::from_toml(&config_content)?;
    Ok(Some(config))
}

fn configure_log_level(debug_enabled: bool) {
    let level = if debug_enabled {
        LevelFilter::Info
    } else {
        LevelFilter::Error
    };
    log::set_max_level(level);
}

fn flush_log_buffer_to_companion(api: &mut ZygiskApi<V4>) -> anyhow::Result<()> {
    let lines = file_logger::drain_lines();
    if lines.is_empty() {
        return Ok(());
    }

    let request = companion::CompanionRequest::WriteLog(companion::WriteLogRequest { lines });
    let response = companion::send_companion_command(api, &request)?;
    if response.status != 0 {
        anyhow::bail!(
            response
                .message
                .unwrap_or_else(|| "companion write log failed".to_string())
        );
    }
    Ok(())
}

// Note: The register_module macro should handle the EnvUnowned properly
// The unwrap_unchecked issue is a macro expansion problem in jni 0.22
// We'll let the macro handle this internally
zygisk_api::register_module!(MyModule);
zygisk_api::register_companion!(handle_companion_request);
