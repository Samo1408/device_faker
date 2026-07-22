#[cfg(target_os = "android")]
mod atexit;
mod companion;
mod config;
mod cow_props;
mod cpu_spoof;
#[cfg(target_os = "android")]
mod file_logger;
mod build_hooks;
mod hooks;

use std::{collections::HashMap, fs, path::Path};

use anyhow::Context;
use companion::{handle_companion_request, spoof_system_props_via_companion};
use config::Config;
use cpu_spoof::apply_cpu_spoof;
use build_hooks::hook_build_fields;
use hooks::apply_telephony_hooks;
use jni::{EnvUnowned, errors::ThrowRuntimeExAndDefault};
use log::{LevelFilter, error, info};
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
        api.set_option(ZygiskOption::DlCloseModuleLibrary);
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

        // Flush log buffer before pre_app_specialize returns, ensuring all logs from
        // on_load + specialize are sent to companion for writing.
        if let Err(e) = flush_log_buffer_to_companion(api) {
            // Don't use error! here - it would produce new log entries we can't flush.
            // Fail silently; logs will be lost.
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

        // Companion now manages session state and restore logic independently;
        // Zygisk module no longer needs cross-app restore (ACTIVE_RESET_SESSION removed).

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

        // ── Unified execution flow (on-demand dispatch) ──────────────────────
        // ① JNI field override (always executed)
        hook_build_fields(env, &merged)?;
        if config.debug {
            info!("Build fields faked successfully");
        }

        // ②-ter Telephony / SIM / Country spoofing hooks
        apply_telephony_hooks(env, &merged.telephony_config)?;
        if config.debug {
            info!("Telephony hooks applied successfully");
        }

        // ②-bis Clear matching prop areas from /proc/self/maps (anti-detection)
        if !merged.hide_maps.is_empty() {
            cow_props::unmap_prop_areas(&merged.hide_maps);
        }

        // ② COW property spoofing (per-process, intercepts native reads, zero-resident)
        //    When companion_resetprop=true, skip COW and delegate to companion (global effect)
        let prop_map = Config::build_merged_property_map(&merged);
        if config.debug {
            info!("Property map: {} entries", prop_map.len());
        }

        if merged.companion_resetprop {
            // All props via companion resetprop (getprop and in-process reads are consistent)
            let delete_props = Config::build_delete_props_list(&merged);
            if !prop_map.is_empty() || !delete_props.is_empty() {
                if let Err(e) =
                    spoof_system_props_via_companion(api, &prop_map, &delete_props, &package_name)
                {
                    error!("Companion resetprop (full) failed: {e:?}");
                } else if config.debug {
                    info!(
                        "Companion resetprop (full): {} set + {} delete for {package_name}",
                        prop_map.len(),
                        delete_props.len()
                    );
                }
            }
        } else {
            // Default path: COW handles found props; companion handles unfound + __DELETE__
            let unfound_props = match cow_props::apply_cow_spoof(&prop_map) {
                Ok(unfound) => unfound,
                Err(e) => {
                    error!("COW spoof failed: {e:?}");
                    Vec::new()
                }
            };

            let delete_props = Config::build_delete_props_list(&merged);
            if !unfound_props.is_empty() || !delete_props.is_empty() {
                let unfound_map: HashMap<String, String> = unfound_props.into_iter().collect();
                if let Err(e) = spoof_system_props_via_companion(
                    api,
                    &unfound_map,
                    &delete_props,
                    &package_name,
                ) {
                    error!("Companion resetprop failed: {e:?}");
                } else if config.debug {
                    info!(
                        "Companion resetprop: {} new + {} delete for {package_name}",
                        unfound_map.len(),
                        delete_props.len()
                    );
                }
            }
        }

        // ④ Companion on-demand: CPU spoof (only when cpu_spoof is configured)
        if merged.cpuinfo_content.is_some() {
            if let Err(e) = apply_cpu_spoof(api, &merged, &package_name, config.debug) {
                error!("CPU spoof failed: {e:?}");
            } else if config.debug {
                info!("CPU spoof applied for {package_name}");
            }
        }

        // ⑤ DlClose (always executed)
        api.set_option(ZygiskOption::DlCloseModuleLibrary);
        Ok(())
    }

    fn extract_android_user_id(args: &<V4 as ZygiskRaw>::AppSpecializeArgs) -> u32 {
        // Android app UID = userId * 100000 + appId
        // userId here maps to the number in /data/user/<userId>/
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
