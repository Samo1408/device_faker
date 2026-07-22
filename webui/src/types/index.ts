export type OnlineTemplateSource = 'gitee' | 'github'
export type OnlineTemplateLoadState = 'idle' | 'loading' | 'ready' | 'error'
export type OnlineTemplateDetailsState = 'idle' | 'loading' | 'partial' | 'complete' | 'error'
export type TemplateCategory = 'common' | 'gaming' | 'transcend'
export type TemplateCategoryFilter = TemplateCategory | 'all'

export interface CustomProps {
  [key: string]: string
}

// ── Telephony / SIM spoofing config ──
export interface CountryPreset {
  iso: string
  label: string
  mcc: string
  mnc: string
  timezone: string
  lat: number
  lon: number
}

export interface TelephonyConfig {
  country_iso?: string
  sim_country_iso?: string
  mcc?: string
  mnc?: string
  operator_name?: string
  sim_serial?: string
  timezone?: string
  device_serial?: string
  soc_manufacturer?: string
  soc_model?: string
  bootloader?: string
  baseband?: string
  iccid?: string
  ip_address?: string
  hide_airplane_mode?: boolean
  hide_developer_mode?: boolean
  country_source?: string
}

// Built-in country presets (mirrors Rust COUNTRY_PRESETS)
export const COUNTRY_PRESETS: CountryPreset[] = [
  { iso: "us", label: "United States 🇺🇸", mcc: "311", mnc: "480", timezone: "America/Chicago", lat: 41.8781, lon: -87.6298 },
  { iso: "gb", label: "United Kingdom 🇬🇧", mcc: "234", mnc: "15", timezone: "Europe/London", lat: 51.5074, lon: -0.1278 },
  { iso: "de", label: "Germany 🇩🇪", mcc: "262", mnc: "01", timezone: "Europe/Berlin", lat: 52.5200, lon: 13.4050 },
  { iso: "fr", label: "France 🇫🇷", mcc: "208", mnc: "01", timezone: "Europe/Paris", lat: 48.8566, lon: 2.3522 },
  { iso: "it", label: "Italy 🇮🇹", mcc: "222", mnc: "01", timezone: "Europe/Rome", lat: 41.9028, lon: 12.4964 },
  { iso: "es", label: "Spain 🇪🇸", mcc: "214", mnc: "01", timezone: "Europe/Madrid", lat: 40.4168, lon: -3.7038 },
  { iso: "nl", label: "Netherlands 🇳🇱", mcc: "204", mnc: "04", timezone: "Europe/Amsterdam", lat: 52.3676, lon: 4.9041 },
  { iso: "se", label: "Sweden 🇸🇪", mcc: "240", mnc: "01", timezone: "Europe/Stockholm", lat: 59.3293, lon: 18.0686 },
  { iso: "no", label: "Norway 🇳🇴", mcc: "242", mnc: "01", timezone: "Europe/Oslo", lat: 59.9139, lon: 10.7522 },
  { iso: "ch", label: "Switzerland 🇨🇭", mcc: "228", mnc: "01", timezone: "Europe/Zurich", lat: 47.3769, lon: 8.5417 },
  { iso: "ca", label: "Canada 🇨🇦", mcc: "302", mnc: "720", timezone: "America/Toronto", lat: 43.6532, lon: -79.3832 },
  { iso: "mx", label: "Mexico 🇲🇽", mcc: "334", mnc: "020", timezone: "America/Mexico_City", lat: 19.4326, lon: -99.1332 },
  { iso: "br", label: "Brazil 🇧🇷", mcc: "724", mnc: "05", timezone: "America/Sao_Paulo", lat: -23.5505, lon: -46.6333 },
  { iso: "jp", label: "Japan 🇯🇵", mcc: "440", mnc: "10", timezone: "Asia/Tokyo", lat: 35.6762, lon: 139.6503 },
  { iso: "kr", label: "South Korea 🇰🇷", mcc: "450", mnc: "05", timezone: "Asia/Seoul", lat: 37.5665, lon: 126.9780 },
  { iso: "in", label: "India 🇮🇳", mcc: "405", mnc: "01", timezone: "Asia/Kolkata", lat: 28.6139, lon: 77.2090 },
  { iso: "sg", label: "Singapore 🇸🇬", mcc: "525", mnc: "01", timezone: "Asia/Singapore", lat: 1.3521, lon: 103.8198 },
  { iso: "au", label: "Australia 🇦🇺", mcc: "505", mnc: "01", timezone: "Australia/Sydney", lat: -33.8688, lon: 151.2093 },
  { iso: "ae", label: "UAE 🇦🇪", mcc: "424", mnc: "02", timezone: "Asia/Dubai", lat: 25.2048, lon: 55.2708 },
  { iso: "sa", label: "Saudi Arabia 🇸🇦", mcc: "420", mnc: "01", timezone: "Asia/Riyadh", lat: 24.7136, lon: 46.6753 },
  { iso: "tr", label: "Turkey 🇹🇷", mcc: "286", mnc: "01", timezone: "Europe/Istanbul", lat: 41.0082, lon: 28.9784 },
  { iso: "ru", label: "Russia 🇷🇺", mcc: "250", mnc: "01", timezone: "Europe/Moscow", lat: 55.7558, lon: 37.6173 },
]

// 设备信息接口
export interface DeviceInfo {
  manufacturer?: string
  brand?: string
  model?: string
  device?: string
  product?: string
  hardware?: string
  name?: string
  marketname?: string
  fingerprint?: string
  build_id?: string
  characteristics?: string
  android_version?: string
  sdk_int?: number
  custom_props?: CustomProps
  force_denylist_unmount?: boolean
  companion_resetprop?: boolean
  cpu_spoof?: string
  cpu_spoof_custom?: string
  telephony?: TelephonyConfig
}

// 机型模板接口
export interface Template extends DeviceInfo {
  packages?: string[]
  version?: string
  version_code?: number
  author?: string
  description?: string
}

// 应用配置接口
export interface AppConfig extends DeviceInfo {
  package: string
}

export interface TemplateMeta {
  version?: string
  version_code?: number
  author?: string
  description?: string
}

export interface OnlineTemplateIndexItem {
  id: string
  name: string
  displayName: string
  category: TemplateCategory
  brand: string | null
  path: string
  sha?: string
  source: OnlineTemplateSource
  contentUrl: string
}

export interface OnlineTemplateDetail {
  template: Template
  meta?: TemplateMeta
}

export interface OnlineTemplateDetailState {
  status: OnlineTemplateLoadState
  detail?: OnlineTemplateDetail
  error?: string | null
  updatedAt?: number
  version?: string
}

export interface OnlineTemplateRecord extends OnlineTemplateIndexItem {
  detailStatus: OnlineTemplateLoadState
  detail?: OnlineTemplateDetail
  detailError?: string | null
}

export interface OnlineTemplateProgress {
  total: number
  resolved: number
  succeeded: number
  failed: number
}

export interface OnlineTemplateLoadSession {
  id: number
  preferredSource: OnlineTemplateSource
  resolvedSource?: OnlineTemplateSource
  startedAt: number
}

export interface OnlineTemplateCacheEntry<T> {
  schemaVersion: number
  createdAt: number
  expiresAt: number
  data: T
  version?: string
}

// 配置文件接口
export interface Config {
  default_force_denylist_unmount?: boolean
  debug?: boolean
  default_cpu_spoof?: string
  cpu_presets?: Record<string, string>
  templates?: Record<string, Template>
  apps?: AppConfig[]
  telephony?: TelephonyConfig
}

// 已安装应用接口
export interface InstalledApp {
  packageName: string
  appName: string
  icon?: string
  versionName?: string
  versionCode?: number
  installed?: boolean
  isSystem?: boolean
}

// 设置接口
export interface Settings {
  theme: 'system' | 'light' | 'dark'
  language: 'system' | 'zh' | 'en' | 'tr'
  showSystemApps: boolean
  onlineTemplateSource: OnlineTemplateSource
}
