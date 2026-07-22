import { inject, provide, ref, type InjectionKey, type Ref } from 'vue'
import type { Template, AppConfig, TelephonyConfig } from '../types'

export const DEVICE_FAKER_FORM_KEY: InjectionKey<Ref<DeviceFakerFormData>> =
  Symbol('deviceFakerForm')

export interface DeviceFakerFormData {
  manufacturer: string
  brand: string
  model: string
  device: string
  product: string
  hardware: string
  name: string
  marketname: string
  fingerprint: string
  build_id: string
  android_version: string
  sdk_int: string
  characteristics: string
  force_denylist_unmount: boolean | undefined
  companion_resetprop: boolean | undefined
  packages: string[]
  cpu_spoof: string
  cpu_spoof_custom: string
  telephony?: TelephonyConfig
}

function createEmptyFormData(): DeviceFakerFormData {
  return {
    manufacturer: '',
    brand: '',
    model: '',
    device: '',
    product: '',
    hardware: '',
    name: '',
    marketname: '',
    fingerprint: '',
    build_id: '',
    android_version: '',
    sdk_int: '',
    characteristics: '',
    force_denylist_unmount: undefined,
    companion_resetprop: undefined,
    packages: [],
    cpu_spoof: '',
    cpu_spoof_custom: '',
    telephony: undefined,
  }
}

export function formDataToTemplate(formData: DeviceFakerFormData, base?: Template): Template {
  const template: Template = {
    ...(base || {}),
    manufacturer: formData.manufacturer,
    brand: formData.brand,
    model: formData.model,
    device: formData.device,
    product: formData.product,
    hardware: formData.hardware,
    fingerprint: formData.fingerprint,
  }

  if (formData.android_version) {
    template.android_version = formData.android_version
  } else {
    delete template.android_version
  }

  if (formData.build_id) {
    template.build_id = formData.build_id
  } else {
    delete template.build_id
  }

  if (formData.sdk_int) {
    const sdkInt = Number(formData.sdk_int)
    if (!isNaN(sdkInt)) {
      template.sdk_int = sdkInt
    } else {
      delete template.sdk_int
    }
  } else {
    delete template.sdk_int
  }

  if (formData.name) {
    template.name = formData.name
  } else {
    delete template.name
  }

  if (formData.marketname) {
    template.marketname = formData.marketname
  } else {
    delete template.marketname
  }

  if (formData.characteristics) {
    template.characteristics = formData.characteristics
  } else {
    delete template.characteristics
  }

  if (formData.force_denylist_unmount !== undefined) {
    template.force_denylist_unmount = formData.force_denylist_unmount
  }

  if (formData.companion_resetprop !== undefined) {
    template.companion_resetprop = formData.companion_resetprop
  }

  if (formData.packages.length > 0) {
    template.packages = formData.packages
  } else {
    delete template.packages
  }

  if (formData.cpu_spoof) {
    template.cpu_spoof = formData.cpu_spoof
  } else {
    delete template.cpu_spoof
  }

  if (formData.cpu_spoof_custom) {
    template.cpu_spoof_custom = formData.cpu_spoof_custom
  } else {
    delete template.cpu_spoof_custom
  }

  if (formData.telephony) {
    template.telephony = formData.telephony
  }

  return template
}

export function templateToFormData(template: Template): DeviceFakerFormData {
  return {
    manufacturer: template.manufacturer || '',
    brand: template.brand || '',
    model: template.model || '',
    device: template.device || '',
    product: template.product || '',
    hardware: template.hardware || '',
    name: template.name || '',
    marketname: template.marketname || '',
    fingerprint: template.fingerprint || '',
    build_id: template.build_id || '',
    android_version: template.android_version || '',
    sdk_int: template.sdk_int ? String(template.sdk_int) : '',
    characteristics: template.characteristics || '',
    force_denylist_unmount: template.force_denylist_unmount,
    companion_resetprop: template.companion_resetprop,
    packages: template.packages || [],
    cpu_spoof: template.cpu_spoof || '',
    cpu_spoof_custom: template.cpu_spoof_custom || '',
    telephony: template.telephony || undefined,
  }
}

export function appConfigToFormData(appConfig: AppConfig): DeviceFakerFormData {
  return {
    manufacturer: appConfig.manufacturer || '',
    brand: appConfig.brand || '',
    model: appConfig.model || '',
    device: appConfig.device || '',
    product: appConfig.product || '',
    hardware: appConfig.hardware || '',
    name: appConfig.name || '',
    marketname: appConfig.marketname || '',
    fingerprint: appConfig.fingerprint || '',
    build_id: appConfig.build_id || '',
    android_version: appConfig.android_version || '',
    sdk_int: appConfig.sdk_int ? String(appConfig.sdk_int) : '',
    characteristics: appConfig.characteristics || '',
    force_denylist_unmount: appConfig.force_denylist_unmount,
    companion_resetprop: appConfig.companion_resetprop,
    packages: [],
    cpu_spoof: appConfig.cpu_spoof || '',
    cpu_spoof_custom: appConfig.cpu_spoof_custom || '',
    telephony: appConfig.telephony || undefined,
  }
}

export function formDataToAppConfig(formData: DeviceFakerFormData, packageName: string): AppConfig {
  return {
    package: packageName,
    manufacturer: formData.manufacturer,
    brand: formData.brand,
    model: formData.model,
    device: formData.device,
    product: formData.product,
    hardware: formData.hardware,
    name: formData.name,
    marketname: formData.marketname,
    fingerprint: formData.fingerprint,
    build_id: formData.build_id,
    android_version: formData.android_version,
    sdk_int: formData.sdk_int ? Number(formData.sdk_int) : undefined,
    characteristics: formData.characteristics,
    force_denylist_unmount: formData.force_denylist_unmount,
    companion_resetprop: formData.companion_resetprop || undefined,
    cpu_spoof: formData.cpu_spoof || undefined,
    cpu_spoof_custom: formData.cpu_spoof_custom || undefined,
    telephony: formData.telephony || undefined,
  }
}

export function useDeviceFakerForm() {
  const formData = ref<DeviceFakerFormData>(createEmptyFormData())

  function resetForm() {
    formData.value = createEmptyFormData()
  }

  function fillFromTemplate(template: Template) {
    formData.value = templateToFormData(template)
  }

  function fillFromAppConfig(appConfig: AppConfig) {
    formData.value = appConfigToFormData(appConfig)
  }

  function toTemplate(base?: Template): Template {
    return formDataToTemplate(formData.value, base)
  }

  function toAppConfig(packageName: string): AppConfig {
    return formDataToAppConfig(formData.value, packageName)
  }

  return {
    formData,
    resetForm,
    fillFromTemplate,
    fillFromAppConfig,
    toTemplate,
    toAppConfig,
  }
}

export function provideDeviceFakerForm() {
  const form = useDeviceFakerForm()
  provide(DEVICE_FAKER_FORM_KEY, form.formData)
  return form
}

export function useDeviceFakerFormField() {
  const formData = inject(DEVICE_FAKER_FORM_KEY)
  if (!formData) {
    throw new Error(
      'useDeviceFakerFormField must be used within a provider of DEVICE_FAKER_FORM_KEY'
    )
  }
  return formData
}
