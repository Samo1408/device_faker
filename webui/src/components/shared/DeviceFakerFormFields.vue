<template>
  <el-form-item :label="t('templates.fields.manufacturer')">
    <el-input
      v-model="formData.manufacturer"
      :placeholder="t('templates.placeholders.manufacturer')"
    />
  </el-form-item>

  <el-form-item :label="t('templates.fields.brand')">
    <el-input v-model="formData.brand" :placeholder="t('templates.placeholders.brand')" />
  </el-form-item>

  <el-form-item :label="t('templates.fields.model')">
    <el-input v-model="formData.model" :placeholder="t('templates.placeholders.model')" />
  </el-form-item>

  <el-form-item :label="t('templates.fields.device')">
    <el-input v-model="formData.device" :placeholder="t('templates.placeholders.device')" />
  </el-form-item>

  <el-form-item :label="t('templates.fields.product')">
    <el-input v-model="formData.product" :placeholder="t('templates.placeholders.product')" />
  </el-form-item>

  <el-form-item :label="t('templates.fields.name_field')">
    <el-input v-model="formData.name" :placeholder="t('templates.placeholders.name_field')" />
  </el-form-item>

  <el-form-item :label="t('templates.fields.market_name')">
    <el-input
      v-model="formData.marketname"
      :placeholder="t('templates.placeholders.market_name')"
    />
  </el-form-item>

  <el-form-item :label="t('templates.fields.fingerprint')">
    <el-input
      v-model="formData.fingerprint"
      type="textarea"
      :rows="3"
      :placeholder="t('templates.placeholders.fingerprint')"
    />
  </el-form-item>

  <el-form-item :label="t('templates.fields.hardware')">
    <el-input v-model="formData.hardware" :placeholder="t('templates.placeholders.hardware')" />
  </el-form-item>

  <el-collapse>
    <el-collapse-item :title="t('templates.fields.system')" name="system">
      <el-form-item :label="t('templates.fields.build_id')">
        <el-input v-model="formData.build_id" :placeholder="t('templates.placeholders.build_id')" />
      </el-form-item>

      <el-form-item :label="t('templates.fields.android_version')">
        <el-input
          v-model="formData.android_version"
          :placeholder="t('templates.placeholders.android_version')"
        />
      </el-form-item>

      <el-form-item :label="t('templates.fields.sdk_int')">
        <el-input
          v-model="formData.sdk_int"
          type="number"
          :placeholder="t('templates.placeholders.sdk_int')"
        />
      </el-form-item>
    </el-collapse-item>
  </el-collapse>

  <el-form-item :label="t('templates.fields.characteristics')">
    <el-input
      v-model="formData.characteristics"
      :placeholder="t('templates.placeholders.characteristics')"
    />
  </el-form-item>

  <el-form-item :label="t('templates.fields.force_denylist_unmount')">
    <el-select
      v-model="formData.force_denylist_unmount"
      :placeholder="t('common.default')"
      style="width: 100%"
    >
      <el-option :label="t('common.default')" :value="undefined" />
      <el-option :label="t('common.enabled')" :value="true" />
      <el-option :label="t('common.disabled')" :value="false" />
    </el-select>
  </el-form-item>

  <el-form-item :label="t('templates.fields.companion_resetprop')">
    <el-select
      v-model="formData.companion_resetprop"
      :placeholder="t('common.default') + ' (' + t('common.disabled') + ')'"
      clearable
      style="width: 100%"
    >
      <el-option :label="t('common.enabled')" :value="true" />
      <el-option :label="t('common.disabled')" :value="false" />
    </el-select>
  </el-form-item>

  <el-collapse>
    <el-collapse-item :title="t('templates.fields.cpu')" name="cpu">
      <el-form-item :label="t('templates.fields.cpu_spoof')">
        <el-select
          v-model="formData.cpu_spoof"
          :placeholder="t('templates.placeholders.cpu_spoof')"
          clearable
          style="width: 100%"
        >
          <el-option v-for="name in availableCpuPresets" :key="name" :label="name" :value="name" />
        </el-select>
      </el-form-item>

      <el-form-item :label="t('templates.fields.cpu_spoof_custom')">
        <el-input
          v-model="formData.cpu_spoof_custom"
          type="textarea"
          :rows="8"
          :placeholder="t('templates.placeholders.cpu_spoof_custom')"
        />
      </el-form-item>
    </el-collapse-item>
  </el-collapse>


  <el-collapse>
    <el-collapse-item title="📱 Telephony / SIM Spoofing" name="telephony">
      <el-form-item label="Country (auto-fill MCC/MNC/Timezone)">
        <el-select
          v-model="formData.telephony.country_iso"
          placeholder="Select country..."
          clearable
          filterable
          style="width: 100%"
          @change="onCountrySelect"
        >
          <el-option
            v-for="c in countryPresets"
            :key="c.iso"
            :label="c.label"
            :value="c.iso"
          />
        </el-select>
      </el-form-item>

      <el-row :gutter="12">
        <el-col :span="12">
          <el-form-item label="MCC">
            <el-input v-model="formData.telephony.mcc" placeholder="e.g. 311" />
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="MNC">
            <el-input v-model="formData.telephony.mnc" placeholder="e.g. 480" />
          </el-form-item>
        </el-col>
      </el-row>

      <el-form-item label="Operator / Carrier Name">
        <el-input v-model="formData.telephony.operator_name" placeholder="e.g. Verizon" />
      </el-form-item>

      <el-form-item label="Timezone">
        <el-input v-model="formData.telephony.timezone" placeholder="e.g. America/Chicago" />
      </el-form-item>

      <el-form-item label="SIM Serial / ICCID">
        <el-row :gutter="8" style="width: 100%">
          <el-col :span="18">
            <el-input v-model="formData.telephony.sim_serial" placeholder="ICCID number" />
          </el-col>
          <el-col :span="6">
            <el-button @click="generateRandom('sim_serial', 20)" style="width: 100%">🎲</el-button>
          </el-col>
        </el-row>
      </el-form-item>

      <el-form-item label="Device Serial">
        <el-row :gutter="8" style="width: 100%">
          <el-col :span="18">
            <el-input v-model="formData.telephony.device_serial" placeholder="Device serial number" />
          </el-col>
          <el-col :span="6">
            <el-button @click="generateRandom('device_serial', 10)" style="width: 100%">🎲</el-button>
          </el-col>
        </el-row>
      </el-form-item>

      <el-divider content-position="left">SoC & Hardware IDs</el-divider>

      <el-form-item label="SoC Manufacturer">
        <el-input v-model="formData.telephony.soc_manufacturer" placeholder="e.g. Qualcomm" />
      </el-form-item>

      <el-form-item label="SoC Model">
        <el-input v-model="formData.telephony.soc_model" placeholder="e.g. Snapdragon 8 Gen 3" />
      </el-form-item>

      <el-form-item label="Bootloader">
        <el-input v-model="formData.telephony.bootloader" placeholder="Bootloader version" />
      </el-form-item>

      <el-form-item label="Baseband">
        <el-input v-model="formData.telephony.baseband" placeholder="Baseband version" />
      </el-form-item>

      <el-form-item label="ICCID">
        <el-row :gutter="8" style="width: 100%">
          <el-col :span="18">
            <el-input v-model="formData.telephony.iccid" placeholder="ICCID" />
          </el-col>
          <el-col :span="6">
            <el-button @click="generateRandom('iccid', 20)" style="width: 100%">🎲</el-button>
          </el-col>
        </el-row>
      </el-form-item>

      <el-form-item label="IP Address">
        <el-row :gutter="8" style="width: 100%">
          <el-col :span="18">
            <el-input v-model="formData.telephony.ip_address" placeholder="e.g. 192.168.1.100" />
          </el-col>
          <el-col :span="6">
            <el-button @click="generateRandomIP()" style="width: 100%">🎲</el-button>
          </el-col>
        </el-row>
      </el-form-item>

      <el-divider content-position="left">Hide System States</el-divider>

      <el-form-item label="Hide Airplane Mode">
        <el-switch v-model="formData.telephony.hide_airplane_mode" />
      </el-form-item>

      <el-form-item label="Hide Developer Options">
        <el-switch v-model="formData.telephony.hide_developer_mode" />
      </el-form-item>
    </el-collapse-item>
  </el-collapse>

  <slot name="packages" />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from '../../utils/i18n'
import { useConfigStore } from '../../stores/config'
import { useDeviceFakerFormField } from '../../composables/useDeviceFakerForm'
import { COUNTRY_PRESETS } from '../../types'

const formData = useDeviceFakerFormField()

const { t } = useI18n()
const configStore = useConfigStore()

const countryPresets = COUNTRY_PRESETS(() => {
  if (!formData.value.telephony) return
  const chars = '0123456789'
  let result = ''
  for (let i = 0; i < len; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  ;(formData.value.telephony as any)[field] = result
}

const generateRandomIP = () => {
  if (!formData.value.telephony) return
  const octet = () => Math.floor(Math.random() * 256)
  formData.value.telephony.ip_address = `${octet()}.${octet()}.${octet()}.${octet()}`
}

const availableCpuPresets = computed(() => {
  const presets = configStore.config.cpu_presets
  if (!presets) return []
  return Object.keys(presets)
})
</script>