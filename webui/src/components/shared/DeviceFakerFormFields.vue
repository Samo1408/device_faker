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

  <slot name="packages" />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from '../../utils/i18n'
import { useConfigStore } from '../../stores/config'
import { useDeviceFakerFormField } from '../../composables/useDeviceFakerForm'

const formData = useDeviceFakerFormField()

const { t } = useI18n()
const configStore = useConfigStore()

const availableCpuPresets = computed(() => {
  const presets = configStore.config.cpu_presets
  if (!presets) return []
  return Object.keys(presets)
})
</script>
