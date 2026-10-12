import { parse as parseToml, stringify as stringifyToml } from 'smol-toml'
import { sanitizeConfigForSave, sanitizeTemplate } from './config'
import { execCommand } from './ksu'
import type { Template } from '../types'

const CLI_PATH_CANDIDATES = [
  '/data/adb/modules/device_faker/bin/device_faker_cli',
  '/data/adb/device_faker/bin/device_faker_cli',
]
const MAX_CHUNK_SIZE = 96 * 1024
const TEMPLATE_SIGNAL_KEYS = [
  'manufacturer',
  'brand',
  'model',
  'device',
  'product',
  'name',
  'marketname',
  'fingerprint',
  'build_id',
  'display_id',
  'incremental',
  'security_patch',
  'characteristics',
  'android_version',
  'sdk_int',
  'custom_props',
]

let cliPathLoader: Promise<string> | null = null

type UnknownRecord = Record<string, unknown>

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasTemplatePayload(value: unknown): boolean {
  if (!isRecord(value)) {
    return false
  }

  return TEMPLATE_SIGNAL_KEYS.some((key) => value[key] !== undefined)
}

function collectTemplates(source: UnknownRecord): Record<string, Template> {
  return Object.entries(source).reduce<Record<string, Template>>((result, [name, value]) => {
    const normalizedName = name.trim()
    if (!normalizedName || !hasTemplatePayload(value)) {
      return result
    }

    const template = sanitizeTemplate(value)
    if (Object.keys(template).length > 0) {
      result[normalizedName] = template
    }

    return result
  }, {})
}

function fileToBase64(chunk: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result as string
      resolve(result.split(',')[1] || '')
    }
    reader.onerror = (err) => reject(err)
    reader.readAsDataURL(chunk)
  })
}

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`
}

export async function resolveCliPath() {
  if (!cliPathLoader) {
    cliPathLoader = (async () => {
      for (const path of CLI_PATH_CANDIDATES) {
        try {
          await execCommand(`test -x ${shellQuote(path)}`)
          return path
        } catch {
          // try next candidate
        }
      }

      return CLI_PATH_CANDIDATES[0]
    })()
  }

  return cliPathLoader
}

export function createDeviceTempPath(prefix: string, extension: string) {
  const normalizedPrefix = prefix.replace(/[^a-zA-Z0-9_-]/g, '_')
  const normalizedExtension = extension.startsWith('.') ? extension : `.${extension}`
  return `/data/local/tmp/${normalizedPrefix}_${Date.now()}${normalizedExtension}`
}

export async function uploadFileToDevice(file: File, targetPath: string) {
  const dirEnd = targetPath.lastIndexOf('/')
  const targetDir = dirEnd > 0 ? targetPath.slice(0, dirEnd) : '/data/local/tmp'
  await execCommand(`mkdir -p ${shellQuote(targetDir)}`)

  const chunkSize =
    file.size > MAX_CHUNK_SIZE * 4
      ? MAX_CHUNK_SIZE
      : Math.max(4096, Math.ceil((file.size || 1) / 4))
  const totalChunks = Math.ceil((file.size || 1) / chunkSize)

  try {
    for (let index = 0; index < totalChunks; index++) {
      const start = index * chunkSize
      const end = Math.min(start + chunkSize, file.size)
      const chunk = file.slice(start, end)
      const base64 = await fileToBase64(chunk)
      const partPath = `${targetPath}.part${index.toString().padStart(8, '0')}`
      await execCommand(`echo ${shellQuote(base64)} | base64 -d > ${shellQuote(partPath)}`)
    }

    await execCommand(
      `cat ${shellQuote(targetPath)}.part* > ${shellQuote(targetPath)} && rm -f ${shellQuote(targetPath)}.part*`
    )
  } catch (error) {
    await execCommand(`rm -f ${shellQuote(targetPath)} ${shellQuote(targetPath)}.part*`).catch(
      () => {}
    )
    throw error
  }
}

async function runCliCommand(args: string[]) {
  const cliPath = await resolveCliPath()
  const command = [shellQuote(cliPath), ...args].join(' ')
  return execCommand(command)
}

export async function convertZipOnDevice(zipPath: string, outputPath: string) {
  await runCliCommand(['convert', '-i', shellQuote(zipPath), '-o', shellQuote(outputPath)])
}

export async function convertPropsFileOnDevice(propsPath: string, outputPath: string) {
  await runCliCommand(['convert-props', '-i', shellQuote(propsPath), '-o', shellQuote(outputPath)])
}

export async function dumpCurrentDeviceToToml(outputPath: string) {
  await runCliCommand(['dump-device', '-o', shellQuote(outputPath)])
}

/** Import a device catalog JSON entry (for example { id, brandLabel, modelLabel, profile }). */
function parseDeviceProfileJson(content: string): Record<string, Template> | null {
  let root: unknown
  try {
    root = JSON.parse(content)
  } catch {
    return null
  }
  if (!isRecord(root)) return null

  // Accept either one catalog entry, a { devices: [...] } catalog, or an array of entries.
  const candidates: unknown[] = Array.isArray(root) ? root :
    Array.isArray(root.devices) ? root.devices : [root]
  const result: Record<string, Template> = {}
  const propertyAliases: Record<string, string> = {
    bootloader: 'ro.bootloader',
    baseband: 'gsm.version.baseband',
    boardPlatform: 'ro.board.platform',
    socManufacturer: 'ro.soc.manufacturer',
    buildFlavor: 'ro.build.flavor',
    buildProduct: 'ro.build.product',
    buildDescription: 'ro.build.description',
  }

  for (const item of candidates) {
    if (!isRecord(item) || !isRecord(item.profile)) continue
    const profile = item.profile
    const template: Template = {}
    const copy = (source: string, target: keyof Template) => {
      const value = profile[source]
      if (typeof value === 'string' && value.trim()) {
        // Template fields are string-valued except numeric/boolean metadata.
        ;(template as unknown as Record<string, unknown>)[target] = value
      }
    }
    copy('manufacturer', 'manufacturer')
    copy('brand', 'brand')
    copy('model', 'model')
    copy('productName', 'name')
    copy('deviceCode', 'device')
    copy('productName', 'product')
    copy('hardware', 'hardware')
    copy('board', 'board')
    copy('socModel', 'soc_model')
    copy('buildFingerprint', 'fingerprint')
    copy('buildId', 'build_id')
    copy('buildDisplayId', 'display_id')
    copy('buildIncremental', 'incremental')
    copy('securityPatch', 'security_patch')
    copy('buildCharacteristics', 'characteristics')

    const androidVersion = profile.androidVersion
    if (typeof androidVersion === 'string' && androidVersion.trim()) template.android_version = androidVersion
    const customProps: Record<string, string> = {}
    for (const [key, value] of Object.entries(profile)) {
      if (typeof value !== 'string' || !value.trim()) continue
      const property = propertyAliases[key] || (key.startsWith('ro.') || key.startsWith('persist.') || key.startsWith('gsm.') ? key : '')
      if (property) customProps[property] = value
    }
    if (Object.keys(customProps).length) template.custom_props = customProps

    const name = typeof item.id === 'string' && item.id.trim()
      ? item.id.trim()
      : typeof item.modelLabel === 'string' && item.modelLabel.trim()
        ? item.modelLabel.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '')
        : `imported_device_${Object.keys(result).length + 1}`
    if (Object.keys(template).length) result[name] = template
  }
  return Object.keys(result).length ? result : null
}

export function parseTemplatesFromToml(content: string): Record<string, Template> {
  const trimmed = content.trim()
  if (!trimmed) {
    throw new Error('TOML content is empty')
  }

  const jsonTemplates = parseDeviceProfileJson(trimmed)
  if (jsonTemplates) return jsonTemplates

  let parsed: unknown
  try {
    parsed = parseToml(trimmed)
  } catch {
    throw new Error('Invalid TOML or device-profile JSON content')
  }

  if (isRecord(parsed) && isRecord(parsed.templates)) {
    const templates = collectTemplates(parsed.templates)
    if (Object.keys(templates).length > 0) {
      return templates
    }
  }

  if (hasTemplatePayload(parsed)) {
    const template = sanitizeTemplate(parsed)
    if (Object.keys(template).length > 0) {
      return { imported_template: template }
    }
  }

  if (isRecord(parsed)) {
    const templates = collectTemplates(parsed)
    if (Object.keys(templates).length > 0) {
      return templates
    }
  }

  throw new Error('No valid templates found in TOML content')
}

export function parseFirstTemplateFromToml(content: string): {
  templateData: Template
  defaultName: string
} {
  const templates = parseTemplatesFromToml(content)
  const [defaultName, templateData] = Object.entries(templates)[0] || []

  if (!defaultName || !templateData) {
    throw new Error('No valid template data found')
  }

  return {
    templateData,
    defaultName,
  }
}

export function stringifyTemplatesToToml(templates: Record<string, Template>) {
  if (Object.keys(templates).length === 0) {
    throw new Error('No templates selected')
  }

  const config = sanitizeConfigForSave({
    templates,
  })

  if (!config.templates || Object.keys(config.templates).length === 0) {
    throw new Error('No valid templates selected')
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return stringifyToml(config as any)
}

export async function copyTextToClipboard(text: string) {
  if (
    typeof navigator !== 'undefined' &&
    navigator.clipboard?.writeText &&
    typeof window !== 'undefined' &&
    window.isSecureContext
  ) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // fall through to legacy copy path
    }
  }

  if (typeof document === 'undefined') {
    return false
  }

  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.top = '-9999px'
  textarea.style.left = '-9999px'
  document.body.appendChild(textarea)

  try {
    textarea.select()
    textarea.setSelectionRange(0, text.length)
    return document.execCommand('copy')
  } catch {
    return false
  } finally {
    document.body.removeChild(textarea)
  }
}
