// Normalize package name by stripping trailing user suffix like "com.foo@10"
export function normalizePackageName(packageName: string): string {
  const match = packageName.match(/^(.*)@\d+$/)
  return match ? match[1] : packageName
}

// Parse package name into base name and userId, e.g. "com.foo@999" -> { base: "com.foo", userId: 999 }
export function parsePackageUser(packageName: string): { base: string; userId: number } {
  const match = packageName.match(/^(.*)@(\d+)$/)
  if (!match) return { base: packageName, userId: 0 }
  return { base: match[1], userId: Number(match[2]) }
}
