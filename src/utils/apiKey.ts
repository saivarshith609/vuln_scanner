export function generatePlatformApiKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `vsec_live_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}
