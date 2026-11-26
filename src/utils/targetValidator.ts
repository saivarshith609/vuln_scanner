/** Local target parsing for immediate UX feedback. The backend remains authoritative. */

export type TargetInputMode = 'single' | 'cidr' | 'range';

export interface TargetValidation {
  isValid: boolean;
  error?: string;
  addressCount?: number;
}

interface ParsedIp {
  family: 4 | 6;
  value: bigint;
  bits: 32 | 128;
}

const HOSTNAME_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

function parseIpv4(value: string): ParsedIp | null {
  const parts = value.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
  const octets = parts.map(Number);
  if (octets.some((part) => part < 0 || part > 255)) return null;
  return { family: 4, bits: 32, value: octets.reduce((total, part) => (total << 8n) + BigInt(part), 0n) };
}

function parseIpv6(value: string): ParsedIp | null {
  if (!value.includes(':') || value.includes(':::') || value.includes('.')) return null;
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if ([...left, ...right].some((part) => !/^[0-9a-fA-F]{1,4}$/.test(part))) return null;
  if ((halves.length === 1 && left.length !== 8) || (halves.length === 2 && left.length + right.length >= 8)) return null;
  const groups = halves.length === 2
    ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
    : left;
  let result = 0n;
  for (const group of groups) result = (result << 16n) + BigInt(`0x${group}`);
  return { family: 6, bits: 128, value: result };
}

function parseIp(value: string): ParsedIp | null {
  return parseIpv4(value) || parseIpv6(value);
}

export function validateSingleTarget(target: string): TargetValidation {
  const value = target.trim();
  if (!value) return { isValid: false, error: 'A single IP address or hostname is required.' };
  if (value.length > 255) return { isValid: false, error: 'Target cannot exceed 255 characters.' };
  if (/\s/.test(value)) return { isValid: false, error: 'Target cannot contain spaces.' };
  if (value.includes('/')) return { isValid: false, error: 'Choose CIDR subnet mode for a network prefix.' };
  if (value.includes(' - ') || value.includes(',')) return { isValid: false, error: 'Choose IP range mode for multiple addresses.' };
  if (parseIp(value) || HOSTNAME_RE.test(value)) return { isValid: true, addressCount: 1 };
  return { isValid: false, error: `"${value}" is not a valid IPv4 address, IPv6 address, or hostname.` };
}

export function validateCidrTarget(target: string, maxAddresses?: number): TargetValidation {
  const value = target.trim();
  const parts = value.split('/');
  if (parts.length !== 2) return { isValid: false, error: 'Enter a CIDR prefix such as 192.168.1.0/24.' };
  const address = parseIp(parts[0]);
  const prefix = Number(parts[1]);
  if (!address || !/^\d{1,3}$/.test(parts[1]) || prefix < 0 || prefix > address.bits) {
    return { isValid: false, error: 'Enter a valid IPv4 or IPv6 CIDR prefix.' };
  }
  const count = 1n << BigInt(address.bits - prefix);
  if (maxAddresses !== undefined && count > BigInt(maxAddresses)) {
    return { isValid: false, error: `Discovery scope exceeds the ${maxAddresses.toLocaleString()}-address safety limit.` };
  }
  return { isValid: true, addressCount: count <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(count) : undefined };
}

export function validateIpRange(startIp: string, endIp: string, maxAddresses = 4096): TargetValidation {
  const start = parseIp(startIp.trim());
  const end = parseIp(endIp.trim());
  if (!start || !end) return { isValid: false, error: 'Enter valid start and end IP addresses.' };
  if (start.family !== end.family) return { isValid: false, error: 'Range addresses must use the same IP family.' };
  if (start.value > end.value) return { isValid: false, error: 'Range start address must not exceed the end address.' };
  const count = end.value - start.value + 1n;
  if (count > BigInt(maxAddresses)) {
    return { isValid: false, error: `Discovery range exceeds the ${maxAddresses.toLocaleString()}-address safety limit.` };
  }
  return { isValid: true, addressCount: Number(count) };
}

/** Backwards-compatible validation used by Authorized Targets. */
export function validateTargetSyntax(target: string): TargetValidation {
  const value = target.trim();
  if (!value) return { isValid: false, error: 'Target address, network, or hostname is required.' };
  if (value.includes('/')) return validateCidrTarget(value);
  return validateSingleTarget(value);
}

export function detectTargetType(target: string): 'IPv4' | 'IPv6' | 'CIDR' | 'Hostname' {
  const value = target.trim();
  if (value.includes('/')) return 'CIDR';
  if (value.includes(':')) return 'IPv6';
  if (parseIpv4(value)) return 'IPv4';
  return 'Hostname';
}
