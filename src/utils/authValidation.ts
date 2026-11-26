export const USERNAME_REQUIREMENTS_TEXT =
  '6-64 characters, starting with an uppercase letter (A-Z), with at least one number (0-9) and one special character. Spaces are not allowed.';

export const PASSWORD_REQUIREMENTS_TEXT =
  '6-20 characters, including uppercase, lowercase, a number, and a special character. Spaces are allowed.';

/**
 * Validate username according to VulnScanner account rules.
 * Preserves case and never strips spaces (spaces are rejected).
 */
export function validateUsernamePolicy(username: string): string | null {
  if (/\s/.test(username)) {
    return 'Username cannot contain spaces.';
  }
  if (username.length < 6 || username.length > 64) {
    return 'Username must be between 6 and 64 characters.';
  }
  if (!/^[A-Z]/.test(username)) {
    return 'Username must start with an uppercase letter (A-Z).';
  }
  if (!/[0-9]/.test(username)) {
    return 'Username must contain at least one number (0-9).';
  }
  if (!/[^A-Za-z0-9\s]/.test(username)) {
    return 'Username must contain at least one special character.';
  }
  return null;
}

export interface ChecklistRequirement {
  id: string;
  label: string;
  met: boolean;
}

export function getUsernameChecklist(username: string): ChecklistRequirement[] {
  return [
    { id: 'length', label: 'At least 6 characters', met: username.length >= 6 },
    { id: 'starts-uppercase', label: 'Starts with an uppercase letter', met: /^[A-Z]/.test(username) },
    { id: 'number', label: 'Contains at least one number', met: /[0-9]/.test(username) },
    { id: 'special', label: 'Contains at least one special character', met: /[^A-Za-z0-9\s]/.test(username) },
    { id: 'no-spaces', label: 'Does not contain spaces', met: username.length > 0 && !/\s/.test(username) },
  ];
}

export function getPasswordChecklist(password: string): ChecklistRequirement[] {
  return [
    { id: 'min-length', label: 'At least 6 characters', met: password.length >= 6 },
    { id: 'max-length', label: 'Maximum 20 characters', met: password.length > 0 && password.length <= 20 },
    { id: 'uppercase', label: 'At least one uppercase letter', met: /[A-Z]/.test(password) },
    { id: 'lowercase', label: 'At least one lowercase letter', met: /[a-z]/.test(password) },
    { id: 'number', label: 'At least one number', met: /[0-9]/.test(password) },
    { id: 'special', label: 'At least one special character', met: /[^A-Za-z0-9\s]/.test(password) },
    { id: 'spaces-allowed', label: 'Spaces are allowed', met: password.length > 0 },
  ];
}

/**
 * Validate password according to VulnScanner account rules.
 * Spaces are allowed anywhere and are never trimmed or normalized.
 */
export function validatePasswordPolicy(password: string): string | null {
  if (password.length < 6 || password.length > 20) {
    return 'Password must be between 6 and 20 characters.';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password must contain at least one uppercase letter.';
  }
  if (!/[a-z]/.test(password)) {
    return 'Password must contain at least one lowercase letter.';
  }
  if (!/[0-9]/.test(password)) {
    return 'Password must contain at least one number.';
  }
  if (!/[^A-Za-z0-9\s]/.test(password)) {
    return 'Password must contain at least one special character.';
  }
  return null;
}
