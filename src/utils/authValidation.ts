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
