import { describe, expect, it } from 'vitest';
import {
  getPasswordChecklist,
  getUsernameChecklist,
  validatePasswordPolicy,
  validateUsernamePolicy,
} from '../utils/authValidation';

describe('username and password validation policies', () => {
  it('validates password length boundaries (6 to 20) and character classes', () => {
    expect(validatePasswordPolicy('Abc1!x')).toBeNull(); // exactly 6
    expect(validatePasswordPolicy('Abcdefghij12345678!x')).toBeNull(); // exactly 20
    expect(validatePasswordPolicy('Ab1!x')).toBe('Password must be between 6 and 20 characters.');
    expect(validatePasswordPolicy('Abcdefghij123456789!x')).toBe('Password must be between 6 and 20 characters.');
    expect(validatePasswordPolicy('abcdef1!')).toBe('Password must contain at least one uppercase letter.');
    expect(validatePasswordPolicy('ABCDEF1!')).toBe('Password must contain at least one lowercase letter.');
    expect(validatePasswordPolicy('Abcdef!')).toBe('Password must contain at least one number.');
    expect(validatePasswordPolicy('Abcdef1')).toBe('Password must contain at least one special character.');
  });

  it('allows spaces anywhere in passwords without treating space alone as a special character', () => {
    expect(validatePasswordPolicy(' Ab1!x')).toBeNull();
    expect(validatePasswordPolicy('Ab1!x ')).toBeNull();
    expect(validatePasswordPolicy('Ab 1!x')).toBeNull();
    expect(validatePasswordPolicy(' Ab 1!x ')).toBeNull();
    expect(validatePasswordPolicy('Abcdef1 ')).toBe('Password must contain at least one special character.');
  });

  it('enforces username rules (min 6, uppercase first, number, special char, no spaces)', () => {
    expect(validateUsernamePolicy('Alice_1')).toBeNull();
    expect(validateUsernamePolicy('ALICE_1')).toBeNull(); // uppercase-only with number + special
    expect(validateUsernamePolicy('A1!XYZ')).toBeNull(); // exactly 6, uppercase + number + special
    expect(validateUsernamePolicy('Ab_1!')).toBe('Username must be between 6 and 64 characters.');
    expect(validateUsernamePolicy('alice_1')).toBe('Username must start with an uppercase letter (A-Z).');
    expect(validateUsernamePolicy('1Alice_')).toBe('Username must start with an uppercase letter (A-Z).');
    expect(validateUsernamePolicy('Alice_!')).toBe('Username must contain at least one number (0-9).');
    expect(validateUsernamePolicy('Alice12')).toBe('Username must contain at least one special character.');
    expect(validateUsernamePolicy('Alice 1!')).toBe('Username cannot contain spaces.');
    expect(validateUsernamePolicy(' Alice_1')).toBe('Username cannot contain spaces.');
  });

  it('computes real-time username and password checklist item states', () => {
    expect(getUsernameChecklist('').every((item) => !item.met)).toBe(true);
    expect(getUsernameChecklist('Alice_1').every((item) => item.met)).toBe(true);
    expect(getPasswordChecklist('').every((item) => !item.met)).toBe(true);
    expect(getPasswordChecklist(' Ab1!x ').every((item) => item.met)).toBe(true);
    const overMax = getPasswordChecklist('Abcdefghij123456789!x');
    expect(overMax.find((item) => item.id === 'max-length')?.met).toBe(false);
  });
});
