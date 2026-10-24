import { randomBytes } from '@echocrypt/crypto';

// No look-alike characters (0/O, 1/l/I), so a generated password can be copied by hand.
const ALPHABET = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/** 16 random characters in groups of four (~93 bits), e.g. "k7Rm-x2Qp-9Wzt-4Hfa". */
export function generatePassword(): string {
  // 224 is a multiple of ALPHABET.length (56), so rejecting bytes above it keeps the choice uniform.
  const chars: string[] = [];
  while (chars.length < 16) {
    for (const b of randomBytes(32)) {
      if (b < 224 && chars.length < 16) chars.push(ALPHABET[b % ALPHABET.length]!);
    }
  }
  return chars.join('').match(/.{4}/g)!.join('-');
}

/** 0-3: too short, weak, okay, strong. Only a hint; the real protection is PBKDF2 with 600k iterations. */
export function passwordStrength(pw: string): 0 | 1 | 2 | 3 {
  if (pw.length < 10) return 0;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z0-9]/].filter((r) => r.test(pw)).length;
  if (pw.length >= 16 || (pw.length >= 12 && classes >= 3)) return 3;
  if (pw.length >= 12 || classes >= 3) return 2;
  return 1;
}
