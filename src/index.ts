interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * Password strength analysis MCP.
 *
 * Keyless, fully offline: estimates entropy from the character-set pool + length,
 * classifies strength, estimates crack time, and flags weaknesses (too short,
 * missing character classes, sequences/repeats, common passwords). The password
 * is analyzed in-process and is NOT sent anywhere or stored. Heuristic estimate,
 * not a guarantee.
 */


const COMMON = new Set([
  'password', '123456', '123456789', '12345678', '12345', 'qwerty', 'abc123', 'password1',
  'iloveyou', 'admin', 'welcome', 'monkey', 'letmein', 'dragon', 'football', '111111',
  '1234567', '000000', 'qwerty123', 'sunshine', 'princess', 'passw0rd', 'login', 'starwars',
]);

function humanTime(seconds: number): string {
  if (seconds < 1) return 'instant';
  const u: [number, string][] = [[60, 'second'], [60, 'minute'], [24, 'hour'], [365, 'day'], [100, 'year'], [Infinity, 'century']];
  let v = seconds, i = 0, name = 'second', div = 1;
  for (const [d, n] of u) { if (v < d * div || d === Infinity) { name = n; break; } div *= d; i++; }
  const val = seconds / div;
  if (val > 1e6) return `${(val).toExponential(1)} ${name}s`;
  return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${name}${val >= 2 ? 's' : ''}`;
}

const tools: McpToolExport['tools'] = [
  {
    name: 'check_password',
    description:
      'Analyze a password\'s strength offline (keyless): character-set entropy, a strength rating, estimated crack time (offline fast + online throttled attacker), and specific weaknesses (length, missing character classes, sequences/repeats, common passwords). The password is NOT transmitted or stored — analysis is in-process. Heuristic, not a guarantee.',
    inputSchema: { type: 'object', properties: { password: { type: 'string', description: 'The password to analyze.' } }, required: ['password'] },
  },
];

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  if (name !== 'check_password') throw new Error(`Unknown tool: ${name}`);
  const pw = args.password;
  if (typeof pw !== 'string' || pw.length === 0) throw new Error('Required argument "password" is missing (a non-empty string).');

  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const entropy = +(pw.length * Math.log2(pool || 1)).toFixed(1);

  const warnings: string[] = [];
  if (pw.length < 8) warnings.push('Shorter than 8 characters.');
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw)) warnings.push('Mix upper- and lower-case letters.');
  if (!/[0-9]/.test(pw)) warnings.push('Add digits.');
  if (!/[^a-zA-Z0-9]/.test(pw)) warnings.push('Add symbols.');
  if (/(.)\1\1/.test(pw)) warnings.push('Contains a character repeated 3+ times.');
  if (/(?:abc|bcd|cde|def|123|234|345|456|567|678|789|qwe|wer|ert|asd)/i.test(pw)) warnings.push('Contains a common sequence.');
  const isCommon = COMMON.has(pw.toLowerCase());
  if (isCommon) warnings.push('This is a very common password — effectively instantly guessed.');

  // Crack time: guesses = pool^length / 2 (average). Offline GPU ~1e11/s, online ~10/s.
  const guesses = isCommon ? 1 : Math.pow(pool || 1, pw.length) / 2;
  const offlineSec = guesses / 1e11;
  const onlineSec = guesses / 10;

  let strength: string;
  if (isCommon || entropy < 28) strength = 'very weak';
  else if (entropy < 36) strength = 'weak';
  else if (entropy < 60) strength = 'reasonable';
  else if (entropy < 128) strength = 'strong';
  else strength = 'very strong';

  return {
    length: pw.length,
    entropy_bits: entropy,
    charset_size: pool,
    strength,
    estimated_crack_time: { offline_fast_attacker: humanTime(offlineSec), online_throttled: humanTime(onlineSec) },
    warnings,
    note: 'Heuristic offline estimate; the password is not transmitted or stored.',
  };
}

export default { tools, callTool, meter: { credits: 1 } } satisfies McpToolExport;
