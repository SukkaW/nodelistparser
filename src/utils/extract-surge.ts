import * as atom from './atom';
import { decode } from '../surge';
import type { SupportedConfig } from '../types';

/**
 * Surge built-in policies that can appear in [Proxy] but are not actual servers
 *
 * @see https://manual.nssurge.com/policy/built-in.html
 */
const BUILT_IN_POLICY_TYPES = new Set([
  'direct',
  'reject',
  'reject-drop',
  'reject-no-drop',
  'reject-tinygif',
  // iOS only
  'cellular',
  'cellular-only',
  'hybrid',
  'no-hybrid'
]);

export function extractSurgeProfileSection(config: string, section = 'Proxy'): string[] {
  const sectionHeader = `[${section}]`;
  const lines: string[] = [];

  let inSection = false;
  const rawLines = config.split('\n');
  for (let i = 0, len = rawLines.length; i < len; i++) {
    const line = rawLines[i].trim();
    if (line[0] === '[') {
      inSection = line === sectionHeader;
      continue;
    }
    if (
      !inSection
      || line === ''
      || line[0] === '#'
      || line[0] === ';'
      || line.startsWith('//')
    ) {
      continue;
    }
    lines.push(line);
  }

  return lines;
}

export function extractSurgeProfileProxies(config: string, skipUnsupported = true): SupportedConfig[] {
  const proxies: SupportedConfig[] = [];

  const lines = extractSurgeProfileSection(config, 'Proxy');
  for (let i = 0, len = lines.length; i < len; i++) {
    const line = lines[i];
    const [, value] = atom.assign(line);
    const type = atom.comma(value)[0].toLowerCase();

    if (BUILT_IN_POLICY_TYPES.has(type)) {
      continue;
    }

    try {
      proxies.push(decode(line));
    } catch (e) {
      if (!skipUnsupported) {
        throw e;
      }
    }
  }

  return proxies;
}
