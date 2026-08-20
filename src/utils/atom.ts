export const boolean = (text: string): boolean => (text === 'true');
export const number = Number;
export const comma = (text: string): string[] => text.split(',').map((piece) => piece.trim());

const RE_WHITESPACE = /\s+/;
export const space = (text: string): string[] => text.split(RE_WHITESPACE).filter(Boolean);

/**
 * Split `text` on the first occurrence of `separator`, keeping the entire
 * remainder (which may itself contain `separator`) as the second element.
 *
 * Note: this is deliberately not `String#split(separator, 2)` -- the native
 * limit argument truncates the remainder instead of preserving it, e.g.
 * `'a:b:c'.split(':', 2)` yields `['a', 'b']` and drops `':c'`.
 */
export function splitOnce(text: string, separator: string): [left: string, right: string] {
  const index = text.indexOf(separator);

  return index === -1
    ? [text, '']
    : [text.slice(0, index), text.slice(index + separator.length)];
}

export function assign(text: string): [left: string, right: string] {
  const signIndex = text.indexOf('=');

  return signIndex === -1
    ? ['', '']
    : [text.slice(0, signIndex).trim(), text.slice(signIndex + 1).trim()];
}
