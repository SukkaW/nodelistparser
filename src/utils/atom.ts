export const boolean = (text: string): boolean => (text === 'true');
export const number = Number;
export const comma = (text: string): string[] => text.split(',').map((piece) => piece.trim());

export const space = (text: string): string[] => text.split(/\s+/).filter(Boolean);
export function assign(text: string): [left: string, right: string] {
  const signIndex = text.indexOf('=');

  return signIndex === -1
    ? ['', '']
    : [text.slice(0, signIndex).trim(), text.slice(signIndex + 1).trim()];
}
