import expect from 'expect';
import * as nodelistparser from './index';
import { ss, clash, surge } from './index';

describe('nodelistparser', () => {
  it('exports', () => {
    expect(typeof nodelistparser).toBe('object');
    expect(typeof ss).toBe('object');
    expect(typeof clash).toBe('object');
    expect(typeof surge).toBe('object');
  });
});
