import { expect } from 'earl';
import * as nodelistparser from './index';
import { ss, clash, surge } from './index';

describe('nodelistparser', () => {
  it('exports', () => {
    expect(typeof nodelistparser).toEqual('object');
    expect(typeof ss).toEqual('object');
    expect(typeof clash).toEqual('object');
    expect(typeof surge).toEqual('object');
  });
});
