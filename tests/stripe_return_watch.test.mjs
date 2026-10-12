import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
const code = readFileSync(new URL('../stripe_navigation.mjs', import.meta.url), 'utf8')
  .replace('export function watchReturn', 'globalThis.watchReturn = function')
  .replace('export default function', 'globalThis.navigation = function');
function setup() {
  let tick, focused = 0, closed = 0, cleared = 0, intervals = 0;
  const tab = {closed: false, location: {href: 'about:blank'}, close() {closed++;this.closed=true;}};
  const context = vm.createContext({URL, location:{origin:'https://app.example'},
    window:{top:{focus:()=>focused++}},
    setInterval:fn=>{tick=fn;intervals++;return 1;},clearInterval:()=>cleared++, Date});
  vm.runInContext(code, context);
  context.watchReturn(tab, 'cs_test_one');
  return {tab, context, tick:()=>tick(), stats:()=>({focused,closed,cleared,intervals})};
}
test('only matching same-origin return closes creator-owned tab', () => {
  const env=setup(); env.tick(); assert.equal(env.stats().closed,0);
  env.tab.location.href='https://app.example/?pago=exitoso&session_id=cs_test_other';
  env.tick(); assert.equal(env.stats().closed,0);
  env.tab.location.href='https://app.example/?pago=exitoso&session_id=cs_test_one';
  env.tick(); assert.deepEqual(env.stats(),{focused:1,closed:1,cleared:1,intervals:1});
});
test('cross-origin inaccessible Checkout does not trigger a return or repeat creation', () => {
  const env=setup();
  Object.defineProperty(env.tab,'location',{get(){throw new Error('SecurityError');}});
  env.tick(); assert.equal(env.stats().closed,0);
  env.context.watchReturn(env.tab,'cs_test_one');
  assert.equal(env.stats().intervals,1);
});
test('canceled return closes popup without granting a purchase', () => {
  const env=setup(); env.tab.location.href='https://app.example/?pago=cancelado';
  env.tick(); assert.equal(env.stats().closed,1);
});
