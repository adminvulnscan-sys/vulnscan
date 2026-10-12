import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
const code = readFileSync(new URL('../payment_return_bridge.mjs', import.meta.url), 'utf8')
  .replace('export default function', 'globalThis.run = function');

function environment() {
  const peers = [], queue = [], messages = [];
  class Channel {
    constructor() { peers.push(this); }
    postMessage(message) {
      messages.push(message);
      for (const peer of peers) if (peer !== this && !peer.closed)
        queue.push(() => peer.onmessage?.({data: message}));
    }
    close() { this.closed = true; }
  }
  function tab(data) {
    const events = [], timers = new Map(), window = {focuses: 0, closes: 0};
    window.top = {focus: () => window.focuses++, close: () => window.closes++};
    const context = vm.createContext({BroadcastChannel: Channel, window,
      crypto: {randomUUID: () => `nonce-${peers.length}`},
      setInterval: fn => {timers.set('retry', fn); return 'retry';},
      setTimeout: fn => {timers.set('timeout', fn); return 'timeout';},
      clearInterval: key => timers.delete(key), clearTimeout: key => timers.delete(key)});
    vm.runInContext(code, context);
    const cleanup = context.run({data, setTriggerValue: (key, value) => events.push([key, value])});
    return {context, window, events, timers, cleanup};
  }
  return {tab, peers, messages, flush() {while (queue.length) queue.shift()();}};
}

test('matching return resumes original tab without transferring authentication', () => {
  const env = environment();
  const source = env.tab({role: 'source', checkout: 'cs_test_one'});
  const returned = env.tab({role: 'return', checkout: 'cs_test_one'});
  env.flush();
  assert.equal(source.window.focuses, 1); assert.equal(returned.window.closes, 1);
  assert.ok(returned.events.some(([key]) => key === 'resumed'));
  assert.equal(returned.timers.size, 0);
  for (const msg of env.messages)
    assert.deepEqual(Object.keys(msg).sort(), ['checkout', 'nonce', 'type']);
  source.cleanup(); returned.cleanup();
  assert.ok(env.peers.every(peer => peer.closed));
});

test('different Checkout cannot acknowledge or resume the original session', () => {
  const env = environment();
  const source = env.tab({role: 'source', checkout: 'cs_test_other'});
  const returned = env.tab({role: 'return', checkout: 'cs_test_one'});
  env.flush(); returned.timers.get('timeout')();
  assert.equal(source.window.focuses, 0); assert.equal(returned.window.closes, 0);
  assert.deepEqual(returned.events, [['unavailable', true]]);
});

test('forged acknowledgement with wrong nonce cannot close return tab', () => {
  const env = environment(); const returned = env.tab({role: 'return', checkout: 'cs_test_one'});
  env.peers[0].onmessage({data: {type: 'ack', checkout: 'cs_test_one', nonce: 'wrong'}});
  assert.equal(returned.window.closes, 0); assert.equal(returned.events.length, 0);
});

test('missing channel support or invalid Checkout falls back without authentication', () => {
  const env = environment();
  const returned = env.tab({role: 'return', checkout: 'invalid'});
  assert.deepEqual(returned.events, [['unavailable', true]]);
  assert.equal(returned.window.closes, 0);
});
