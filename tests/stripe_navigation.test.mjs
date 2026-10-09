import test from 'node:test';
import assert from 'node:assert/strict';
import render from '../stripe_navigation.mjs';

function fixture() {
  const stored=new Map(), states=[], errors=[], urls=[];
  globalThis.sessionStorage={getItem:k=>stored.get(k)??null,setItem:(k,v)=>stored.set(k,v)};
  globalThis.window={location:{assign:url=>urls.push(url)}};
  const call=data=>render({data:{scope:'user-pdf',...data},
    setStateValue:(k,v)=>states.push([k,v]),setTriggerValue:(k,v)=>errors.push([k,v])});
  return {stored,states,errors,urls,call};
}

test('browser intent survives rerender, reload and widget remount',()=>{
  const f=fixture(); f.call({});
  const intent=f.states[0][1];
  f.call({known_intent:intent});
  assert.equal(f.states.length,1);
  f.call({}); // Fresh server/widget state, same sessionStorage after reload.
  assert.equal(f.states[1][1],intent);
  assert.equal(f.urls.length,0);
});
test('server URL navigates same tab without any second click; nonce deduplicated',()=>{
  const f=fixture(), data={url:'https://checkout.stripe.com/test',navigation:'once'};
  f.call(data); f.call(data);
  assert.deepEqual(f.urls,['https://checkout.stripe.com/test']);
  assert.equal(f.errors.length,0);
});
test('portal allowed, unsafe destinations rejected',()=>{
  const f=fixture();
  f.call({url:'https://billing.stripe.com/test',navigation:'portal'});
  for(const url of ['http://checkout.stripe.com/test','https://checkout.stripe.com.evil.invalid',
    'https://user@checkout.stripe.com/test','javascript:alert(1)','https://checkout.stripe.com:444/test']) {
    f.call({url,navigation:url});
  }
  assert.equal(f.urls.length,1);
  assert.equal(f.errors.length,5);
});
test('new completed purchase rotates intent, failed navigation reports retryable error',()=>{
  const f=fixture(); f.call({rotate:'replacement'});
  assert.equal(f.states[0][1],'replacement');
  window.location.assign=()=>{throw Error('blocked')};
  f.call({url:'https://checkout.stripe.com/test',navigation:'retry'});
  assert.equal(f.errors.length,1);
  assert.equal(f.stored.has('vulnscan-stripe-navigation:user-pdf'),false);
});
