import test from 'node:test';
import assert from 'node:assert/strict';
import render from '../stripe_navigation.mjs';

let nextScope=0;
function fixture() {
  const stored=new Map(), states=[], errors=[], urls=[], listeners=new Set();
  const scope='scope-'+nextScope++;
  const tab={closed:false,opener:{},document:{body:{}},focus(){},close(){this.closed=true},location:{replace:url=>urls.push(url)}};
  globalThis.CSS={escape:value=>value};
  globalThis.document={addEventListener:(name,fn)=>listeners.add(fn),removeEventListener:(name,fn)=>listeners.delete(fn)};
  globalThis.sessionStorage={getItem:k=>stored.get(k)??null,setItem:(k,v)=>stored.set(k,v)};
  globalThis.window={open:()=>tab};
  let cleanup;
  const call=data=>{cleanup?.();cleanup=render({data:{scope,button_key:'buy',...data},
    setStateValue:(k,v)=>states.push([k,v]),setTriggerValue:(k,v)=>errors.push([k,v])});};
  const click=()=>{
    const event={target:{closest:()=>({disabled:false,closest:()=>true})},preventDefault(){this.prevented=true},stopImmediatePropagation(){this.stopped=true}};
    for(const listener of listeners)listener(event);
    return event;
  };
  return {stored,states,errors,urls,call,click,tab,scope,listeners};
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
test('actual click opens external tab; server URL navigates it without second click',()=>{
  const f=fixture(), data={url:'https://checkout.stripe.com/test',navigation:'once'};
  f.call({}); f.click(); f.call(data); f.call(data);
  assert.deepEqual(f.urls,['https://checkout.stripe.com/test']);
  assert.equal(f.errors.length,0);
});
test('portal allowed, unsafe destinations rejected',()=>{
  const f=fixture(); f.call({}); f.click();
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
  f.click(); f.tab.location.replace=()=>{throw Error('blocked')};
  f.call({url:'https://checkout.stripe.com/test',navigation:'retry'});
  assert.equal(f.errors.length,1);
  assert.equal(f.stored.has('vulnscan-stripe-navigation:'+f.scope),false);
});

test('popup blocked prevents native purchase, and reports an actionable error',()=>{
  const f=fixture(); f.call({}); window.open=()=>null;
  const event=f.click();
  assert.equal(event.prevented,true);assert.equal(event.stopped,true);
  assert.equal(f.errors.length,1);assert.equal(f.urls.length,0);
});
test('double clicks reuse the tab, failure closes it and listeners clean up',()=>{
  const f=fixture();let opens=0;window.open=()=>{opens++;return f.tab};
  f.call({});f.click();f.click();assert.equal(opens,1);
  f.call({known_intent:f.states[0][1]});assert.equal(f.listeners.size,1);
  f.call({failed:true});assert.equal(f.tab.closed,true);assert.equal(f.listeners.size,0);
});
test('no user gesture means no external window or iframe navigation',()=>{
  const f=fixture();window.open=()=>{throw Error('must not open during render')};
  f.call({url:'https://checkout.stripe.com/test',navigation:'no-gesture'});
  assert.equal(f.errors.length,1);assert.equal(f.urls.length,0);
});
