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
  globalThis.window={open:url=>{urls.push(url);return tab}};
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

test('browser intent survives rerender and reload without readiness callbacks',()=>{
  const f=fixture(); f.call({}); f.click();
  const intent=f.errors.find(([k])=>k==='purchase')[1];
  f.call({failed:true});f.call({});f.click();
  assert.equal(f.errors.filter(([k])=>k==='purchase')[1][1],intent);
  assert.equal(f.states.length,0);assert.equal(f.urls.length,0);
});
test('actual click opens external tab; server URL navigates it without second click',()=>{
  const f=fixture(), data={url:'https://checkout.stripe.com/test',navigation:'once'};
  f.call({}); f.click(); assert.equal(f.urls.length,0); f.call(data); f.call(data);
  assert.deepEqual(f.urls,['https://checkout.stripe.com/test']);
  assert.equal(f.errors.filter(([k])=>k==='redirect_error').length,0);
});
test('portal allowed, unsafe destinations rejected',()=>{
  const f=fixture(); f.call({}); f.click();
  f.call({url:'https://billing.stripe.com/test',navigation:'portal'});
  for(const url of ['http://checkout.stripe.com/test','https://checkout.stripe.com.evil.invalid',
    'https://user@checkout.stripe.com/test','javascript:alert(1)','https://checkout.stripe.com:444/test']) {
    f.call({url,navigation:url});
  }
  assert.equal(f.urls.length,1);
  assert.equal(f.errors.filter(([k])=>k==='redirect_error').length,5);
});
test('new completed purchase rotates intent, failed navigation reports retryable error',()=>{
  const f=fixture(); f.call({rotate:'replacement'});
  assert.equal(f.stored.get('vulnscan-stripe-intent:'+f.scope),'replacement');
  f.click(); window.open=()=>null;
  f.call({url:'https://checkout.stripe.com/test',navigation:'retry'});
  assert.equal(f.errors.filter(([k])=>k==='redirect_error').length,1);
  assert.equal(f.stored.has('vulnscan-stripe-navigation:'+f.scope),false);
});

test('blocked popup retries same ready URL on native click without a purchase event',()=>{
  const f=fixture(); f.call({}); f.click(); window.open=()=>null;
  f.call({url:'https://checkout.stripe.com/test',navigation:'retry'});
  assert.equal(f.errors.filter(([k])=>k==='redirect_error').length,1);assert.equal(f.urls.length,0);
  window.open=url=>{f.urls.push(url);return f.tab};
  const event=f.click();
  assert.equal(event.prevented,true);assert.equal(event.stopped,true);
  assert.deepEqual(f.urls,['https://checkout.stripe.com/test']);
  assert.ok(f.states.some(([k,v])=>k==='navigation_done'&&v==='retry'));
});
test('double clicks while preparing are suppressed; failure allows retry',()=>{
  const f=fixture(); f.call({});f.click();
  assert.equal(f.click().prevented,true);assert.equal(f.urls.length,0);
  f.call({failed:true});f.call({});
  assert.equal(f.click().prevented,true);
  assert.equal(f.errors.filter(([k])=>k==='purchase').length,2);
  assert.equal(f.listeners.size,1);
});
test('reload without a gesture never opens a popup; explicit click recovers ready URL',()=>{
  const f=fixture();
  f.call({url:'https://checkout.stripe.com/test',navigation:'recover'});
  assert.equal(f.urls.length,0);
  assert.equal(f.click().prevented,true);
  assert.deepEqual(f.urls,['https://checkout.stripe.com/test']);
});
