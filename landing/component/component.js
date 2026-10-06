(function(){
 const viewport=document.getElementById('landing-viewport');
 let documents={},current=null,first=true;
 const send=(type,extra={})=>window.parent.postMessage({isStreamlitMessage:true,type,...extra},'*');
 function mount(language){
  const html=documents[language];
  if(!html)throw new Error('Missing presentation document');
  const unresolved=[...html.matchAll(/\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}/g)].map(match=>match[1]);
  if(unresolved.length)throw new Error('Unresolved presentation template: '+[...new Set(unresolved)].join(', '));
  if(window.__vs_abort)window.__vs_abort.abort();
  window.__vs_abort=new AbortController();
  const parsed=new DOMParser().parseFromString(html,'text/html');
  let style=document.getElementById('presentation-style');
  if(!style){style=document.createElement('style');style.id='presentation-style';document.head.append(style);}
  style.textContent=parsed.querySelector('style').textContent;
  const scripts=[...parsed.querySelectorAll('script')];scripts.forEach(script=>script.remove());
  document.documentElement.lang=language;
  document.body.dataset.lang=language;
  viewport.replaceChildren(...parsed.body.childNodes);
  // innerHTML/DOMParser do not execute scripts: execute the trusted local runtime explicitly.
  scripts.forEach(source=>{const script=document.createElement('script');script.textContent=source.textContent;document.head.append(script);script.remove();});
  current=language;
 }
 window.addEventListener('vulnscan:language',event=>{
  const selected=event.detail;if(!['es','en'].includes(selected)||selected===current)return;
  const scroll=viewport.scrollTop;
  try{localStorage.setItem('vulnscan-public-language',selected);}catch(error){}
  mount(selected);viewport.scrollTop=scroll;
  send('streamlit:setComponentValue',{value:selected,dataType:'json'});
 });
 window.addEventListener('message',event=>{
  if(event.source!==window.parent||event.data.type!=='streamlit:render')return;
  documents=event.data.args.documents;
  let language=event.data.args.language;
  if(first){try{const stored=localStorage.getItem('vulnscan-public-language');if(['es','en'].includes(stored))language=stored;}catch(error){}first=false;}
  if(current!==language)mount(language);
  if(language!==event.data.args.language)send('streamlit:setComponentValue',{value:language,dataType:'json'});
  send('streamlit:setFrameHeight',{height:900});
 });
 send('streamlit:componentReady',{apiVersion:1});
})();
