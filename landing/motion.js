(function(){
document.body.dataset.lang=document.documentElement.lang;
const viewport=document.getElementById('landing-viewport')||document.scrollingElement;
const signal=window.__vs_abort?.signal;
// The component owns the scrolling viewport. No parent DOM access is needed.
document.querySelectorAll('a[href^="#"]').forEach(link=>link.addEventListener('click',event=>{
 const id=link.getAttribute('href').slice(1),target=id?document.getElementById(id):document.body;
 if(!target)return;
 event.preventDefault();
 if(window.innerWidth<=900)document.querySelector('.menu').open=false;
 viewport.scrollTo({top:target.getBoundingClientRect().top-viewport.getBoundingClientRect().top+viewport.scrollTop-24,behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});
 if(id){target.setAttribute('tabindex','-1');target.focus({preventScroll:true});}
}));
const picker=document.querySelector('.language-picker');
const lang=document.documentElement.lang;
document.querySelectorAll('[data-language]').forEach(button=>{
 button.setAttribute('aria-pressed',String(button.dataset.language===lang));
 button.addEventListener('click',()=>{
  const selected=button.dataset.language;
  picker.open=false;
  if(selected===lang)return;
  try{localStorage.setItem('vulnscan-public-language',selected);}catch(error){}
  window.dispatchEvent(new CustomEvent('vulnscan:language',{detail:selected}));
 });
});
document.addEventListener('click',event=>{if(!picker.contains(event.target))picker.open=false;},{signal});
document.addEventListener('keydown',event=>{if(event.key==='Escape'&&picker.open){picker.open=false;picker.querySelector('summary').focus();}},{signal});
const tabs=[...document.querySelectorAll('[role="tab"]')];
function activateTab(tab){tabs.forEach(item=>{const active=item===tab;item.setAttribute('aria-selected',String(active));item.tabIndex=active?0:-1;document.getElementById(item.getAttribute('aria-controls')).hidden=!active;});}
tabs.forEach((tab,index)=>{
 tab.addEventListener('click',()=>activateTab(tab));
 tab.addEventListener('keydown',event=>{
  let next;if(event.key==='ArrowRight')next=(index+1)%tabs.length;else if(event.key==='ArrowLeft')next=(index+tabs.length-1)%tabs.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=tabs.length-1;else return;
  event.preventDefault();activateTab(tabs[next]);tabs[next].focus();
 });
});
const scene=document.querySelector('.scene'),visual=document.querySelector('.visual');
const motion=window.matchMedia('(prefers-reduced-motion: reduce)');
const pointer=window.matchMedia('(hover: hover) and (pointer: fine) and (min-width: 901px)');
let visible=false,frame=0;
const reset=()=>{cancelAnimationFrame(frame);scene.style.transform='';};
if('IntersectionObserver' in window){new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;if(!visible)reset();},{threshold:.15}).observe(visual);}
visual.addEventListener('pointermove',event=>{if(!visible||motion.matches||!pointer.matches)return;const box=visual.getBoundingClientRect();const x=(event.clientX-box.left)/box.width-.5,y=(event.clientY-box.top)/box.height-.5;cancelAnimationFrame(frame);frame=requestAnimationFrame(()=>{scene.style.transform=`rotateX(${10-y*9}deg) rotateY(${-13+x*12}deg)`;});});
visual.addEventListener('pointerleave',reset);
motion.addEventListener('change',reset);
document.addEventListener('visibilitychange',()=>{if(document.hidden)reset();},{signal});
document.querySelectorAll('.menu nav a').forEach(link=>link.addEventListener('click',()=>{if(window.innerWidth<=900)document.querySelector('.menu').open=false;}));
// Desktop details is open for reliable native disclosure semantics.
const desktopMenu=window.matchMedia('(min-width:901px)');
const adjustMenu=()=>{document.querySelector('.menu').open=desktopMenu.matches;};
adjustMenu();desktopMenu.addEventListener('change',adjustMenu,{signal});

})();
