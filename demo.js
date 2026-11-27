const entries=[];
function log(text){entries.push(text);const list=document.getElementById('events');if(list)list.textContent=entries.join('\n');}
document.addEventListener('securitypolicyviolation',event=>{const text='БЛОКИРОВКА: '+event.effectiveDirective+' → '+event.blockedURI;log(text);console.warn('[CSP demo]',text);});
document.addEventListener('DOMContentLoaded',()=>{
 log('Тестируются только встроенный JavaScript и локальная картинка. Чужих запросов нет.');
 const script=document.createElement('script');script.textContent="document.getElementById('inline-result').textContent='Встроенный JavaScript выполнен: политика разрешила его.'; console.info('[CSP demo] Inline разрешён');";document.body.append(script);
 const img=new Image();img.alt='Локальный тестовый ресурс';img.onload=()=>log('РАЗРЕШЕНО: локальная картинка /sample.svg');img.onerror=()=>log('Картинка не загружена. Событие CSP выше указывает, была ли причина в политике.');img.src='/sample.svg';document.body.append(img);
});
