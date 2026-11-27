// Deliberately small, documented feature space; never uses audit findings as inputs.
export const featureNames = ['default_missing','default_wildcard','script_missing','script_inline','script_eval','script_broad','script_nonce_hash','script_dynamic','script_external','script_many_hosts','style_inline','style_external','img_broad','img_data','connect_broad','connect_external','frame_missing','frame_broad','base_missing','base_broad','form_missing','form_broad','object_not_none'];
export const featureLabels = ['Нет default-src','Широкий default-src','Нет ограничений скриптов','Разрешён inline JavaScript','Разрешён unsafe-eval','Широкие источники скриптов','Nonce или хеш скрипта','strict-dynamic','Внешний источник скриптов','Несколько источников скриптов','Встроенные стили','Внешние стили','Широкие источники картинок','Картинки data:','Широкие соединения','Внешние соединения','Нет frame-ancestors','Широкий frame-ancestors','Нет base-uri','Широкий base-uri','Нет form-action','Широкий form-action','Объекты не запрещены полностью'];
export const classes=['lower','review','high'];
export const classLabels=['Меньше признаков слабой CSP','Нужна проверка настроек','Выраженные признаки слабой CSP'];
const supported=new Set('default-src script-src style-src img-src connect-src frame-ancestors base-uri form-action object-src'.split(' '));
const broad=v=>v?.some(x=>['*','http:','https:','data:'].includes(x))||false;
const hosts=v=>v?.filter(x=>!x.startsWith("'")&&!['*','http:','https:','data:'].includes(x)).length||0;
export function extract(raw){
 const d=Object.create(null),reasons=[];
 if(typeof raw!=='string'||raw.length>16000)return {supported:false,reasons:['Политика отсутствует или слишком длинная.']};
 for(const part of raw.split(';')){const [key,...values]=part.trim().split(/\s+/);if(!key)continue;const name=key.toLowerCase();
  if(!supported.has(name))reasons.push('Модель не обучалась на директиве '+name);
  if(Object.hasOwn(d,name)){reasons.push('Повтор директивы '+name);continue;}d[name]=values;
  if(values.includes("'none'")&&values.length>1)reasons.push("Сочетание 'none' с другими источниками");
  for(const v of values){if(!/^(?:'(?:self|none|unsafe-inline|unsafe-eval|strict-dynamic)'|'(?:nonce-|sha(?:256|384|512)-)[A-Za-z0-9+/_=-]+'|\*|https?:|data:|(?:https?:\/\/)?(?:\*\.)?[a-z0-9][a-z0-9.-]*(?::\d+)?)$/i.test(v)||['self','none','unsafe-inline','unsafe-eval','strict-dynamic'].includes(v))reasons.push('Незнакомый формат источника: '+v);}
 }
 const eff=n=>d[n]??d['default-src'];const s=eff('script-src');const hasKey=s?.some(v=>/^'(nonce-|sha(256|384|512)-)/.test(v))||false;const dynamic=s?.includes("'strict-dynamic'")||false;
 const x=[!d['default-src'],broad(d['default-src']),!s,s?.includes("'unsafe-inline'")&&!hasKey&&!dynamic,s?.includes("'unsafe-eval'"),broad(s)&&!dynamic,hasKey,dynamic,hosts(s)>0,hosts(s)>1,eff('style-src')?.includes("'unsafe-inline'"),hosts(eff('style-src'))>0,broad(eff('img-src')),eff('img-src')?.includes('data:'),broad(eff('connect-src')),hosts(eff('connect-src'))>0,!d['frame-ancestors'],broad(d['frame-ancestors']),!d['base-uri'],broad(d['base-uri']),!d['form-action'],broad(d['form-action']),eff('object-src')?.join(' ')!=="'none'"].map(Number).map(v=>v||0);
 return {supported:reasons.length===0,reasons:[...new Set(reasons)],x};
}
export function probabilities(model,x){const z=model.weights.map((w,k)=>model.bias[k]+w.reduce((s,v,j)=>s+v*x[j],0));const max=Math.max(...z);const e=z.map(v=>Math.exp(v-max));const sum=e.reduce((a,b)=>a+b,0);return e.map(v=>v/sum);}
export function infer(model,raw){
 if(!model)return {status:'unavailable',message:'Файл ML-модели недоступен. Обычный аудит продолжает работать.'};
 const f=extract(raw);if(!f.supported)return {status:'unsupported',message:'Эта политика выходит за учебную область модели. Используйте обычный аудит.',reasons:f.reasons};
 const scores=probabilities(model,f.x);const k=scores.indexOf(Math.max(...scores));
 const drivers=f.x.flatMap((v,j)=>v?[{feature:featureNames[j],text:featureLabels[j],contribution:(model.weights[k][j]-model.weights[k===0?2:0][j])*v}]:[]).filter(v=>v.contribution>0).sort((a,b)=>b.contribution-a.contribution).slice(0,4);
 return {status:'ok',class:classes[k],label:classLabels[k],scores:Object.fromEntries(classes.map((name,i)=>[name,scores[i]])),drivers,version:model.version,scope:'Оценка одной политики. Report-Only не блокирует; сочетание нескольких политик модель не оценивает.'};
}
