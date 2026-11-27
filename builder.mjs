export const names=['default-src','script-src','style-src','img-src','connect-src','frame-ancestors'];
export function domainSource(input){
 const value=input.trim();
 if(!value||/[\s;'"<>,?#]/.test(value))throw Error('Введите один домен без кавычек, пути, параметров или директив.');
 const match=value.match(/^(https?:\/\/)?(\*\.)?([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::(\d{1,5}))?$/i);
 if(!match||match[3].split('.').some(s=>!s||s.startsWith('-')||s.endsWith('-'))||(match[4]&&(+match[4]<1||+match[4]>65535)))throw Error('Пример допустимого домена: https://cdn.example.com или *.example.com.');
 return value.toLowerCase();
}
export function serialize(state){return names.filter(n=>state[n]!==null).map(n=>n+' '+(state[n]?.length?state[n].join(' '):"'none'")).join('; ');}
export function explain(state,name){
 let values=state[name],fallback=false;
 if(values===null){if(name==='frame-ancestors')return 'Встраивание не ограничено этой CSP. default-src здесь не применяется.';values=state['default-src'];fallback=true;}
 if(values===null)return 'Нет ограничения: директива и default-src отсутствуют.';
 const prefix=fallback?'Используется default-src: ':'';
 if(!values?.length||values.includes("'none'"))return prefix+'Запрещено всё для этого типа ресурсов.';
 const parts=[];if(values.includes("'self'"))parts.push('свой origin (схема, хост и порт)');if(values.includes('*'))parts.push('любые сетевые хосты');if(values.includes("'unsafe-inline'"))parts.push('встроенный код');parts.push(...values.filter(v=>!['*',"'self'","'unsafe-inline'"].includes(v)));
 return prefix+'Разрешено: '+parts.join(', ')+'. Остальные источники не разрешены этим списком.';
}
