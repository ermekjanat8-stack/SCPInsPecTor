import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import net from 'node:net';
import {report} from './analyzer.mjs';
const blocked=new net.BlockList();
for(const [ip,bits] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.168.0.0',16],['192.0.0.0',24],['192.0.2.0',24],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',3]])blocked.addSubnet(ip,bits,'ipv4');
export function publicIP(ip){return net.isIP(ip)===4?!blocked.check(ip,'ipv4'):net.isIP(ip)===6&&/^[23][0-9a-f]{3}:/i.test(ip)&&!/^2001:(?:db8|0):/i.test(ip)&&!/^2002:/i.test(ip);}
export function normalizeURL(value){
 if(typeof value!=='string'||!value.trim())throw Error('Вставьте ссылку своего сайта.');
 if(value.length>4096)throw Error('Ссылка слишком длинная.');
 const text=value.trim();let url;try{url=new URL(text.includes('://')?text:'https://'+text);}catch{throw Error('Не удалось разобрать ссылку. Пример: https://example.com');}
 if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw Error('Разрешены HTTP/HTTPS ссылки без логина и пароля.');
 url.hash='';return url;
}
export async function scanURL(input,{port=8787,lookup=dns.lookup,requestHeaders=getHeaders}={}){
 let url=normalizeURL(input);const originalURL=url.href,redirects=[];const deadline=Date.now()+25000;
 for(let step=0;step<6;step++){
  url=normalizeURL(url.href);
  const ownApp=['127.0.0.1','localhost'].includes(url.hostname)&&url.protocol==='http:'&&url.port===String(port);
  if(!ownApp&&url.port&&!['80','443'].includes(url.port))throw Error('Для интернет-сайтов поддерживаются порты 80 и 443.');
  let addresses;
  if(ownApp)addresses=[{address:'127.0.0.1',family:4}];
  else {
   let timer;try{addresses=await Promise.race([lookup(url.hostname.replace(/^\[|\]$/g,''),{all:true}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Истекло время поиска адреса сайта.')),Math.max(1,deadline-Date.now()));})]);}finally{clearTimeout(timer);}
   if(!addresses.length||addresses.some(a=>!publicIP(a.address)))throw Error('Нужен публичный адрес сайта. Из локальных адресов доступно только это приложение на порту '+port+'.');
  }
  if(Date.now()>=deadline)throw Error('Проверка превысила 25 секунд.');
  const response=await requestHeaders(url,addresses[0],Math.min(10000,deadline-Date.now()));
  if([301,302,303,307,308].includes(response.status)&&response.location){redirects.push({url:url.href,status:response.status});url=new URL(response.location,url);continue;}
  const values=name=>response.rawHeaders.flatMap((s,i)=>i%2===0&&s.toLowerCase()===name?[response.rawHeaders[i+1]]:[]);
  const result=report(values('content-security-policy'),values('content-security-policy-report-only'));
  return {...result,source:'url',originalURL,url:url.href,status:response.status,redirects,contentType:values('content-type')[0]||'',limitations:['Проверены только HTTP-заголовки конечной страницы. CSP в HTML meta в этой версии не извлекается.','Проверка без входа в аккаунт и cookies; другие страницы или авторизованная версия могут иметь иную политику.',...result.limitations]};
 }throw Error('Более пяти перенаправлений. Проверьте конечную ссылку сайта.');
}
function getHeaders(url,address,timeout){return new Promise((resolve,reject)=>{
 const request=(url.protocol==='https:'?https:http).request(url,{method:'GET',headers:{'User-Agent':'CSP-Inspector/2.0','Accept':'text/html'},lookup:(_host,options,callback)=>options.all?callback(null,[address]):callback(null,address.address,address.family)},res=>{
  const result={status:res.statusCode,rawHeaders:res.rawHeaders,location:res.headers.location};res.destroy();resolve(result);
 });
 const timer=setTimeout(()=>request.destroy(Error('Сайт не ответил вовремя. Попробуйте ещё раз.')),timeout);
 request.on('close',()=>clearTimeout(timer));request.on('error',error=>reject(Error('Не удалось получить заголовки сайта: '+error.message)));request.end();
});}
