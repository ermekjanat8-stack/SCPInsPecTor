import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {report} from './analyzer.mjs';
import {withML} from './ml-service.mjs';
import {scanURL} from './scan-url.mjs';
export const appPolicy="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
const port=Number(process.env.PORT||8787);
const assets={'/':['index.html','text/html; charset=utf-8'],'/app.js':['app.js','text/javascript; charset=utf-8'],'/builder.mjs':['builder.mjs','text/javascript; charset=utf-8'],'/profiles.json':['profiles.json','application/json; charset=utf-8'],'/demo.js':['demo.js','text/javascript; charset=utf-8'],'/sample.svg':['sample.svg','image/svg+xml'],'/style.css':['style.css','text/css; charset=utf-8']};
const escape=s=>s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
export const server=http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Cache-Control','no-store');res.setHeader('Content-Security-Policy',appPolicy);
 const send=(code,data)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(data));};
 try{
  if(req.headers.host!==`127.0.0.1:${port}`&&req.headers.host!==`localhost:${port}`)return send(403,{error:'Недопустимый Host.'});
  const url=new URL(req.url,'http://127.0.0.1:'+port);
  if(req.method==='GET'&&url.pathname==='/demo'){
   const policy=url.searchParams.get('policy')||"default-src 'self'; script-src 'self'; img-src 'none'";
   if(policy.length>10000)throw Error('Политика слишком длинная.');
   res.removeHeader('Content-Security-Policy');res.setHeader('Referrer-Policy','no-referrer');res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});
   return res.end(`<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>CSP — живая демонстрация</title><link rel="stylesheet" href="/style.css"><script src="/demo.js"></script><meta http-equiv="Content-Security-Policy" content="${escape(policy)}"></head><body><main><a href="/">Вернуться к конструктору</a><h1>Браузер проверяет CSP</h1><p>Ниже применяется собранная политика через настоящий meta-тег. Откройте F12 → Console, чтобы увидеть сообщения браузера.</p><pre>${escape(policy)}</pre><p id="inline-result">Встроенный JavaScript не выполнился.</p><pre id="events" aria-live="polite"></pre><aside>Наблюдатель и оформление загружены перед meta, чтобы отобразить результат даже при script-src 'none'. Проверяемые ресурсы добавляются после meta. frame-ancestors, sandbox и отчётность через meta не поддерживаются; для frame-ancestors нужен HTTP-заголовок.</aside></main></body></html>`);
  }
  if(req.method==='GET'&&(url.pathname==='/'||/^\/assets\/[a-zA-Z0-9_.-]+$/.test(url.pathname))){
   const file=url.pathname==='/'?'dist/index.html':'dist'+url.pathname;
   const type=file.endsWith('.js')?'text/javascript; charset=utf-8':file.endsWith('.css')?'text/css; charset=utf-8':'text/html; charset=utf-8';
   try{const content=await readFile(new URL(file,import.meta.url));res.writeHead(200,{'Content-Type':type});return res.end(content);}catch{return send(503,{error:'Сначала выполните npm run build.'});}
  }
  if(req.method==='GET'&&Object.hasOwn(assets,url.pathname)){const [f,type]=assets[url.pathname];res.writeHead(200,{'Content-Type':type});return res.end(await readFile(new URL(f,import.meta.url)));}
  if(req.method!=='POST'||url.pathname!=='/api/check')return send(404,{error:'Не найдено.'});
  if(req.headers.origin&&!['http://127.0.0.1:'+port,'http://localhost:'+port,'http://127.0.0.1:5173','http://localhost:5173'].includes(req.headers.origin))return send(403,{error:'Недопустимый Origin.'});
  if(!req.headers['content-type']?.startsWith('application/json'))return send(415,{error:'Требуется JSON.'});
  let body='';for await(const chunk of req){body+=chunk;if(body.length>65536)return send(413,{error:'Слишком большой запрос.'});}
  const data=JSON.parse(body);
  if(data.mode==='url')return send(200,withML(await scanURL(data.url,{port})));
  if(data.mode==='local')return send(200,withML({...report([appPolicy]),url:'http://127.0.0.1:'+port+'/',status:200}));
  if(data.mode!=='text')throw Error('Неизвестный режим проверки.');
  if(typeof data.policy!=='string')throw Error('Нужен текст политики.');
  send(200,withML(report(data.reportOnly?[]:[data.policy],data.reportOnly?[data.policy]:[])));
 }catch(e){send(400,{error:e.message||'Не удалось выполнить проверку.'});}
});
if(process.argv[1]===fileURLToPath(import.meta.url))server.listen(port,'127.0.0.1',()=>console.log(`CSP Inspector: http://127.0.0.1:${port}`));
