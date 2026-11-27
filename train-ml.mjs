import {mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {analyze} from './analyzer.mjs';
import {extract,featureNames,classes,probabilities} from './ml-core.mjs';
// Reproducible synthetic supervision, NOT expert-labelled vulnerability data.
let seed=20261127;const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296;};
const pick=a=>a[Math.floor(random()*a.length)];
const options={
 'default-src':[null,"'none'","'self'",'*','https:'],
 'script-src':[null,"'none'","'self'","'self' 'unsafe-inline'","'self' 'unsafe-eval'",'*','https:',"'self' https://cdn.example.com","https://a.example.com https://b.example.com","'nonce-MDEyMzQ1Njc4OWFiY2RlZg==' 'strict-dynamic'","'nonce-MDEyMzQ1Njc4OWFiY2RlZg==' 'unsafe-inline'"],
 'style-src':[null,"'self'","'self' 'unsafe-inline'",'https://style.example.com'],
 'img-src':[null,"'self'",'*',"'self' data:"],
 'connect-src':[null,"'none'","'self'",'*',"'self' https://api.example.com"],
 'frame-ancestors':[null,"'none'","'self'",'*'],
 'base-uri':[null,"'none'","'self'",'*'],
 'form-action':[null,"'none'","'self'",'*'],
 'object-src':[null,"'none'","'self'",'*']
};
const rows=[],seen=new Set(),counts=[0,0,0];
for(let i=0;i<100000&&Math.min(...counts)<400;i++){
 const d={'default-src':"'none'",'script-src':"'self'",'style-src':"'self'",'img-src':"'self'",'connect-src':"'none'",'frame-ancestors':"'none'",'base-uri':"'none'",'form-action':"'self'",'object-src':"'none'"};
 const mutations=1+Math.floor(random()*12);for(let j=0;j<mutations;j++){const key=pick(Object.keys(options));d[key]=pick(options[key]);}
 const raw=Object.entries(d).filter(([,v])=>v!==null).map(([k,v])=>k+' '+v).join('; ');const f=extract(raw);const key=f.x.join('');if(seen.has(key))continue;
 const findings=analyze(raw).findings;const y=findings.some(f=>f.level==='high')?2:findings.some(f=>['medium','low'].includes(f.level))?1:0;
 if(counts[y]>=400)continue;seen.add(key);counts[y]++;rows.push({raw,x:f.x,y});
}
const splits={train:[],validation:[],test:[]};
for(let k=0;k<3;k++){const group=rows.filter(r=>r.y===k);for(let i=group.length-1;i>0;i--){const j=Math.floor(random()*(i+1));[group[i],group[j]]=[group[j],group[i]];}group.forEach((r,i)=>splits[i<Math.floor(group.length*.6)?'train':i<Math.floor(group.length*.8)?'validation':'test'].push(r));}
if(counts.some(n=>n<50))throw Error('Недостаточно разнообразных примеров для каждого класса: '+counts);
const model={version:'synthetic-softmax-v1',features:featureNames,classes,weights:classes.map(()=>featureNames.map(()=>0)),bias:[0,0,0]};
function evaluate(data,m){const confusion=classes.map(()=>[0,0,0]);let loss=0;for(const r of data){const p=probabilities(m,r.x);confusion[r.y][p.indexOf(Math.max(...p))]++;loss-=Math.log(Math.max(p[r.y],1e-12));}return {count:data.length,accuracy:confusion.reduce((s,row,i)=>s+row[i],0)/data.length,loss:loss/data.length,confusion,recall:confusion.map((row,i)=>row[i]/row.reduce((a,b)=>a+b,0))};}
let best,bestLoss=Infinity,bestEpoch=0;
for(let epoch=1;epoch<=1200;epoch++){
 const gw=classes.map(()=>featureNames.map(()=>0)),gb=[0,0,0];
 for(const r of splits.train){const p=probabilities(model,r.x);for(let k=0;k<3;k++){const error=p[k]-Number(r.y===k);gb[k]+=error;for(let j=0;j<r.x.length;j++)gw[k][j]+=error*r.x[j];}}
 for(let k=0;k<3;k++){model.bias[k]-=.3*gb[k]/splits.train.length;for(let j=0;j<featureNames.length;j++)model.weights[k][j]-=.3*(gw[k][j]/splits.train.length+.0001*model.weights[k][j]);}
 if(epoch%20===0){const val=evaluate(splits.validation,model);if(val.loss<bestLoss){bestLoss=val.loss;best=structuredClone(model);bestEpoch=epoch;}}
}
const evaluation={seed:20261127,algorithm:'Multinomial logistic regression (softmax), batch gradient descent',features:featureNames.length,labelSource:'Метки автоматически получены обычным аудитом analyze(): high → high; medium/low → review; иначе lower. Это имитация правил, а не независимая разметка экспертов.',splitMethod:'60/20/20 по классам, уникальные векторы признаков разделены до обучения; одинаковых векторов между частями нет.',classCounts:counts,selectedEpoch:bestEpoch,train:evaluate(splits.train,best),validation:evaluate(splits.validation,best),test:evaluate(splits.test,best),limitations:'Синтетический тест измеряет согласие с правилами генератора, не точность обнаружения реальных уязвимостей. Баллы softmax не откалиброваны как вероятность атаки.'};
const dataset=Object.entries(splits).flatMap(([split,data])=>data.map(r=>JSON.stringify({split,...r}))).join('\n')+'\n';evaluation.datasetSha256=createHash('sha256').update(dataset).digest('hex');
best.evaluation=evaluation;
await mkdir(new URL('./ml/',import.meta.url),{recursive:true});
await writeFile(new URL('./ml/model.json',import.meta.url),JSON.stringify(best,null,2));
await writeFile(new URL('./ml/evaluation.json',import.meta.url),JSON.stringify(evaluation,null,2));
await writeFile(new URL('./ml/dataset.jsonl',import.meta.url),dataset);
console.log(JSON.stringify(evaluation,null,2));
