import {readFile} from 'node:fs/promises';
import {infer,featureNames} from './ml-core.mjs';
let model;
try{model=JSON.parse(await readFile(new URL('./ml/model.json',import.meta.url),'utf8'));if(JSON.stringify(model.features)!==JSON.stringify(featureNames)||model.weights.length!==3||model.weights.some(w=>w.length!==featureNames.length||w.some(v=>!Number.isFinite(v)))||model.bias.length!==3||model.bias.some(v=>!Number.isFinite(v)))throw Error('Несовместимая модель');}catch{model=null;}
export function withML(report){
 return {...report,mlInfo:model?{version:model.version,algorithm:'Логистическая регрессия · 23 признака',evaluation:model.evaluation}:null,policies:report.policies.map(p=>{
  const ml=infer(model,p.raw);const ruleClass=p.findings.some(f=>f.level==='high')?'high':p.findings.some(f=>['medium','low'].includes(f.level))?'review':'lower';
  return {...p,ml:{...ml,ruleClass,disagrees:ml.status==='ok'&&ml.class!==ruleClass}};
 })};
}
