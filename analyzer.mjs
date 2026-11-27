const known = new Set('default-src script-src script-src-elem script-src-attr style-src style-src-elem style-src-attr img-src font-src connect-src media-src object-src frame-src child-src worker-src manifest-src base-uri form-action frame-ancestors sandbox report-uri report-to upgrade-insecure-requests block-all-mixed-content require-trusted-types-for trusted-types'.split(' '));
export function analyze(raw, mode = 'enforce') {
  const directives = {}, findings = [];
  const add = (level, title, detail, fix) => findings.push({level,title,detail,fix});
  for (const part of raw.split(';')) {
    const [key, ...values] = part.trim().split(/\s+/); if (!key) continue;
    const name = key.toLowerCase();
    if (Object.hasOwn(directives,name)) { add('medium','Повтор директивы '+name,'Браузер использует первое объявление этой директивы.','Объедините нужные значения в одном объявлении.'); continue; }
    directives[name] = values;
    if (!known.has(name)) add('info','Проверьте директиву '+name,'Директива неизвестна этому анализатору; возможна опечатка или расширение.','Сверьте название со спецификацией CSP.');
    if (values.includes("'none'") && values.length > 1) add('medium',name+': none вместе с источниками',"'none' не запрещает другие перечисленные источники.","Оставьте только 'none' для полного запрета либо удалите его.");
    for (const v of values) if (['self','none','unsafe-inline','unsafe-eval','strict-dynamic'].includes(v)) add('medium','Ключевое слово без кавычек',name+': '+v+' интерпретируется не как ключевое слово.','Используйте одинарные кавычки: '+"'"+v+"'.");
  }
  if (mode === 'report') add('medium','Политика только для наблюдения','Report-Only не блокирует нарушения.','После проверки отчётов внедрите Content-Security-Policy.');
  if (!Object.hasOwn(directives,'default-src')) add('medium','Отсутствует default-src','Типы ресурсов без собственных директив и резервных правил могут остаться неограниченными.',"Добавьте default-src 'self' или 'none' и явно разрешите необходимые источники.");
  if (directives['default-src']?.includes('*')) add('high','default-src *: слишком широкий запасной список','Разрешает сетевые источники для типов ресурсов, использующих default-src. Явные script-src, img-src и другие директивы продолжают действовать; * не разрешает inline-код автоматически.',"Замените * на 'self' или 'none' и настройте отдельные директивы.");
  const effective = name => directives[name] ?? (name.startsWith('script-src-') ? directives['script-src'] : undefined) ?? directives['default-src'];
  for (const name of ['script-src-elem','script-src-attr']) {
    const src = effective(name);
    if (!src) {add('high',name+': нет ограничения','Не найдены ни директива, ни её резервные источники.','Задайте script-src и при необходимости отдельные правила для элементов и обработчиков.');continue;}
    const nonce = src.some(v => /^'nonce-[A-Za-z0-9+/_=-]+'$/.test(v));
    const hash = src.some(v => /^'sha(256|384|512)-[A-Za-z0-9+/_=-]+'$/.test(v));
    const dynamic = src.includes("'strict-dynamic'");
    if (src.includes("'unsafe-inline'") && !nonce && !hash && !dynamic) add('high',name+': разрешён inline JavaScript','Встроенный код разрешён этой политикой.','Используйте nonce/хеши для элементов; удалите встроенные обработчики событий.');
    if (name === 'script-src-elem' && !dynamic && src.some(v=>v==='*'||/^(https?:|data:)$/.test(v))) add('high','Слишком широкие источники скриптов',src.join(' '),'Ограничьте источники; рассмотрите nonce или хеши и strict-dynamic.');
    if (name === 'script-src-elem' && dynamic) add('info','Используется strict-dynamic','В CSP3 списки хостов, схемы и unsafe-inline для загрузки скриптов игнорируются; доверие передаётся динамически загруженным скриптам.','Проверьте доверенные загрузчики и nonce/хеши начальных скриптов.');
  }
  const scripts = directives['script-src'] ?? directives['default-src'] ?? [];
  if (scripts.includes("'unsafe-eval'")) add('high','Разрешён unsafe-eval','Политика разрешает выполнение JavaScript из строк.','Удалите unsafe-eval и замените eval()/Function() в приложении и зависимостях.');
  const objects = effective('object-src');
  if (!objects || objects.join(' ') !== "'none'") add('medium','Встраиваемые объекты не запрещены полностью','object-src допускает объекты либо не ограничен. Для большинства приложений они не нужны.',"Задайте object-src 'none', если объекты не требуются.");
  for (const name of ['base-uri','frame-ancestors','form-action']) {
    if (!Object.hasOwn(directives,name)) add('medium','Отсутствует '+name,'Эта директива не наследует default-src. '+({'base-uri':'Нет ограничения изменения базового URL.','frame-ancestors':'CSP не ограничивает встраивание страницы во фрейм.','form-action':'CSP не ограничивает адреса отправки форм.'}[name]),"Добавьте "+name+" 'self' или 'none' с учётом работы сайта.");
    else if (directives[name].some(v=>v==='*'||v==='https:'||v==='http:')) add('medium',name+': широкое разрешение',directives[name].join(' '),'Укажите только необходимые источники.');
  }
  if ((effective('style-src')??[]).includes("'unsafe-inline'")) add('low','Разрешены встроенные стили','Это ослабляет ограничения CSS, но не означает разрешение JavaScript.','При возможности используйте отдельные CSS-файлы, nonce или хеши.');
  for (const [name, values] of Object.entries(directives)) for (const v of values) {
    if (v.startsWith("'nonce-") && v.endsWith("'")) {
      const bytes = Buffer.from(v.slice(7,-1),'base64').length;
      if (bytes < 16) add('medium','Короткий nonce в '+name,'Значение содержит менее 128 бит. По одному ответу нельзя проверить случайность или повторное использование.','Генерируйте криптографически случайный nonce минимум из 16 байт для каждого ответа.');
    }
  }
  return {raw,mode,directives,findings};
}
export function report(enforced=[], observation=[]) {
  const policies = [...enforced.flatMap(s=>s.split(',').map(p=>analyze(p))), ...observation.flatMap(s=>s.split(',').map(p=>analyze(p,'report')))];
  return {checkedAt:new Date().toISOString(),policies,headerPresent:enforced.length>0,limitations:['Статический аудит текста политики. Реальную работу meta можно отдельно проверить в локальной демонстрации.','Находки относятся к отдельным политикам. Несколько enforced-политик применяются совместно и могут ограничивать друг друга.','Проверка не доказывает наличие XSS и не гарантирует безопасность. Не проверяются исходный код, обходы доверенных доменов и случайность nonce.']};
}
