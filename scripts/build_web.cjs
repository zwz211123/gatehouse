// Precompile templates at build time so the shipped UI works with script-src
// 'self' and never requires unsafe-eval, a CDN or a runtime template compiler.
const fs=require('fs'),path=require('path'),vm=require('vm');
const root=path.resolve(__dirname,'..');const read=p=>fs.readFileSync(path.join(root,p),'utf8');
const {JSDOM}=require('jsdom');const dom=new JSDOM('');const context={console,document:dom.window.document};const vue=read('web/vendor/vue.global.prod.js');vm.runInNewContext(vue,context);
const inline=[];const template=read('web/template.html').replace(/style="([^"]*)"/g,(_,style)=>{let i=inline.indexOf(style);if(i<0){i=inline.length;inline.push(style)}return 'data-style="'+i+'"'});
const render=context.Vue.compile(template,{hoistStatic:false}).toString();
const js=vue+'\nconst _Vue=Vue;\nconst GatehouseRender='+render+';\nGatehouseRender._rc=true;\n'+read('web/audit-format.js')+'\n'+read('web/app.js');
dom.window.close();
const css=read('web/style.css')+'\n'+inline.map((s,i)=>'[data-style="'+i+'"]{'+s+'}').join('\n')+'\n';
const output={'internal/gh/webui/app.js':js,'internal/gh/webui/style.css':css};
let bad=false;for(const [p,data] of Object.entries(output)){if(process.argv.includes('--check')){if(read(p)!==data){console.error('Stale browser asset: '+p);bad=true}}else fs.writeFileSync(path.join(root,p),data)}if(bad)process.exit(1);
