// Fixed labels and structured fields only; no generated summaries or remote services.
const AuditFormat = (() => {
 const modes={shell:'终端',exec:'固定命令',sftp:'SFTP',scp:'SCP',tcp:'TCP 转发',subsystem:'SFTP'};
 const actions={'ssh.login':'SSH 登录','connection.close':'连接结束','direct.start':'进入目标终端','direct.close':'返回菜单','proxy.start':'打开通道','proxy.close':'通道结束','proxy.exit':'目标进程结束','proxy.tcp':'打开 TCP 转发','proxy.tcp.close':'TCP 转发结束','proxy.issue':'申请临时账号','proxy.claim':'验证临时账号','proxy.password':'临时账号认证','proxy.revoke':'撤销临时入口','proxy.delete':'删除临时入口','proxy.credentials':'查看临时凭据','proxy.mismatch':'请求被拒绝','web.issue':'签发 Web 登录凭据','web.redeem':'登录 Web 管理器','session.terminate':'终止连接','credential.test':'测试目标连接','backup.export':'导出备份','backup.create':'创建备份','backup.restore.stage':'暂存恢复文件','backup.restore':'恢复备份','initialize':'初始化','owner.recover':'恢复所有者'};
 const nouns={asset:'服务器',account:'目标账号',credential:'凭据',user:'用户',key:'接入公钥',group:'用户组',grant:'授权',settings:'全局设置',config:'全局设置',ticket:'临时账号'};
 const verbs={create:'创建',update:'修改',delete:'删除',change:'变更'};
 const files={init:'初始化 SFTP',open:'打开文件',close:'关闭文件',read:'读取文件',write:'写入文件',lstat:'读取路径属性',fstat:'读取文件属性',setstat:'修改路径属性',fsetstat:'修改文件属性',opendir:'打开目录',readdir:'读取目录',remove:'删除文件',mkdir:'创建目录',rmdir:'删除目录',realpath:'解析路径',stat:'读取属性',rename:'重命名',posix_rename:'重命名',readlink:'读取链接',symlink:'创建符号链接',extended:'扩展请求',malformed:'无效 SFTP 请求',unknown:'未知 SFTP 请求',authorization:'文件访问检查',statvfs:'读取文件系统信息',fsync:'同步文件'};
 const results={ok:'成功',attempt:'请求已接收',eof:'读取结束',denied:'拒绝',error:'失败',unsupported:'不支持',aborted:'中止'};
 function action(code){if(actions[code])return actions[code];if(code.startsWith('file.'))return files[code.slice(5)]||'文件请求（'+code.slice(5)+'）';const [n,v]=code.split('.');return nouns[n]&&verbs[v]?verbs[v]+nouns[n]:'事件（'+code+'）'}
 function detail(e,name=id=>id){let d;try{d=JSON.parse(e.detail)}catch{}
  if(d&&typeof d==='object'){
   const parts=[];if(d.path)parts.push(d.path+(d.target?' → '+d.target:''));else if(d.account)parts.push('目标：'+name(d.account));if(d.modes?.length)parts.push('用途：'+d.modes.map(m=>modes[m]||m).join(' / '));if(d.length!==undefined)parts.push('长度 '+d.length+' 字节');if(d.offset!==undefined)parts.push('偏移 '+d.offset);if(d.reason)parts.push(d.reason);if(d.error)parts.push(d.error);if(d.extension)parts.push('扩展：'+d.extension);return parts.join('；')||action(e.action);
  }
  if(e.action==='proxy.exit')return /^\d+$/.test(e.detail)?'退出码 '+e.detail:'目标进程被信号终止';
  if(e.action==='proxy.start')return modes[e.detail]||'SSH 请求';
  if(e.action==='ssh.login'&&e.result==='ok')return e.entry==='menu'?'公钥验证通过':'临时账号验证通过';
  return e.detail||'';
 }
 const capVerbs={read:'查看',create:'创建',update:'修改',delete:'删除',trust:'设置可信主机公钥',special:'访问特殊地址',chroot:'确认路径隔离',import:'导入',generate:'生成密钥',test:'测试连接',bind:'绑定凭据',owner:'任免所有者',terminate:'终止连接',export:'导出',restore:'恢复',direct:'直接连接',revoke:'撤销',shell:'交互式终端',exec:'固定命令',sftp:'SFTP',scp:'SCP',tcp:'TCP 转发',multi:'多次或并发连接',reconnect:'重连',list:'列目录',write:'写文件',mkdir:'创建目录',remove:'删除文件',rename:'重命名',metadata:'修改文件属性',login:'登录',jump:'经堡垒机转发'};
 const capNouns={...nouns,session:'连接',shell:'SSH',proxy:'临时入口',file:'文件',web:'Web'};
 function capability(code){if(code==='*')return '全部操作';return code.split('.').map((p,i)=>i===0?(capNouns[p]||p):(capVerbs[p]||p)).join(' · ')}
 return {modes,action,detail,capability,result:r=>results[r]||r||'未记录',failure:r=>!['ok','attempt','eof'].includes(r)};
})();
if(typeof module!=='undefined')module.exports=AuditFormat;
