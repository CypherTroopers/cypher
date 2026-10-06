import { constants,openSync,closeSync,lstatSync,fstatSync,readSync } from 'node:fs';
import { createHmac } from 'node:crypto';

/** Coturn REST secret is server-only. Refuse links, other owners and any group/world access. */
export function loadTurnSecret(path) {
  try {
    for(let current=path;;current=current.slice(0,current.lastIndexOf('/'))||'/') {
      if(lstatSync(current).isSymbolicLink())throw new Error();
      if(current==='/')break;
    }
    const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
    try {
      const before=fstatSync(fd);
      if(!before.isFile()||before.uid!==process.getuid()||(before.mode&0o777)!==0o600||before.size<32||before.size>129)throw new Error();
      const bytes=Buffer.alloc(130),size=readSync(fd,bytes,0,bytes.length,0),after=fstatSync(fd);
      if(size>129||before.size!==size||before.mtimeMs!==after.mtimeMs)throw new Error();
      const secret=bytes.subarray(0,size).toString('utf8').trim();
      if(!/^[A-Za-z0-9_-]{32,128}$/.test(secret))throw new Error();
      return Buffer.from(secret,'ascii');
    } finally {closeSync(fd);}
  } catch {throw new Error('TURN secret must be an owner-only 0600 bounded regular file without linked paths');}
}

/** Timestamped HMAC-SHA1 is coturn's REST credential protocol, not a persistent browser secret. */
export function turnCredentials(turn,secret,session,now=Date.now()) {
  const expiry=Math.min(Math.floor(session.expiresAt/1000),Math.floor(now/1000)+turn.ttlSeconds);
  const username=`${expiry}:${session.peerId}`;
  return {urls:turn.urls,username,credential:createHmac('sha1',secret).update(username).digest('base64')};
}
