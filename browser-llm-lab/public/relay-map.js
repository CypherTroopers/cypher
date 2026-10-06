// Screen coordinates are CSS pixels. Country anchors are estimates; unknown peers never get geographic coordinates.
export const MAP_LIMITS=Object.freeze({peers:20,pulses:24,fps:30,pulseMs:2600,activityMs:5000,pinSize:30,maxDPR:2});
const clamp=(value,min,max)=>Math.max(min,Math.min(max,value));
const peerID=value=>typeof value==='string'&&/^[\w-]{1,64}$/.test(value);
const safeGeo=geo=>geo&&geo.accuracy==='country'&&typeof geo.countryCode==='string'&&/^[A-Z]{2}$/.test(geo.countryCode)&&
  !['XX','T1'].includes(geo.countryCode)&&Number.isFinite(geo.lat)&&Number.isFinite(geo.lon)&&Math.abs(geo.lat)<=90&&Math.abs(geo.lon)<=180?
  {countryCode:geo.countryCode,label:typeof geo.label==='string'?geo.label.slice(0,48):geo.countryCode,lat:geo.lat,lon:geo.lon,accuracy:'country'}:null;
const boxOverlap=(a,b,gap=7)=>a.x<b.x+b.width+gap&&a.x+a.width+gap>b.x&&a.y<b.y+b.height+gap&&a.y+a.height+gap>b.y;
const nodeBox=(x,y,labelWidth)=>({x:x-labelWidth/2,y:y-24,width:labelWidth,height:76});

export function connectionCurve(a,b){
  const distance=Math.hypot(b.x-a.x,b.y-a.y),bend=clamp(distance*.25,32,94);
  return {a:{x:a.x,y:a.y},control:{x:(a.x+b.x)/2,y:Math.max(10,Math.min(a.y,b.y)-bend)},b:{x:b.x,y:b.y}};
}
export function curvePoint(curve,t){const u=1-clamp(t,0,1),v=1-u;return {x:u*u*curve.a.x+2*u*v*curve.control.x+v*v*curve.b.x,y:u*u*curve.a.y+2*u*v*curve.control.y+v*v*curve.b.y};}

/** Pure deterministic placement. Leader lines distinguish label offsets from the actual country anchor. */
export function layoutMap(snapshot={},viewport={}){
  const width=Math.max(180,Number(viewport.width)||640);let height=Math.max(180,Number(viewport.height)||340);
  const emptyMapHeight=Math.min(height-28,(width-28)/2);
  const empty={width,height,nodes:[],links:[],dock:null,mapBounds:{x:14,y:(height-emptyMapHeight)/2,width:width-28,height:emptyMapHeight}};
  if(!snapshot.requested)return empty;
  const peers=[...(Array.isArray(snapshot.peers)?snapshot.peers:[])].filter(p=>p.connected&&peerID(p.peerId))
    .sort((a,b)=>a.peerId.localeCompare(b.peerId)).filter((p,index,list)=>!index||p.peerId!==list[index-1].peerId).slice(0,MAP_LIMITS.peers);
  const input=[{id:'self',self:true,label:'You',geo:safeGeo(snapshot.selfGeo)},...peers.map(p=>({id:p.peerId,self:false,label:'Peer '+(p.peerId.length>7?p.peerId.slice(0,3)+'…'+p.peerId.slice(-3):p.peerId),geo:safeGeo(p.geo)}))];
  const unknown=input.filter(n=>!n.geo),known=input.filter(n=>n.geo),dense=input.length>4;
  const columns=Math.max(1,Math.min(6,Math.floor((width-16)/140))),rows=Math.ceil(unknown.length/columns);
  const labelRows=dense?Math.ceil(known.length/columns):0;
  const mapAreaHeight=dense?(known.length?Math.max(120,Math.min(300,(width-28)/2)):70):0;
  const legendTop=14+mapAreaHeight+16,legendHeight=labelRows*44;
  // Expand only enough for the bounded 21 browser cards. No node or label is clipped into a fixed-height dock.
  if(dense)height=Math.max(height,legendTop+legendHeight+(unknown.length?38+rows*54:14));
  const dock=unknown.length?{x:12,y:height-(38+rows*54),width:width-24,height:30+rows*54,label:'UNLOCATED · NOT PLACED ON THE MAP'}:null;
  const area={x:14,y:14,width:width-28,height:dense?mapAreaHeight:Math.max(70,(dock?dock.y-14:height-14)-14)};
  const mapHeight=Math.min(area.height,area.width/2),mapBounds={...area,y:area.y+(area.height-mapHeight)/2,height:mapHeight};
  const labelWidth=width<440?108:124,placed=[],nodes=[];
  const groups=new Map();
  for(const n of known){const group=groups.get(n.geo.countryCode)||[];group.push(n);groups.set(n.geo.countryCode,group);}
  const spread=labelWidth/2+12,offsets=[[-spread,-14],[spread,-14],[-spread,72],[spread,72],[0,0],[-2*spread,18],[2*spread,18],[0,-100],[0,100]];
  for(const n of known){
    const group=groups.get(n.geo.countryCode),index=group.indexOf(n);
    const anchor={x:mapBounds.x+(n.geo.lon+180)/360*mapBounds.width,y:mapBounds.y+(90-n.geo.lat)/180*mapBounds.height};
    const candidates=group.length>1?[...offsets.slice(index,index+1),...offsets]:[[0,0],...offsets];
    let point,bounds;
    for(const [dx,dy] of candidates){
      const x=clamp(anchor.x+dx,labelWidth/2+8,width-labelWidth/2-8),y=clamp(anchor.y+dy,area.y+25,Math.max(area.y+25,area.y+area.height-54));
      const candidate=nodeBox(x,y,labelWidth);
      if(!point){point={x,y};bounds=candidate;}
      if(!placed.some(b=>boxOverlap(candidate,b))){point={x,y};bounds=candidate;break;}
    }
    placed.push(bounds);nodes.push({...n,located:true,anchor,...point,pinSize:MAP_LIMITS.pinSize,
      countryLabel:n.geo.countryCode+' · '+n.geo.label,labelBox:{x:point.x-labelWidth/2,y:point.y+18,width:labelWidth,height:34}});
  }
  // A full legend keeps dense-country and mixed-location labels readable at every width.
  if(dense){
    const cellWidth=(width-24-(columns-1)*8)/columns;
    nodes.forEach((node,index)=>{node.label=String(index+1).padStart(2,'0')+' · '+node.label;node.labelBox={x:12+(index%columns)*(cellWidth+8),y:legendTop+Math.floor(index/columns)*44,width:cellWidth,height:36};});
  }else if(placed.some((box,index)=>placed.slice(index+1).some(other=>boxOverlap(box,other)))){
    const xs=[labelWidth/2+8,width-labelWidth/2-8],ys=[area.y+25,area.y+area.height-54];
    nodes.forEach((node,index)=>{node.x=xs[index%2];node.y=ys[Math.floor(index/2)];node.labelBox={x:node.x-labelWidth/2,y:node.y+18,width:labelWidth,height:34};});
  }
  // Only labels may fan out across the canvas. Every geographic pin stays near its true country anchor.
  const pinOffsets={1:[[0,0]],2:[[-16,-8],[16,8]],3:[[0,-22],[-22,16],[22,16]],4:[[-20,-18],[20,-18],[-20,20],[20,20]]};
  for(const node of nodes){
    const group=groups.get(node.geo.countryCode),index=group.findIndex(n=>n.id===node.id);
    const angle=index/group.length*Math.PI*2-Math.PI/2;
    const [dx,dy]=pinOffsets[group.length]?.[index]||[Math.cos(angle)*30,Math.sin(angle)*30];
    node.x=clamp(node.anchor.x+dx,16,width-16);node.y=clamp(node.anchor.y+dy,23,height-16);
    node.compact=group.length>4;node.pinSize=node.compact?8:MAP_LIMITS.pinSize;node.legend=dense;
  }
  unknown.forEach((n,index)=>{
    const cellWidth=(dock.width-16-(columns-1)*8)/columns,x=dock.x+8+(index%columns)*(cellWidth+8),y=dock.y+28+Math.floor(index/columns)*54;
    nodes.push({...n,located:false,geo:null,anchor:null,x:x+18,y:y+18,pinSize:MAP_LIMITS.pinSize,countryLabel:'Location unavailable',
      labelBox:{x:x+35,y:y+3,width:cellWidth-39,height:39},dockBox:{x,y,width:cellWidth,height:44}});
  });
  const self=nodes.find(n=>n.self),links=nodes.filter(n=>!n.self).map(n=>({from:'self',to:n.id,geographic:self.located&&n.located,curve:connectionCurve(self,n)}));
  return {width,height,nodes,links,dock,mapBounds};
}

export function activityPath(layout,event){
  if(!['received','forwarded','acknowledged'].includes(event?.name))return null;
  const self=layout.nodes.find(n=>n.self),peer=layout.nodes.find(n=>!n.self&&n.id===event.peerId);if(!self||!peer)return null;
  const from=event.name==='forwarded'?self:peer,to=from===self?peer:self;
  return {from:from.id,to:to.id,kind:event.name,geographic:from.located&&to.located,curve:connectionCurve(from,to)};
}

function rounded(ctx,x,y,width,height,radius=7){
  const r=Math.min(radius,width/2,height/2);ctx.beginPath();ctx.moveTo(x+r,y);ctx.lineTo(x+width-r,y);ctx.quadraticCurveTo(x+width,y,x+width,y+r);
  ctx.lineTo(x+width,y+height-r);ctx.quadraticCurveTo(x+width,y+height,x+width-r,y+height);ctx.lineTo(x+r,y+height);ctx.quadraticCurveTo(x,y+height,x,y+height-r);
  ctx.lineTo(x,y+r);ctx.quadraticCurveTo(x,y,x+r,y);ctx.closePath();
}
function curveStroke(ctx,curve){ctx.beginPath();ctx.moveTo(curve.a.x,curve.a.y);ctx.quadraticCurveTo(curve.control.x,curve.control.y,curve.b.x,curve.b.y);ctx.stroke();}
function fitText(ctx,value,width){let text=String(value);if(ctx.measureText(text).width<=width)return text;while(text.length&&ctx.measureText(text+'…').width>width)text=text.slice(0,-1);return text+'…';}

/** No module-level DOM effects. A renderer owns at most one animation frame and one bounded timer. */
export class RelayMap {
  constructor(canvas,{now=()=>globalThis.performance?.now?.()??Date.now(),requestFrame=globalThis.requestAnimationFrame?.bind(globalThis),
    cancelFrame=globalThis.cancelAnimationFrame?.bind(globalThis),setTimer=globalThis.setTimeout?.bind(globalThis),clearTimer=globalThis.clearTimeout?.bind(globalThis),
    fetcher=globalThis.fetch?.bind(globalThis),reducedMotion,document:ownerDocument=canvas?.ownerDocument,onLayout=()=>{}}={}){
    Object.assign(this,{canvas,now,requestFrame,cancelFrame,setTimer,clearTimer,document:ownerDocument,onLayout});
    this.ctx=canvas?.getContext?.('2d');this.snapshot={requested:false,peers:[]};this.rings=[];this.pulses=[];this.frame=null;this.frameTimer=null;this.activityTimer=null;this.dirty=false;this.inView=true;
    this.destroyed=false;this.drawCount=0;this.lastDrawAt=-Infinity;this.activityCount=0;this.activityCounts={received:0,forwarded:0,acknowledged:0};this.latestActivity=null;
    this.layout=layoutMap();this.visible=!this.document||this.document.visibilityState!=='hidden';
    this.motionQuery=canvas?.ownerDocument?.defaultView?.matchMedia?.('(prefers-reduced-motion: reduce)')||globalThis.matchMedia?.('(prefers-reduced-motion: reduce)');
    this.reducedMotion=reducedMotion??Boolean(this.motionQuery?.matches);
    this.motionChanged=event=>{this.reducedMotion=Boolean(event.matches);this.cancelAnimation();this.pulses=[];this.draw();this.schedule();};
    this.visibilityChanged=()=>{this.visible=this.document?.visibilityState!=='hidden';this.cancelAnimation();if(!this.visible){this.pulses=[];this.latestActivity=null;}this.draw();};
    this.document?.addEventListener?.('visibilitychange',this.visibilityChanged);this.motionQuery?.addEventListener?.('change',this.motionChanged);
    const Observer=canvas?.ownerDocument?.defaultView?.ResizeObserver||globalThis.ResizeObserver;
    if(Observer){this.observer=new Observer(()=>this.resize());this.observer.observe(canvas);}
    const Intersection=canvas?.ownerDocument?.defaultView?.IntersectionObserver||globalThis.IntersectionObserver;
    if(Intersection){this.intersection=new Intersection(entries=>{const next=entries.some(entry=>entry.isIntersecting);if(next===this.inView)return;this.inView=next;this.cancelAnimation();
      this.pulses=[];this.latestActivity=null;this.draw(true);});this.intersection.observe(canvas);}
    if(fetcher&&this.ctx){fetcher('/assets/earth-land.json',{credentials:'omit',cache:'force-cache'}).then(r=>r.ok?r.json():null)
      .then(land=>{if(this.destroyed)return;this.rings=Array.isArray(land?.rings)?land.rings:[];this.draw();}).catch(()=>{});}
    this.resize();
  }
  resize(){
    if(this.destroyed||!this.canvas)return;const box=this.canvas.getBoundingClientRect?.();
    this.width=Math.max(180,Math.round(box?.width||640));
    this.baseHeight??=Math.max(180,Math.round(box?.height||340));
    this.layout=layoutMap(this.snapshot,{width:this.width,height:this.baseHeight});this.height=this.layout.height;
    if(this.canvas.style&&this.canvas.style.height!==`${this.height}px`)this.canvas.style.height=`${this.height}px`;
    const dpr=clamp(this.canvas.ownerDocument?.defaultView?.devicePixelRatio||1,1,MAP_LIMITS.maxDPR);
    if(this.canvas.width!==Math.round(this.width*dpr))this.canvas.width=Math.round(this.width*dpr);
    if(this.canvas.height!==Math.round(this.height*dpr))this.canvas.height=Math.round(this.height*dpr);
    this.dpr=dpr;this.remapPulses();this.onLayout(this.layout);this.draw(!this.snapshot.requested);this.schedule();
  }
  set(snapshot={}){
    if(this.destroyed)return;this.snapshot=snapshot;
    if(!snapshot.requested){this.pulses=[];this.latestActivity=null;this.cancelAnimation();}
    this.resize();
  }
  remapPulses(){const nodes=new Map(this.layout.nodes.map(node=>[node.id,node]));this.pulses=this.pulses.filter(p=>nodes.has(p.from)&&nodes.has(p.to))
    .map(p=>({...p,geographic:nodes.get(p.from).located&&nodes.get(p.to).located,curve:connectionCurve(nodes.get(p.from),nodes.get(p.to))}));}
  transfer(event){
    if(this.destroyed||!this.ctx||!this.visible||!this.snapshot.requested)return false;
    const path=activityPath(this.layout,event);if(!path)return false;const at=this.now();
    this.activityCount=Math.min(Number.MAX_SAFE_INTEGER,this.activityCount+1);this.activityCounts[path.kind]=Math.min(Number.MAX_SAFE_INTEGER,this.activityCounts[path.kind]+1);
    if(!this.inView){this.diagnostics();return true;}
    this.latestActivity={kind:path.kind,at,expiresAt:at+MAP_LIMITS.activityMs};
    if(!this.reducedMotion){this.pulses.push({...path,at});if(this.pulses.length>MAP_LIMITS.pulses)this.pulses.splice(0,this.pulses.length-MAP_LIMITS.pulses);}
    if(this.activityTimer!==null){this.clearTimer?.(this.activityTimer);this.activityTimer=null;}
    this.dirty=true;this.diagnostics();this.schedule();return true;
  }
  cancelAnimation(){if(this.frame!==null)this.cancelFrame?.(this.frame);if(this.frameTimer!==null)this.clearTimer?.(this.frameTimer);if(this.activityTimer!==null)this.clearTimer?.(this.activityTimer);this.frame=null;this.frameTimer=null;this.activityTimer=null;}
  schedule(){
    if(this.destroyed||!this.visible||!this.inView||!this.snapshot.requested)return;
    const now=this.now();this.pulses=this.pulses.filter(p=>now-p.at<MAP_LIMITS.pulseMs);
    if((this.pulses.length&&!this.reducedMotion)||this.dirty){
      if(this.activityTimer!==null){this.clearTimer?.(this.activityTimer);this.activityTimer=null;}
      if(this.frame!==null||this.frameTimer!==null)return;
      const delay=Math.max(0,1000/MAP_LIMITS.fps-(now-this.lastDrawAt));
      this.frameTimer=this.setTimer(()=>{this.frameTimer=null;if(!this.visible||!this.inView||!this.snapshot.requested||this.destroyed)return;
        if(this.pulses.length&&!this.reducedMotion&&this.requestFrame)this.frame=this.requestFrame(()=>{this.frame=null;this.draw();this.schedule();});
        else{this.draw();this.schedule();}},delay);
    }else if(this.latestActivity&&this.latestActivity.expiresAt>now){
      if(this.activityTimer!==null)return;
      this.activityTimer=this.setTimer(()=>{this.activityTimer=null;this.latestActivity=null;this.draw();this.schedule();},Math.min(MAP_LIMITS.activityMs,this.latestActivity.expiresAt-now));
    }
  }
  inspect(){const now=this.now();return {layout:structuredClone(this.layout),pulses:this.pulses.map(p=>({...p,curve:structuredClone(p.curve),progress:clamp((now-p.at)/MAP_LIMITS.pulseMs,0,1),position:curvePoint(p.curve,(now-p.at)/MAP_LIMITS.pulseMs)})),pendingFrame:this.frame!==null||this.frameTimer!==null||this.activityTimer!==null,
    drawCount:this.drawCount,lastDrawAt:this.lastDrawAt,activityCount:this.activityCount,activityCounts:{...this.activityCounts},reducedMotion:this.reducedMotion,visible:this.visible,inView:this.inView};}
  diagnostics(){
    const dataset=this.canvas?.dataset;if(!dataset)return;
    dataset.mapKnown=String(this.layout.nodes.filter(n=>n.located).length);dataset.mapUnknown=String(this.layout.nodes.filter(n=>!n.located).length);
    dataset.mapPulses=String(this.pulses.length);dataset.mapEvents=String(this.activityCount);dataset.mapReceived=String(this.activityCounts.received);
    dataset.mapForwarded=String(this.activityCounts.forwarded);dataset.mapAcknowledged=String(this.activityCounts.acknowledged);dataset.mapFrames=String(this.drawCount);
    dataset.mapNodes=JSON.stringify(this.layout.nodes.map(({id,self,located,countryLabel,x,y,pinSize,anchor})=>({id,self,located,countryLabel,x,y,pinSize,anchor})));
    this.canvas.setAttribute?.('aria-label',this.snapshot.requested?`Connected browser map. ${this.layout.nodes.map(n=>`${n.label}: ${n.located?n.countryLabel+' country estimate':'location unavailable, shown in unlocated dock'}`).join('; ')}. Thin lines show connections; moving particles show actual transfers.`:'Browser map. Node OFF; no participants or transfers.');
  }
  draw(force=false){
    if(this.destroyed||!this.ctx)return;const now=this.now();this.pulses=this.pulses.filter(p=>now-p.at<MAP_LIMITS.pulseMs);
    if(this.latestActivity?.expiresAt<=now)this.latestActivity=null;
    this.diagnostics();if(!this.visible||!this.inView)return;
    if(!force&&now-this.lastDrawAt<1000/MAP_LIMITS.fps){this.dirty=true;return;}this.dirty=false;
    this.drawCount++;this.lastDrawAt=now;this.diagnostics();const ctx=this.ctx,{width,height,mapBounds,dock,nodes,links}=this.layout;
    ctx.setTransform(this.dpr||1,0,0,this.dpr||1,0,0);ctx.clearRect(0,0,width,height);
    const glow=ctx.createRadialGradient(width*.55,height*.4,10,width*.55,height*.4,width*.75);glow.addColorStop(0,'#113446');glow.addColorStop(1,'#06111c');ctx.fillStyle=glow;ctx.fillRect(0,0,width,height);
    const project=([lon,lat])=>({x:mapBounds.x+(lon+180)/360*mapBounds.width,y:mapBounds.y+(90-lat)/180*mapBounds.height});
    ctx.strokeStyle='#24404e';ctx.lineWidth=.6;
    for(let lon=-180;lon<=180;lon+=30){const p=project([lon,0]);ctx.beginPath();ctx.moveTo(p.x,mapBounds.y);ctx.lineTo(p.x,mapBounds.y+mapBounds.height);ctx.stroke();}
    for(let lat=-60;lat<=60;lat+=30){const p=project([0,lat]);ctx.beginPath();ctx.moveTo(mapBounds.x,p.y);ctx.lineTo(mapBounds.x+mapBounds.width,p.y);ctx.stroke();}
    ctx.fillStyle='#1b4655';ctx.strokeStyle='#386c7d';ctx.lineWidth=.65;
    for(const ring of this.rings){if(!Array.isArray(ring))continue;ctx.beginPath();ring.forEach((point,i)=>{const p=project(point);i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y);});ctx.closePath();ctx.fill();ctx.stroke();}
    if(dock){rounded(ctx,dock.x,dock.y,dock.width,dock.height,9);ctx.fillStyle='#0b1926';ctx.fill();ctx.strokeStyle='#486071';ctx.lineWidth=1;ctx.stroke();
      ctx.fillStyle='#b7c9d4';ctx.font='600 10px system-ui';ctx.textAlign='left';ctx.fillText(fitText(ctx,dock.label,dock.width-20),dock.x+10,dock.y+17);}
    for(const link of links){ctx.strokeStyle='rgba(148,186,204,.5)';ctx.lineWidth=1.2;ctx.setLineDash(link.geographic?[]:[4,5]);curveStroke(ctx,link.curve);}ctx.setLineDash([]);
    for(const pulse of this.pulses){const ack=pulse.kind==='acknowledged',sent=pulse.kind==='forwarded',t=clamp((now-pulse.at)/MAP_LIMITS.pulseMs,0,1),color=ack?'#8affb9':sent?'#ffba70':'#48e8ff';
      ctx.strokeStyle=ack?'rgba(138,255,185,.72)':sent?'rgba(255,186,112,.72)':'rgba(72,232,255,.65)';ctx.lineWidth=2;ctx.shadowColor=color;ctx.shadowBlur=7;curveStroke(ctx,pulse.curve);
      for(let trail=2;trail>=0;trail--){const point=curvePoint(pulse.curve,clamp(t-trail*.055,0,1));ctx.fillStyle=color;ctx.globalAlpha=1-trail*.25;ctx.beginPath();ctx.arc(point.x,point.y,trail?2.8:4.5,0,Math.PI*2);ctx.fill();}
      ctx.globalAlpha=1;ctx.shadowBlur=0;
    }
    for(const node of nodes)this.drawNode(ctx,node);
    if(this.latestActivity){const label={received:'RECEIVED',forwarded:'SENT',acknowledged:'ACK RECEIVED'}[this.latestActivity.kind],text=label+' · '+this.activityCounts[this.latestActivity.kind];
      ctx.font='600 11px system-ui';const w=Math.min(width-24,ctx.measureText(text).width+20);rounded(ctx,width-w-12,10,w,25,7);ctx.fillStyle='#071923ed';ctx.fill();ctx.strokeStyle=this.latestActivity.kind==='acknowledged'?'#81ebad':'#43dfee';ctx.lineWidth=1;ctx.stroke();
      ctx.textAlign='center';ctx.fillStyle='#e1f8ef';ctx.fillText(text,width-w/2-12,27);}
  }
  drawNode(ctx,node){
    const color=node.self?'#77ffce':'#55ddff';
    if(node.located){
      ctx.strokeStyle='#bbd5dfb3';ctx.lineWidth=1;ctx.setLineDash([3,3]);ctx.beginPath();ctx.moveTo(node.anchor.x,node.anchor.y);ctx.lineTo(node.x,node.y+14);ctx.stroke();ctx.setLineDash([]);
      ctx.fillStyle='#d4f6fc';ctx.beginPath();ctx.arc(node.anchor.x,node.anchor.y,2.4,0,Math.PI*2);ctx.fill();
      const label=node.labelBox,labelCenter={x:label.x+label.width/2,y:label.y+label.height/2};
      if(!node.legend){ctx.strokeStyle='#83a8bbb3';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(node.x,node.y+14);ctx.lineTo(labelCenter.x,labelCenter.y);ctx.stroke();}
      if(node.compact){ctx.beginPath();ctx.arc(node.x,node.y,3.5,0,Math.PI*2);ctx.fillStyle=color;ctx.fill();ctx.strokeStyle='#e5ffff';ctx.lineWidth=.7;ctx.stroke();}
      else{ctx.save();ctx.translate(node.x,node.y);ctx.beginPath();ctx.moveTo(0,15);ctx.bezierCurveTo(-4,9,-13,0,-13,-8);ctx.bezierCurveTo(-13,-25,13,-25,13,-8);ctx.bezierCurveTo(13,0,4,9,0,15);ctx.closePath();
      ctx.shadowColor=color;ctx.shadowBlur=10;ctx.fillStyle=color;ctx.fill();ctx.shadowBlur=0;ctx.strokeStyle='#e5ffff';ctx.lineWidth=1;ctx.stroke();
      ctx.beginPath();ctx.arc(0,-9,5,0,Math.PI*2);ctx.fillStyle='#083141';ctx.fill();ctx.restore();}
      const b=node.labelBox;rounded(ctx,b.x,b.y,b.width,b.height,6);ctx.fillStyle='#051421ee';ctx.fill();ctx.strokeStyle='#3c6375';ctx.lineWidth=1;ctx.stroke();
      ctx.textAlign='center';ctx.font='600 12px system-ui';ctx.fillStyle='#e6faff';ctx.fillText(fitText(ctx,node.label,b.width-12),labelCenter.x,b.y+13);
      ctx.font='11px system-ui';ctx.fillStyle='#a6c6d6';ctx.fillText(fitText(ctx,node.countryLabel,b.width-12),labelCenter.x,b.y+27);
    }else{
      const b=node.dockBox;rounded(ctx,b.x,b.y,b.width,b.height,6);ctx.fillStyle='#142634';ctx.fill();ctx.strokeStyle='#405c70';ctx.lineWidth=1;ctx.stroke();
      ctx.strokeStyle=color;ctx.lineWidth=1.5;ctx.beginPath();ctx.arc(node.x,node.y,10,0,Math.PI*2);ctx.stroke();ctx.textAlign='center';ctx.font='600 12px system-ui';ctx.fillStyle=color;ctx.fillText('?',node.x,node.y+4);
      const label=node.labelBox;ctx.textAlign='left';ctx.font='600 11px system-ui';ctx.fillStyle='#e2f0f7';ctx.fillText(fitText(ctx,node.label,label.width),label.x,label.y+13);
      ctx.font='10px system-ui';ctx.fillStyle='#9fb5c3';ctx.fillText(fitText(ctx,'No country',label.width),label.x,label.y+28);
    }
  }
  destroy(){this.destroyed=true;this.cancelAnimation();this.pulses=[];this.observer?.disconnect();this.intersection?.disconnect();this.document?.removeEventListener?.('visibilitychange',this.visibilityChanged);this.motionQuery?.removeEventListener?.('change',this.motionChanged);}
}
