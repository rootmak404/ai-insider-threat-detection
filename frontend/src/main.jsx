import React,{useEffect,useMemo,useState}from"react";
import{createRoot}from"react-dom/client";
import"./style.css";

const API=import.meta.env.VITE_API_URL||"http://127.0.0.1:8000";

const category=x=>({
  usb_or_volume_inserted:"Removable Media",
  file_downloaded:"Downloads",
  privilege_change:"Privilege Escalation",
  account_change:"Account Manipulation",
  security_policy_change:"Security Policy",
  session_login:"Off-Hours Session",
  session_logout:"Session"
}[x]||"Security Activity");

function Login({done}){
  const[u,su]=useState(""),[p,sp]=useState(""),[e,se]=useState("");
  async function submit(x){
    x.preventDefault();
    try{
      const r=await fetch(API+"/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});
      if(!r.ok)return se("Invalid administrator credentials");
      const d=await r.json();localStorage.setItem("token",d.access_token);done(d.access_token)
    }catch{se("Backend unavailable")}
  }
  return <div className="login">
    <div className="login-grid">
      <div className="login-brand">
        <small>ENDPOINT SECURITY / SOC</small>
        <h1>INSIDER<br/><span>THREAT</span><br/>COMMAND</h1>
        <p>Continuous monitoring for removable media, downloads, sessions and local security changes.</p>
      </div>
      <form className="login-card" onSubmit={submit}>
        <h2>Administrator access</h2>
        <label>Username<input value={u} onChange={e=>su(e.target.value)} autoComplete="username" required/></label>
        <label>Password<input type="password" value={p} onChange={e=>sp(e.target.value)} autoComplete="current-password" required/></label>
        <button>Sign in <span>→</span></button>
        {e&&<div className="error">{e}</div>}
      </form>
    </div>
  </div>
}

function Dashboard({token,logout}){
  const[s,ss]=useState({}),[a,sa]=useState([]),[u,su]=useState([]),[live,slive]=useState(false),[filter,setFilter]=useState("ALL");
  const[notes,setNotes]=useState([]),[open,setOpen]=useState(false),[toasts,setToasts]=useState([]);
  const unread=notes.filter(n=>!n.read).length;
  function notify(x){
    setNotes(q=>[{...x,read:false},...q.filter(v=>v.id!==x.id)].slice(0,30));
    setToasts(q=>[x,...q.filter(v=>v.id!==x.id)].slice(0,3));
    setTimeout(()=>setToasts(q=>q.filter(v=>v.id!==x.id)),6000);
  }
  function toggleBell(){setOpen(o=>{if(o)setNotes(q=>q.map(n=>({...n,read:true})));return!o})}
  const H={Authorization:"Bearer "+token};
  async function load(){
    try{
      const[x,y,z]=await Promise.all(["stats","alerts","users"].map(q=>fetch(API+"/api/admin/"+q,{headers:H})));
      if(x.status===401)return logout();
      ss(await x.json());sa(await y.json());su(await z.json())
    }catch{}
  }
  async function ack(id){await fetch(API+"/api/admin/alerts/"+id+"/ack",{method:"POST",headers:H});load()}
  useEffect(()=>{
    load();
    const w=new WebSocket(API.replace(/^http/,"ws")+"/api/ws");
    w.onopen=()=>{slive(true);w.send("connected")};w.onclose=()=>slive(false);
    w.onmessage=e=>{const m=JSON.parse(e.data);if(m.type!=="security_alert")return;const x=m.alert;sa(q=>[x,...q.filter(v=>v.id!==x.id)]);notify(x);if("Notification"in window&&Notification.permission==="granted")new Notification(x.risk_level+" Security Alert",{body:`${x.username} · ${x.title} · ${x.risk_score}/100`});load()};
    if("Notification"in window&&Notification.permission==="default")Notification.requestPermission();
    return()=>w.close()
  },[]);
  const filtered=useMemo(()=>filter==="ALL"?a:a.filter(x=>x.risk_level===filter),[a,filter]);
  const cats=useMemo(()=>{const m={};a.forEach(x=>{const c=category(x.event_type);m[c]=(m[c]||0)+1});return Object.entries(m).sort((x,y)=>y[1]-x[1]).slice(0,6)},[a]);
  const maxCat=Math.max(1,...cats.map(c=>c[1]));
  return <div className="app">
    <header className="top">
      <div className="brand"><div className="brandmark">IT</div><div><b>INSIDER THREAT</b><span>DETECTION SYSTEM</span></div></div>
      <div className="top-right">
        <div className="bell-wrap">
          <button className={"bell"+(open?" sel":"")} onClick={toggleBell} aria-label={`Notifications, ${unread} unread`}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>
            {unread>0&&<span className="badge">{unread>9?"9+":unread}</span>}
          </button>
          {open&&<div className="note-panel paper">
            <div className="note-head"><b>Notifications</b>{notes.length>0&&<button onClick={()=>setNotes([])}>Clear</button>}</div>
            {notes.length?notes.map(n=><div className={"note"+(n.read?"":" unread")} key={n.id}><div className={"severity "+n.risk_level}>{n.risk_level==="HIGH"?"!":"·"}</div><div><b>{n.title}</b><span>{n.username} · {n.hostname} · {n.risk_score}/100</span><small>{new Date(n.timestamp).toLocaleTimeString()}</small></div></div>):<p className="muted">No new alerts this session.</p>}
          </div>}
        </div>
        <div className="live-dot"><b className={live?"on":""}/>{live?"LIVE":"RECONNECTING"}</div>
        <button className="signout" onClick={logout}>Sign out ↗</button>
      </div>
    </header>
    <main>
      <section className="page-title"><h1>Security Overview</h1></section>
      <section className="metrics">
        <Metric label="OPEN ALERTS" value={s.open_alerts||0} sub="Awaiting acknowledgement"/>
        <Metric label="HIGH RISK" value={s.high_risk||0} sub="Immediate review"/>
        <Metric label="MEDIUM RISK" value={s.medium_risk||0} sub="Contextual review"/>
        <Metric label="AFFECTED USERS" value={s.affected_users||0} sub="Flagged activity only"/>
      </section>
      <section className="paper panel category-panel">
        <div className="eyebrow">DETECTION BREAKDOWN</div><h3>Threat vectors</h3>
        <div className="bars">{cats.length?cats.map(([name,n])=><div className="bar" key={name}><div><b>{name}</b><strong>{n}</strong></div><div className="bar-bg"><i style={{width:Math.max(12,(n/maxCat)*100)+"%"}}/></div></div>):<p className="muted">No flagged vectors yet.</p>}</div>
      </section>
      <section className="paper panel alerts-panel">
        <div className="panel-head"><div><div className="eyebrow">REAL-TIME DETECTIONS</div><h3>Recent alerts</h3></div><div className="filters"><button className={filter==="ALL"?"sel":""} onClick={()=>setFilter("ALL")}>All</button><button className={filter==="HIGH"?"sel":""} onClick={()=>setFilter("HIGH")}>High</button><button className={filter==="MEDIUM"?"sel":""} onClick={()=>setFilter("MEDIUM")}>Medium</button></div></div>
        <div className="alert-list">{filtered.length?filtered.slice(0,10).map(x=><AlertRow key={x.id} x={x} ack={ack}/>):<div className="empty"><b>No flagged activity</b><span>Continuous monitoring is active.</span></div>}</div>
      </section>
      <section className="paper panel users-panel">
        <div className="eyebrow">RISK AGGREGATION</div><h3>Affected endpoints</h3>
        <div className="user-grid">{u.length?u.slice(0,8).map((x,i)=><div className="user-card" key={i}><div className="user-avatar">{(x.username||"?")[0].toUpperCase()}</div><div className="user-main"><b>{x.username}</b><span>{x.hostname} · {x.platform}</span></div><div className="user-risk"><small>MAX</small><strong className={x.max_risk>=75?"danger":x.max_risk>=50?"warn":""}>{x.max_risk}</strong></div><div className="user-count">{x.alert_count}<small>alerts</small></div></div>):<div className="muted">No affected endpoints.</div>}</div>
      </section>
    </main>
    <div className="toasts">{toasts.map(x=><div className={"toast paper "+x.risk_level} key={x.id} onClick={()=>setToasts(q=>q.filter(v=>v.id!==x.id))}><div className={"severity "+x.risk_level}>{x.risk_level==="HIGH"?"!":"·"}</div><div><b>{x.risk_level} · {x.title}</b><span>{x.username} on {x.hostname} · {x.risk_score}/100</span></div></div>)}</div>
  </div>
}

function Metric({label,value,sub}){return <div className="metric paper"><span>{label}</span><strong>{value}</strong><small>{sub}</small></div>}
function AlertRow({x,ack}){return <div className="alert-row"><div className={"severity "+x.risk_level}>{x.risk_level==="HIGH"?"!":"·"}</div><div className="alert-content"><div className="alert-title"><b>{x.title}</b><span>{category(x.event_type)}</span></div><p>{x.explanation}</p><div className="meta"><span>{x.username}</span><span>{x.hostname}</span><span>{new Date(x.timestamp).toLocaleString()}</span></div></div><div className="score"><strong>{x.risk_score}</strong><small>/100</small></div>{!x.acknowledged&&<button className="ack" onClick={()=>ack(x.id)}>ACK</button>}</div>}
function App(){const[t,st]=useState(localStorage.getItem("token"));function out(){localStorage.removeItem("token");st(null)}return t?<Dashboard token={t} logout={out}/>:<Login done={st}/>}
createRoot(document.getElementById("root")).render(<App/>);
