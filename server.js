import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET;
const FLAG_PEPPER = process.env.FLAG_PEPPER;
if (!SESSION_SECRET || SESSION_SECRET.length < 32 || !FLAG_PEPPER || FLAG_PEPPER.length < 24) {
  console.error("Set SESSION_SECRET (32+ chars) and FLAG_PEPPER (24+ chars) in .env");
  process.exit(1);
}

const db = new Database(path.join(__dirname, "data", "arena.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student',
 xp INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
 id INTEGER PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL,
 difficulty TEXT NOT NULL, points INTEGER NOT NULL, description TEXT NOT NULL,
 instructions TEXT NOT NULL, hint TEXT NOT NULL, flag_hash TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS solves (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
 points_awarded INTEGER NOT NULL, solved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(user_id, challenge_id)
);
CREATE TABLE IF NOT EXISTS attempts (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
 correct INTEGER NOT NULL, attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS teams (
 id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, invite_code TEXT UNIQUE NOT NULL,
 owner_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS team_members (
 team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY(team_id,user_id)
);
CREATE TABLE IF NOT EXISTS hints_used (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
 PRIMARY KEY(user_id,challenge_id)
);
`);
const flagHash = flag => crypto.createHmac("sha256", FLAG_PEPPER).update(flag).digest("hex");
const initial = [
 ["HTTP Detective","Web Detective","Easy",100,"Inspect the sample request shown below and identify the HTTP method used to retrieve a resource.","Sample request: GET /training/profile HTTP/1.1\nHost: arena.local\n\nSubmit the flag in the format RAVENX{GET}.","Look at the first word in the request line.","RAVENX{GET}"],
 ["Header Check","Web Security","Medium",200,"A training endpoint requires a custom header. Identify its name from the supplied documentation.","Training docs: The client must send X-ARENA-KEY: enabled. No real endpoint is involved.\nSubmit the header name as the flag.","It begins with X-.","RAVENX{X-ARENA-KEY}"],
 ["Caesar Archive","Cryptography","Easy",100,"Decode this Caesar-shifted training message: FODV.","Shift each letter back by one.","The decoded word is a common programming term.","RAVENX{CODE}"],
 ["File Signature","Digital Forensics","Medium",200,"A fictional file begins with the hexadecimal signature 50 4B 03 04. Identify the common file type.","This is a static forensic exercise. No files need to be downloaded.","Think of a compressed archive format.","RAVENX{ZIP}"],
 ["Subnet Basics","Networking","Hard",300,"In this training example, what is the number of usable host addresses in a /29 IPv4 subnet?","Use the standard IPv4 subnet host-count rule for a /29 network.","There are 8 total addresses; account for network and broadcast addresses.","RAVENX{6}"]
];
const insertChallenge = db.prepare(`INSERT INTO challenges(title,category,difficulty,points,description,instructions,hint,flag_hash)
 VALUES(?,?,?,?,?,?,?,?)`);
const count = db.prepare("SELECT COUNT(*) n FROM challenges").get().n;
if (!count) for (const c of initial) insertChallenge.run(c[0],c[1],c[2],c[3],c[4],c[5],c[6],flagHash(c[7]));

const safeUser = u => ({ id:u.id, username:u.username, role:u.role, xp:u.xp });
const hashToken = t => crypto.createHmac("sha256", SESSION_SECRET).update(t).digest("hex");
const appLimiter = rateLimit({ windowMs: 60_000, limit: 100, standardHeaders: true, legacyHeaders: false });
app.use(helmet({ contentSecurityPolicy: false }));
app.use(appLimiter);
app.use(express.json({limit:"20kb"}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname,"public")));

function auth(req,res,next) {
  const token=req.cookies.arena_session;
  if (!token) return res.status(401).json({error:"Please log in."});
  const row=db.prepare(`SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id
    WHERE sessions.token_hash=? AND sessions.expires_at>?`).get(hashToken(token),Date.now());
  if (!row) return res.status(401).json({error:"Session expired. Please log in again."});
  req.user=row; next();
}
function admin(req,res,next){ if(req.user?.role!=="admin") return res.status(403).json({error:"Administrator access required."}); next(); }
function validText(v,min,max){ return typeof v==="string" && v.trim().length>=min && v.trim().length<=max; }
function newSession(userId,res){
  const token=crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").run(hashToken(token),userId,Date.now()+7*86400000);
  res.cookie("arena_session",token,{httpOnly:true,sameSite:"strict",secure:process.env.NODE_ENV==="production",maxAge:7*86400000});
}

app.post("/api/auth/register", async (req,res)=>{
  const {username,email,password}=req.body||{};
  if(!validText(username,3,20)||!/^[a-zA-Z0-9_]+$/.test(username)||!validText(email,5,120)||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!validText(password,10,100))
    return res.status(400).json({error:"Use a 3–20 character username, valid email and password of at least 10 characters."});
  try{
    const info=db.prepare("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)").run(username.trim(),email.trim().toLowerCase(),await bcrypt.hash(password,12));
    newSession(info.lastInsertRowid,res);
    res.json({user:safeUser(db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid))});
  }catch(e){res.status(409).json({error:"Username or email is already registered."});}
});
app.post("/api/auth/login",async(req,res)=>{
  const {username,password}=req.body||{};
  if(!validText(username,1,80)||!validText(password,1,100)) return res.status(400).json({error:"Enter your username and password."});
  const u=db.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE").get(username.trim());
  if(!u||!(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:"Incorrect username or password."});
  newSession(u.id,res); res.json({user:safeUser(u)});
});
app.post("/api/auth/logout",auth,(req,res)=>{db.prepare("DELETE FROM sessions WHERE user_id=?").run(req.user.id);res.clearCookie("arena_session");res.json({ok:true});});
app.get("/api/auth/me",auth,(req,res)=>res.json({user:safeUser(req.user)}));

app.get("/api/dashboard",auth,(req,res)=>{
 const solved=db.prepare("SELECT COUNT(*) n FROM solves WHERE user_id=?").get(req.user.id).n;
 const total=db.prepare("SELECT COUNT(*) n FROM challenges WHERE active=1").get().n;
 const rank=db.prepare("SELECT COUNT(*)+1 r FROM users WHERE xp>?").get(req.user.xp).r;
 const team=db.prepare("SELECT teams.* FROM teams JOIN team_members ON teams.id=team_members.team_id WHERE team_members.user_id=?").get(req.user.id)||null;
 res.json({user:safeUser(req.user),solved,total,progress:total?Math.round(solved/total*100):0,rank,team});
});
app.get("/api/challenges",auth,(req,res)=>{
 const rows=db.prepare(`SELECT c.id,c.title,c.category,c.difficulty,c.points,c.description,
 EXISTS(SELECT 1 FROM solves s WHERE s.challenge_id=c.id AND s.user_id=?) solved
 FROM challenges c WHERE c.active=1 ORDER BY c.id`).all(req.user.id);
 res.json({challenges:rows});
});
app.get("/api/challenges/:id",auth,(req,res)=>{
 const c=db.prepare("SELECT id,title,category,difficulty,points,description,instructions FROM challenges WHERE id=? AND active=1").get(Number(req.params.id));
 if(!c)return res.status(404).json({error:"Challenge not found."});
 res.json({challenge:c});
});
app.post("/api/challenges/:id/submit",auth,(req,res)=>{
 const id=Number(req.params.id), flag=req.body?.flag;
 if(!Number.isInteger(id)||!validText(flag,3,120))return res.status(400).json({error:"Enter a valid flag."});
 const c=db.prepare("SELECT * FROM challenges WHERE id=? AND active=1").get(id);
 if(!c)return res.status(404).json({error:"Challenge not found."});
 if(db.prepare("SELECT 1 FROM solves WHERE user_id=? AND challenge_id=?").get(req.user.id,id))return res.status(409).json({error:"You have already solved this challenge."});
 const attempts=db.prepare("SELECT COUNT(*) n FROM attempts WHERE user_id=? AND attempted_at>datetime('now','-1 hour')").get(req.user.id).n;
 if(attempts>=30)return res.status(429).json({error:"Too many attempts. Try again later."});
 const correct=crypto.timingSafeEqual(Buffer.from(flagHash(flag.trim())),Buffer.from(c.flag_hash));
 db.prepare("INSERT INTO attempts(user_id,challenge_id,correct) VALUES(?,?,?)").run(req.user.id,id,correct?1:0);
 if(!correct)return res.status(400).json({error:"Incorrect flag. Review the challenge and try again."});
 const used=db.prepare("SELECT 1 FROM hints_used WHERE user_id=? AND challenge_id=?").get(req.user.id,id);
 const award=Math.max(50,c.points-(used?25:0));
 const tx=db.transaction(()=>{db.prepare("INSERT INTO solves(user_id,challenge_id,points_awarded) VALUES(?,?,?)").run(req.user.id,id,award);db.prepare("UPDATE users SET xp=xp+? WHERE id=?").run(award,req.user.id);});
 tx();res.json({ok:true,message:"Flag accepted! Challenge cleared.",pointsAwarded:award});
});
app.post("/api/challenges/:id/hint",auth,(req,res)=>{
 const id=Number(req.params.id),c=db.prepare("SELECT hint FROM challenges WHERE id=? AND active=1").get(id);
 if(!c)return res.status(404).json({error:"Challenge not found."});
 if(db.prepare("SELECT 1 FROM solves WHERE user_id=? AND challenge_id=?").get(req.user.id,id))return res.status(409).json({error:"Challenge already solved."});
 db.prepare("INSERT OR IGNORE INTO hints_used(user_id,challenge_id) VALUES(?,?)").run(req.user.id,id);
 res.json({hint:c.hint,penalty:"Using a hint reduces this challenge reward by 25 points."});
});
app.get("/api/leaderboard",auth,(req,res)=>res.json({leaders:db.prepare(`SELECT username,xp,(SELECT COUNT(*) FROM solves WHERE solves.user_id=users.id) solved
 FROM users ORDER BY xp DESC,username ASC LIMIT 50`).all()}));

app.post("/api/teams",auth,(req,res)=>{
 const name=req.body?.name;
 if(!validText(name,3,24))return res.status(400).json({error:"Team name must be 3–24 characters."});
 if(db.prepare("SELECT 1 FROM team_members WHERE user_id=?").get(req.user.id))return res.status(409).json({error:"You are already in a team."});
 try{const code=crypto.randomBytes(4).toString("hex").toUpperCase();const id=db.prepare("INSERT INTO teams(name,invite_code,owner_id) VALUES(?,?,?)").run(name.trim(),code,req.user.id).lastInsertRowid;db.prepare("INSERT INTO team_members(team_id,user_id) VALUES(?,?)").run(id,req.user.id);res.json({team:{id,name:name.trim(),invite_code:code}});}catch(e){res.status(409).json({error:"That team name is already taken."});}
});
app.post("/api/teams/join",auth,(req,res)=>{
 const code=req.body?.code;
 if(!validText(code,4,12))return res.status(400).json({error:"Enter an invitation code."});
 if(db.prepare("SELECT 1 FROM team_members WHERE user_id=?").get(req.user.id))return res.status(409).json({error:"Leave your current team first."});
 const t=db.prepare("SELECT * FROM teams WHERE invite_code=?").get(code.trim().toUpperCase());
 if(!t)return res.status(404).json({error:"Invitation code not found."});
 db.prepare("INSERT INTO team_members(team_id,user_id) VALUES(?,?)").run(t.id,req.user.id);res.json({ok:true,team:t.name});
});
app.get("/api/teams/me",auth,(req,res)=>{
 const t=db.prepare(`SELECT t.id,t.name,t.invite_code,t.owner_id FROM teams t JOIN team_members m ON m.team_id=t.id WHERE m.user_id=?`).get(req.user.id);
 if(!t)return res.json({team:null});
 t.members=db.prepare("SELECT u.username,u.xp FROM team_members m JOIN users u ON u.id=m.user_id WHERE m.team_id=? ORDER BY u.xp DESC").all(t.id);
 t.totalXp=t.members.reduce((s,m)=>s+m.xp,0);res.json({team:t});
});
app.post("/api/teams/leave",auth,(req,res)=>{
 const t=db.prepare("SELECT team_id FROM team_members WHERE user_id=?").get(req.user.id);
 if(!t)return res.status(404).json({error:"You are not in a team."});
 const team=db.prepare("SELECT * FROM teams WHERE id=?").get(t.team_id);
 if(team.owner_id===req.user.id){db.prepare("DELETE FROM teams WHERE id=?").run(team.id);}else{db.prepare("DELETE FROM team_members WHERE user_id=?").run(req.user.id);}
 res.json({ok:true});
});

app.get("/api/admin/statistics",auth,admin,(req,res)=>res.json({
 users:db.prepare("SELECT COUNT(*) n FROM users").get().n,
 challenges:db.prepare("SELECT COUNT(*) n FROM challenges").get().n,
 solves:db.prepare("SELECT COUNT(*) n FROM solves").get().n
}));
app.get("/api/admin/users",auth,admin,(req,res)=>res.json({users:db.prepare("SELECT id,username,email,role,xp,created_at FROM users ORDER BY created_at DESC").all()}));
app.get("/api/admin/challenges",auth,admin,(req,res)=>res.json({challenges:db.prepare("SELECT id,title,category,difficulty,points,description,active FROM challenges ORDER BY id").all()}));
app.post("/api/admin/challenges",auth,admin,(req,res)=>{
 const {title,category,difficulty,points,description,instructions,hint,flag}=req.body||{};
 if(!validText(title,3,100)||!validText(category,3,40)||!["Easy","Medium","Hard"].includes(difficulty)||![100,200,300].includes(Number(points))||!validText(description,5,500)||!validText(instructions,5,2000)||!validText(hint,3,300)||!validText(flag,5,120))return res.status(400).json({error:"Check all challenge fields. Points must be 100, 200 or 300."});
 const info=db.prepare("INSERT INTO challenges(title,category,difficulty,points,description,instructions,hint,flag_hash) VALUES(?,?,?,?,?,?,?,?)").run(title,category,difficulty,Number(points),description,instructions,hint,flagHash(flag.trim()));
 res.status(201).json({id:info.lastInsertRowid});
});
app.put("/api/admin/challenges/:id",auth,admin,(req,res)=>{
 const {title,category,difficulty,points,description,instructions,hint,flag}=req.body||{};
 if(!validText(title,3,100)||!validText(category,3,40)||!["Easy","Medium","Hard"].includes(difficulty)||![100,200,300].includes(Number(points))||!validText(description,5,500)||!validText(instructions,5,2000)||!validText(hint,3,300))return res.status(400).json({error:"Invalid challenge fields."});
 const c=db.prepare("SELECT id FROM challenges WHERE id=?").get(Number(req.params.id));if(!c)return res.status(404).json({error:"Challenge not found."});
 if(flag&&validText(flag,5,120))db.prepare("UPDATE challenges SET title=?,category=?,difficulty=?,points=?,description=?,instructions=?,hint=?,flag_hash=? WHERE id=?").run(title,category,difficulty,Number(points),description,instructions,hint,flagHash(flag.trim()),c.id);
 else db.prepare("UPDATE challenges SET title=?,category=?,difficulty=?,points=?,description=?,instructions=?,hint=? WHERE id=?").run(title,category,difficulty,Number(points),description,instructions,hint,c.id);
 res.json({ok:true});
});
app.delete("/api/admin/challenges/:id",auth,admin,(req,res)=>{
 const info=db.prepare("UPDATE challenges SET active=0 WHERE id=?").run(Number(req.params.id));
 if(!info.changes)return res.status(404).json({error:"Challenge not found."});res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`CTF ARENA running at http://localhost:${PORT}`));
