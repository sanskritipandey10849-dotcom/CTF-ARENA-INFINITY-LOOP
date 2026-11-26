import dotenv from "dotenv";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import path from "node:path";
import {fileURLToPath} from "node:url";
dotenv.config();
const dir=path.dirname(fileURLToPath(import.meta.url));
if(!process.env.ADMIN_USERNAME||!process.env.ADMIN_PASSWORD){console.error("Set ADMIN_USERNAME and ADMIN_PASSWORD in .env first.");process.exit(1);}
const db=new Database(path.join(dir,"data","arena.db"));
const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD,12);
try{db.prepare("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,'admin')").run(process.env.ADMIN_USERNAME,`${process.env.ADMIN_USERNAME}@arena.local`,hash);console.log("Admin account created.");}
catch{console.error("Could not create admin. The username may already exist.");}
