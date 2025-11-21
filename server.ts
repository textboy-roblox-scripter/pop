import express from "express"
import axios from "axios"
import cookieParser from "cookie-parser"
import cors from "cors"
import jwt from "jsonwebtoken"
import crypto from "crypto"

const app = express()
app.use(cors({origin:true,credentials:true}))
app.use(express.json())
app.use(cookieParser())

const CLIENT_ID=process.env.DISCORD_CLIENT_ID||""
const CLIENT_SECRET=process.env.DISCORD_CLIENT_SECRET||""
const BASE_URL=process.env.BASE_URL||"http://localhost:4000"
const JWT_SECRET=process.env.JWT_SECRET||"jwtsecret"
const BOT_SHARED=process.env.BOT_SHARED_SECRET||""
const BOT_API_URL=process.env.BOT_API_URL||"http://localhost:3002/api/execute"
const BOT_GUILD_IDS=(process.env.BOT_GUILD_IDS||"").split(",").filter(Boolean)

app.get("/auth/login",(req,res)=>{
  const redirect=encodeURIComponent(process.env.REDIRECT_URI||BASE_URL+"/auth/callback")
  res.redirect(`https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${redirect}&response_type=code&scope=identify%20guilds`)
})

app.get("/auth/callback",async(req,res)=>{
  const code=String(req.query.code||"")
  const params=new URLSearchParams()
  params.set("client_id",CLIENT_ID)
  params.set("client_secret",CLIENT_SECRET)
  params.set("grant_type","authorization_code")
  params.set("code",code)
  params.set("redirect_uri",process.env.REDIRECT_URI||BASE_URL+"/auth/callback")
  params.set("scope","identify guilds")
  const tokenRes=await axios.post("https://discord.com/api/oauth2/token",params,{headers:{"Content-Type":"application/x-www-form-urlencoded"}})
  const access=tokenRes.data.access_token
  const userRes=await axios.get("https://discord.com/api/users/@me",{headers:{Authorization:`Bearer ${access}`}})
  const guildsRes=await axios.get("https://discord.com/api/users/@me/guilds",{headers:{Authorization:`Bearer ${access}`}})
  const token=jwt.sign({user:userRes.data,guilds:guildsRes.data,access},JWT_SECRET,{expiresIn:"7d"})
  res.cookie("session",token,{httpOnly:true,sameSite:"lax",secure:false,maxAge:7*24*60*60*1000})
  res.redirect((process.env.FRONTEND_URL||"http://localhost:3000")+"/dashboard")
})

function getSession(req:any){const t=req.cookies?.session;if(!t)return null;try{return jwt.verify(t,JWT_SECRET)}catch{return null}}

app.get("/api/my-guilds",(req,res)=>{
  const s=getSession(req)
  if(!s)return res.status(401).json({error:"unauthenticated"})
  const userGuilds=(s as any).guilds||[]
  const manageable=userGuilds.filter((g:any)=>(BigInt(g.permissions||"0")&0x20n)===0x20n)
  const final=manageable.filter((g:any)=>BOT_GUILD_IDS.includes(g.id))
  res.json(final)
})

app.post("/api/sig",(req,res)=>{
  const body=JSON.stringify(req.body||"")
  const h=crypto.createHmac("sha256",BOT_SHARED).update(body).digest("hex")
  res.send(h)
})

app.post("/api/execute",async(req,res)=>{
  const s=getSession(req)
  if(!s)return res.status(401).json({error:"unauthenticated"})
  const sig=String(req.headers["x-bot-sig"]||"")
  const r=await axios.post(BOT_API_URL,req.body,{headers:{"Content-Type":"application/json","x-bot-sig":sig}})
  res.json(r.data)
})

app.listen(Number(process.env.PORT||4000))
