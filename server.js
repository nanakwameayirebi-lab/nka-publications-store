import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const BASE_URL = (process.env.BASE_URL || '').replace(/\/$/, '');

app.use('/api/paystack/webhook', express.raw({type:'application/json'}));
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname,'public')));

function required(){
  if(!PAYSTACK_SECRET_KEY) throw new Error('PAYSTACK_SECRET_KEY is missing');
  if(!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) throw new Error('Supabase environment variables are missing');
}
async function paystackRequest(endpoint, options={}){
  required();
  const r=await fetch('https://api.paystack.co'+endpoint,{...options,headers:{Authorization:`Bearer ${PAYSTACK_SECRET_KEY}`,'Content-Type':'application/json',...(options.headers||{})}});
  const d=await r.json();
  if(!r.ok || !d.status) throw new Error(d.message||`Paystack request failed (${r.status})`);
  return d;
}
async function supabase(pathname, options={}){
  const r=await fetch(`${SUPABASE_URL}/rest/v1${pathname}`,{...options,headers:{apikey:SUPABASE_SERVICE_ROLE_KEY,Authorization:`Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,'Content-Type':'application/json',...(options.headers||{})}});
  const text=await r.text(); let d; try{d=JSON.parse(text)}catch{d=text}
  if(!r.ok) throw new Error(typeof d==='string'?d:(d.message||d.error_description||JSON.stringify(d)));
  return d;
}
function hash(v){return crypto.createHash('sha256').update(v).digest('hex')}
function token(){return crypto.randomBytes(32).toString('hex')}
async function getProduct(slug){
  const rows=await supabase(`/products?slug=eq.${encodeURIComponent(slug)}&active=eq.true&select=*`);
  return rows[0];
}
async function getOrder(reference){
  const rows=await supabase(`/orders?reference=eq.${encodeURIComponent(reference)}&select=*`);
  return rows[0];
}
async function createDownloadToken(order){
  const raw=token();
  const expires=new Date(Date.now()+7*24*60*60*1000).toISOString();
  await supabase(`/orders?id=eq.${encodeURIComponent(order.id)}`,{method:'PATCH',headers:{Prefer:'return=minimal'},body:JSON.stringify({status:'paid',download_token_hash:hash(raw),download_token_expires_at:expires,updated_at:new Date().toISOString()})});
  return `${BASE_URL}/download/${raw}`;
}
async function fulfillOrder(reference, tx){
  const order=await getOrder(reference); if(!order) throw new Error('Order not found');
  if(tx.status!=='success') throw new Error('Payment not successful');
  if(Number(tx.amount)!==Number(order.amount) || tx.currency!==order.currency) throw new Error('Payment amount/currency mismatch');
  const product=await getProduct(order.product_slug); if(!product) throw new Error('Product not found');
  const downloadUrl=await createDownloadToken(order);
  return {downloadUrl,product};
}

app.get('/api/products', async (req,res)=>{try{const rows=await supabase('/products?active=eq.true&select=slug,name,price,currency');res.json(rows)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/initialize-payment', async (req,res)=>{
  try{
    const {email,product_slug}=req.body;
    if(!email || !product_slug) return res.status(400).json({error:'Email and product are required'});
    const product=await getProduct(product_slug); if(!product) return res.status(404).json({error:'Product not found'});
    const reference=`NKA-${Date.now()}-${crypto.randomBytes(5).toString('hex')}`;
    await supabase('/orders',{method:'POST',headers:{Prefer:'return=minimal'},body:JSON.stringify({reference,product_slug:product.slug,customer_email:String(email).trim().toLowerCase(),amount:product.price,currency:product.currency,status:'pending'})});
    const tx=await paystackRequest('/transaction/initialize',{method:'POST',body:JSON.stringify({email:String(email).trim().toLowerCase(),amount:product.price,currency:product.currency,reference,callback_url:`${BASE_URL}/api/paystack/callback`,channels:['card','mobile_money'],metadata:{product_slug:product.slug,customer_email:String(email).trim().toLowerCase()}})});
    res.json({status:true,authorization_url:tx.data.authorization_url,access_code:tx.data.access_code,reference});
  }catch(e){console.error(e);res.status(500).json({error:e.message})}
});

app.get('/api/paystack/callback',async(req,res)=>{
  const reference=req.query.reference;
  if(!reference) return res.redirect('/success.html?state=missing_reference');
  try{
    const v=await paystackRequest(`/transaction/verify/${encodeURIComponent(reference)}`);
    if(v.data.status==='success'){
      const result=await fulfillOrder(reference,v.data);
      return res.redirect(`/success.html?reference=${encodeURIComponent(reference)}&state=paid&download=${encodeURIComponent(result.downloadUrl)}`);
    }
    return res.redirect(`/success.html?reference=${encodeURIComponent(reference)}&state=pending`);
  }catch(e){console.error('callback',e);return res.redirect(`/success.html?reference=${encodeURIComponent(reference)}&state=error`)}
});

app.get('/api/order-status',async(req,res)=>{
  try{
    const reference=req.query.reference; if(!reference) return res.status(400).json({error:'Reference required'});
    const order=await getOrder(reference); if(!order) return res.status(404).json({error:'Order not found'});
    if(order.status==='paid') return res.json({status:'paid',downloadUrl:await createDownloadToken(order)});
    const v=await paystackRequest(`/transaction/verify/${encodeURIComponent(reference)}`);
    if(v.data.status==='success'){
      const result=await fulfillOrder(reference,v.data);
      return res.json({status:'paid',downloadUrl:result.downloadUrl});
    }
    res.json({status:v.data.status||order.status});
  }catch(e){res.status(500).json({error:e.message})}
});

function validSignature(req){
  const sig=req.headers['x-paystack-signature']; if(!sig || !PAYSTACK_SECRET_KEY) return false;
  const expected=crypto.createHmac('sha512',PAYSTACK_SECRET_KEY).update(req.body).digest('hex');
  return sig.length===expected.length && crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected));
}
app.post('/api/paystack/webhook',async(req,res)=>{
  try{
    if(!validSignature(req)) return res.status(401).send('Invalid signature');
    const event=JSON.parse(req.body.toString('utf8'));
    if(event.event==='charge.success' || event.event==='transaction.success'){
      const ref=event.data?.reference;
      if(ref){try{const v=await paystackRequest(`/transaction/verify/${encodeURIComponent(ref)}`);await fulfillOrder(ref,v.data)}catch(e){console.error('webhook fulfillment',e.message)}}
    }
    res.sendStatus(200);
  }catch(e){console.error('webhook',e);res.sendStatus(200)}
});

app.get('/download/:token',async(req,res)=>{
  try{
    const h=hash(req.params.token);
    const rows=await supabase(`/orders?download_token_hash=eq.${encodeURIComponent(h)}&status=eq.paid&select=*`);
    const order=rows[0];
    if(!order) return res.status(404).send('Download link is invalid or expired.');
    if(order.download_token_expires_at && new Date(order.download_token_expires_at).getTime()<Date.now()) return res.status(410).send('Download link has expired.');
    const product=await getProduct(order.product_slug); if(!product) return res.status(404).send('File unavailable.');
    const r=await fetch(`${SUPABASE_URL}/storage/v1/object/sign/ebooks/${product.file_path}`,{method:'POST',headers:{apikey:SUPABASE_SERVICE_ROLE_KEY,Authorization:`Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({expiresIn:600})});
    const d=await r.json(); if(!r.ok || !d.signedURL) throw new Error(d.message||'Could not create signed URL');
    const signed=d.signedURL.startsWith('http')?d.signedURL:`${SUPABASE_URL}/storage/v1${d.signedURL}`;
    res.redirect(signed);
  }catch(e){console.error('download',e);res.status(500).send('File currently not available. Please try again.')}
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
export default app;
