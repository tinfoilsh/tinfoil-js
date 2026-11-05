import { ASN1Obj } from '@freedomofpress/crypto-browser';
import { TDXQuote } from '../src/tdx/quote.js';
import { pckExtensions } from '../src/tdx/collateral.js';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { authenticateQuote, validatePolicy } from '../src/quote/index.js';
import { buffer, certificate, der, hex, pemCertificates, unhex } from '../src/quote/crypto.js';
import { AMD_TURIN } from '../src/quote/roots.js';
import { GUEST_BITS, parsePlatformArtifact, PLATFORM_BITS, PLATFORM_V2 } from '../src/policy/index.js';
import { parseJSON } from '../src/encoding.js';
import { Report } from '../src/sev/report.js';
const fixture = (name: string) => JSON.parse(readFileSync(new URL(`fixtures/hardware-v3/${name}.json`, import.meta.url), 'utf8'));
const bytes = (s: string) => Uint8Array.from(Buffer.from(s, 'base64'));
const sev = fixture('sev'), tdx = fixture('tdx'), copy = structuredClone;
async function key(f: any, name = 'privateKey', curve = 'P-384') { return crypto.subtle.importKey('pkcs8', buffer(bytes(f[name])), { name: 'ECDSA', namedCurve: curve }, false, ['sign']); }
async function signed(f: any, change: (r: Uint8Array, v: DataView) => void) {
 f=copy(f);const r=bytes(f.report);change(r,new DataView(r.buffer));const intel=Boolean(f.responses),size=intel?32:48;
 const sig=new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:intel?'SHA-256':'SHA-384'},await key(f,'privateKey',intel?'P-256':'P-384'),buffer(r.slice(0,intel?0x278:0x2a0))));
 if(intel)r.set(sig,0x27c);else {r.set(sig.slice(0,size).reverse(),0x2a0);r.set(sig.slice(size).reverse(),0x2e8);}f.report=Buffer.from(r).toString('base64');return f;
}
async function authenticate(f: any,date?:Date) {
 const intel=Boolean(f.responses),en=intel?{intelPcs:{responses:f.responses.map((r:any)=>({url:r.url,headers:r.headers,body:bytes(r.body_base64)}))}}:{amdVcek:{vcekDer:bytes(f.vcek),certChainPem:f.chain},amdCrl:{crlDer:bytes(f.crl)}};
 return authenticateQuote({format:`https://tinfoil.sh/format/${intel?'tdx-quote':'sev-snp-report'}/v1`,report:bytes(f.report)},en,date??new Date(f.time*1000),{amdRootPem:f.chain,intelRootPem:f.root});
}
async function verify(f:any,pins?:any){return validatePolicy(await authenticate(f),f.refs,unhex(f.reportData),pins);}
async function pcs(f:any,kind:'tcbInfo'|'enclaveIdentity',mutate:(o:any)=>void){
 f=copy(f);const r=f.responses.find((r:any)=>r.url.includes(kind==='tcbInfo'?'/tcb?':'/qe/identity')),o=JSON.parse(Buffer.from(r.body_base64,'base64').toString());mutate(o[kind]);
 o.signature=hex(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},await key(f,'tcbPrivateKey','P-256'),buffer(new TextEncoder().encode(JSON.stringify(o[kind]))))));r.body_base64=Buffer.from(JSON.stringify(o)).toString('base64');return f;
}
describe('portable v3 hardware',()=>{
 it.each([['SEV',sev],['TDX',tdx]])('authenticates and appraises %s',async(_,f)=>{expect(await verify(f)).toMatchObject({codeMeasurement:f.refs[f.responses?'tdx':'snp']});});
 it('handles sliced Buffer inputs and refuses fabricated authenticated objects',async()=>{const q=await authenticate(sev);await expect(validatePolicy({...q},sev.refs,unhex(sev.reportData))).rejects.toMatchObject({layer:'policy'});const r=Buffer.concat([Buffer.alloc(13),Buffer.from(sev.report,'base64'),Buffer.alloc(13)]).subarray(13,-13);expect(new Report(r).launch).toBe(sev.refs.snp.launch);});
 it.each(Object.entries(GUEST_BITS))('enforces SNP guest-policy %s',async(_,bit)=>{await expect(verify(await signed(sev,(_r,v)=>v.setBigUint64(8,v.getBigUint64(8,true)^(1n<<BigInt(bit)),true)))).rejects.toMatchObject({layer:'policy'});});
 it.each(Object.entries(PLATFORM_BITS))('enforces SNP platform-info %s',async(_,bit)=>{await expect(verify(await signed(sev,(_r,v)=>v.setBigUint64(0x40,v.getBigUint64(0x40,true)^(1n<<BigInt(bit)),true)))).rejects.toMatchObject({layer:'policy'});});
 it.each(['bl_spl','tee_spl','snp_spl','ucode_spl'])('enforces each SNP %s floor',async name=>{for(const block of ['minimum_tcb','minimum_launch_tcb']){const f=copy(sev);f.refs.platformArtifact.policies['sev-policy'].sev_snp[block][name]=255;await expect(verify(f)).rejects.toMatchObject({layer:'policy'});}});
 it('preserves exact uint64 mitigation bits above 2^53',async()=>{const f=await signed(sev,(_r,v)=>{v.setUint32(0,5,true);v.setBigUint64(0x1f8,1n<<60n,true);v.setBigUint64(0x200,1n<<63n,true);});const p=f.refs.platformArtifact.policies['sev-policy'].sev_snp;p.minimum_launch_mitigation_vector=parseJSON('1152921504606846976');p.minimum_current_mitigation_vector=parseJSON('9223372036854775808');await expect(verify(f)).resolves.toBeDefined();p.minimum_launch_mitigation_vector=parseJSON('1152921504606846977');await expect(verify(f)).rejects.toMatchObject({layer:'policy'});p.minimum_launch_mitigation_vector=1152921504606846976;expect(()=>parsePlatformArtifact(f.refs.platformArtifact)).toThrow('exact');});
 it.each([0x180,0x1a0])('rejects signed cert/report mismatch at %s before mismatched policy',async offset=>{const f=await signed(sev,r=>{r[offset]^=1;r[0xc0]=9;});f.refs.snp.launch='ff'.repeat(48);await expect(verify(f)).rejects.toMatchObject({layer:'quote'});});
 it.each([0xe0,0x110])('rejects ID-block material at %s',async offset=>{await expect(verify(await signed(sev,r=>{r[offset]=1;}))).rejects.toMatchObject({layer:'policy'});});
 it.each([0x4c,0x18b,0x208,0x2d0,0x318])('rejects SNP reserved data at %s',async offset=>{await expect(authenticate(await signed(sev,r=>{r[offset]=1;}))).rejects.toMatchObject({layer:'quote'});});
 it('checks CRL bounds inclusively',async()=>{const fs=der(bytes(sev.crl)).subs[0].subs,start=fs[3].toDate(),end=fs[4].toDate();await expect(authenticate(sev,start)).resolves.toBeDefined();await expect(authenticate(sev,end)).resolves.toBeDefined();await expect(authenticate(sev,new Date(+start-1))).rejects.toMatchObject({layer:'quote'});await expect(authenticate(sev,new Date(+end+1))).rejects.toMatchObject({layer:'quote'});});
 it.each([['MRSEAM',0x10],['TD_ATTRIBUTES',0x78],['XFAM',0x80],['MRTD',0x88],['MRCONFIGID',0xb8],['MROWNER',0xe8],['MROWNERCONFIG',0x118],['RTMR0',0x148],['RTMR1',0x178],['RTMR2',0x1a8],['RTMR3',0x1d8],['REPORT_DATA',0x208]] as const)('checks signed TDX %s',async(_,offset)=>{await expect(verify(await signed(tdx,r=>{r[48+offset]^=1;}))).rejects.toMatchObject({layer:'policy'});});
 it('rejects TDX debug even if endorsed',async()=>{const f=await signed(tdx,r=>{r[48+0x78]|=1;});f.refs.platformArtifact.policies['tdx-policy'].tdx.td_attributes='0100004000000000';await expect(verify(f)).rejects.toMatchObject({layer:'policy'});});
 it('accepts zero padding and rejects unsigned nonzero trailing quote data',async()=>{const f=copy(tdx);f.report=Buffer.concat([Buffer.from(f.report,'base64'),Buffer.alloc(70)]).toString('base64');await expect(verify(f)).resolves.toBeDefined();f.report=Buffer.concat([Buffer.from(f.report,'base64'),Buffer.from([1])]).toString('base64');await expect(authenticate(f)).rejects.toMatchObject({layer:'quote'});});
 it.each(['tcbInfo','enclaveIdentity'] as const)('rejects duplicate PCS %s member substitution',async kind=>{const f=copy(tdx),r=f.responses.find((r:any)=>r.url.includes(kind==='tcbInfo'?'/tcb?':'/qe/identity'));r.body_base64=Buffer.from(Buffer.from(r.body_base64,'base64').toString().replace('{',`{"${kind}":{},`)).toString('base64');await expect(authenticate(f)).rejects.toMatchObject({layer:'quote'});});
 it.each(['Revoked','OutOfDate','OutOfDateConfigurationNeeded','ConfigurationNeeded','SWHardeningNeeded'])('rejects Intel TCB %s',async status=>{for(const kind of ['tcbInfo','enclaveIdentity'] as const)await expect(authenticate(await pcs(tdx,kind,o=>{o.tcbLevels[0].tcbStatus=status;}))).rejects.toMatchObject({layer:'quote'});});
 it('rejects signed TDX module TCB downgrade',async()=>{await expect(authenticate(await pcs(tdx,'tcbInfo',o=>{o.tdxModuleIdentities.find((m:any)=>m.id==='TDX_03').tcbLevels[0].tcbStatus='OutOfDate';}))).rejects.toMatchObject({layer:'quote'});});
 it('binds QE report to exact attestation key',async()=>{const f=copy(tdx),r=bytes(f.report),start=0x27c+128+6;r[start+0x140]^=1;r.set(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},await key(f,'pckPrivateKey','P-256'),buffer(r.slice(start,start+384)))),start+384);f.report=Buffer.from(r).toString('base64');await expect(authenticate(f)).rejects.toMatchObject({layer:'quote'});});
 it.each([['SEV',sev],['TDX',tdx]])('authenticates %s config/runtime bindings through shared policy path',async(_,base)=>{const hash='af'.repeat(32),f=await signed(base,r=>r.set(unhex(hash),base.responses?48+0xb8:0xc0)),q=await authenticate(f),a=f.refs.platformArtifact;a.format=PLATFORM_V2;a.measurements={};for(const p of Object.values(a.policies) as any[]){if(p.sev_snp)delete p.sev_snp.host_data;if(p.tdx)delete p.tdx.platform_measurements;}const refs={...f.refs,kind:'config',configHash:hash,[q.platform==='sev-snp'?'snp':'tdx']:q.measurement};await expect(validatePolicy(q,refs,unhex(f.reportData))).resolves.toBeDefined();await expect(validatePolicy(q,{...refs,configHash:'bf'.repeat(32)},unhex(f.reportData))).rejects.toMatchObject({layer:'policy'});const pin=q.platform==='sev-snp'?{type:'sev-snp',launch:'ff'.repeat(48)}:{type:'tdx',rtmr2:'ff'.repeat(48)};await expect(validatePolicy(q,refs,unhex(f.reportData),pin as any)).rejects.toMatchObject({layer:'policy'});});
 it('fills unspecified RTMR3 pins and checks fixed-register agreement',async()=>{const f=await signed(tdx,r=>r.fill(0x77,48+0x1d8,48+0x208));await expect(verify(f)).rejects.toMatchObject({layer:'policy'});await expect(verify(f,{type:'tdx',rtmr3:'77'.repeat(48)})).resolves.toBeDefined();await expect(verify(tdx,{type:'tdx',rtmr1:'77'.repeat(48)})).rejects.toMatchObject({layer:'policy'});});
 it.each(['inf17','inf18'])('verifies production Turin %s with embedded roots and captured CRL',async name=>{const f=fixture(`turin-${name}`),r=Buffer.from(f.report_base64,'base64');const q=await authenticateQuote({format:'https://tinfoil.sh/format/sev-snp-report/v1',report:r},{amdVcek:{vcekDer:Buffer.from(f.vcek_der_base64,'base64'),certChainPem:AMD_TURIN},amdCrl:{crlDer:readFileSync(new URL('fixtures/hardware-v3/turin-crl.der',import.meta.url))}},new Date('2026-10-24T00:00:00Z'));const a={format:'https://tinfoil.sh/predicate/platform-endorsements/v1',measurements:{},machines:{[q.identity]:'turin'},policies:{turin:f.policy}},refs={...sev.refs,platformArtifact:a,snp:q.measurement};await expect(validatePolicy(q,refs,Uint8Array.from(r.subarray(0x50,0x90)))).resolves.toBeDefined();f.policy.sev_snp.platform_info.ecc_enabled=false;await expect(validatePolicy(q,refs,Uint8Array.from(r.subarray(0x50,0x90)))).rejects.toMatchObject({layer:'policy'});});
 it('accepts authenticated TDX user data changes without changing platform identity',async()=>{
  const original=await authenticate(tdx),f=await signed(tdx,r=>r.fill(0xa5,28,48)),changed=await authenticate(f);
  expect(changed.identity).toBe(original.identity);expect(changed.measurement).toEqual(original.measurement);await expect(verify(f)).resolves.toBeDefined();
 });
 it('rejects paired TDX signature and policy mismatches during quote authentication',async()=>{
  const f=copy(tdx),r=bytes(f.report);r[0x27c]^=1;f.report=Buffer.from(r).toString('base64');f.refs.tdx.rtmr1='ff'.repeat(48);
  await expect(verify(f)).rejects.toMatchObject({layer:'quote'});
  const q=await authenticate(tdx);const refs=copy(tdx.refs);refs.platformArtifact.machines={};await expect(validatePolicy(q,refs,unhex(tdx.reportData))).rejects.toMatchObject({layer:'policy'});
 });
 it('rejects unsupported required device constraints instead of treating GPU shape as evidence',async()=>{
  const f=copy(sev);f.refs.shape.gpus=1;await expect(verify(f)).resolves.toBeDefined();
  f.refs.platformArtifact.policies['sev-policy'].required_devices=['gpu'];await expect(verify(f)).rejects.toMatchObject({layer:'policy'});
 });
 it('compares every TDATTRIBUTES and XFAM bit with authenticated policy',async()=>{
  for(const offset of [0x78,0x80])for(let bit=0;bit<64;bit++){
   const f=await signed(tdx,(_r,v)=>v.setBigUint64(48+offset,v.getBigUint64(48+offset,true)^(1n<<BigInt(bit)),true));
   await expect(verify(f)).rejects.toMatchObject({layer:'policy'});
  }
 });
 it('enforces TDX fixed bits even when the policy repeats unsupported values',async()=>{
  // TDX 1.0 permits these XSAVE features in addition to fixed x87 and SSE.
  const optionalXFAM=[2,5,6,7,8,9,11,12,14,15,17,18],optionalAttributes=[28,30,63];
  for(const [offset,name,allowed] of [[0x78,'td_attributes',optionalAttributes],[0x80,'xfam',optionalXFAM]] as const)for(let bit=0;bit<64;bit++){
   const f=await signed(tdx,(_r,v)=>v.setBigUint64(48+offset,v.getBigUint64(48+offset,true)^(1n<<BigInt(bit)),true));
   f.refs.platformArtifact.policies['tdx-policy'].tdx[name]=hex(bytes(f.report).slice(48+offset,48+offset+8));
   if(allowed.includes(bit))await expect(verify(f)).resolves.toBeDefined();else await expect(verify(f)).rejects.toMatchObject({layer:'policy'});
  }
 });
 it('rejects unsupported quote algorithms and TEE type before appraisal',async()=>{
  for(const [base,offset,value] of [[sev,0x34,2],[tdx,2,3],[tdx,4,0]] as const){
   const f=await signed(base,(_r,v)=>offset===2?v.setUint16(offset,value,true):v.setUint32(offset,value,true));await expect(authenticate(f)).rejects.toMatchObject({layer:'quote'});
  }
 });

 it('requires report v5 for nonzero SNP mitigation floors',async()=>{
  for(const version of [3,4,5]){
   const f=await signed(sev,(_r,v)=>{v.setUint32(0,version,true);v.setBigUint64(0x1f8,version===5?1n:0n,true);v.setBigUint64(0x200,version===5?1n:0n,true);});
   for(const name of ['minimum_launch_mitigation_vector','minimum_current_mitigation_vector'])f.refs.platformArtifact.policies['sev-policy'].sev_snp[name]=1;
   if(version===5)await expect(verify(f)).resolves.toBeDefined();else await expect(verify(f)).rejects.toMatchObject({layer:'policy'});
  }
 });
 it('rejects every SNP reserved guest-policy and platform-info bit',()=>{
  const samples=[bytes(sev.report),bytes(fixture('turin-inf17').report_base64)];
  for(const original of samples)for(const [offset,bits] of [[8,[17,...Array.from({length:38},(_,i)=>i+26)]],[0x40,Array.from({length:56},(_,i)=>i+8)]] as [number,number[]][]){
   for(const bit of bits){const r=Uint8Array.from(original),v=new DataView(r.buffer);v.setBigUint64(offset,v.getBigUint64(offset,true)^(1n<<BigInt(bit)),true);expect(()=>new Report(r)).toThrow('reserved');}
  }
 });

 it('requires canonical PPID in every parsed PCK SGX extension',()=>{
  const pck=pemCertificates(new TDXQuote(bytes(tdx.report)).certificateChain)[0],prefix='1.2.840.113741.1.13.1';
  for(const mode of ['missing','short','type','duplicate']){
   const root=der(pck.root.toDER()),extensions=root.subs[0].subs.find(n=>n.tag.isContextSpecific(3))!.subs[0];
   const extension=extensions.subs.find(n=>n.subs[0].toOID()===prefix)!,payload=der(extension.subs[extension.subs.length-1].value);
   const index=payload.subs.findIndex(n=>n.subs[0].toOID()===prefix+'.1'),ppid=payload.subs[index];
   if(mode==='missing')payload.subs.splice(index,1);
   if(mode==='duplicate')payload.subs.push(ppid);
   if(mode==='short')ppid.subs[1]=new ASN1Obj(ppid.subs[1].tag,ppid.subs[1].value.slice(1),[]);
   if(mode==='type')ppid.subs[1]=der(new Uint8Array([2,1,0]));
   const last=extension.subs.length-1;extension.subs[last]=new ASN1Obj(extension.subs[last].tag,payload.toDER(),[]);
   expect(()=>pckExtensions(certificate(root.toDER()))).toThrow();
  }
 });
 it.each(['tcbInfo','enclaveIdentity'] as const)('enforces both signed PCS %s validity endpoints inclusively',async kind=>{
  for(const [field,delta,accept] of [['issueDate',0,true],['issueDate',1,false],['nextUpdate',0,true],['nextUpdate',-1,false]] as const){
   const f=await pcs(tdx,kind,o=>{o[field]=new Date(tdx.time*1000+delta*1000).toISOString();});
   if(accept)await expect(authenticate(f)).resolves.toBeDefined();else await expect(authenticate(f)).rejects.toMatchObject({layer:'quote'});
  }
 });
 it('requires each SNP and TDX policy field in both platform profiles',()=>{
  const required={sev_snp:['minimum_build','minimum_api_version','minimum_abi_version','minimum_guest_svn','minimum_tcb','minimum_launch_tcb','vmpl','image_id','family_id','minimum_launch_mitigation_vector','minimum_current_mitigation_vector'],tdx:['qe_vendor_id','minimum_tee_tcb_svn','mr_seam','td_attributes','xfam','minimum_tcb_evaluation_data_number']};
  for(const base of [sev,tdx])for(const config of [false,true]){
   const artifact=copy(base.refs.platformArtifact),block=base.responses?'tdx':'sev_snp',name=base.responses?'tdx-policy':'sev-policy';
   if(config){artifact.format=PLATFORM_V2;delete artifact.measurements;for(const policy of Object.values(artifact.policies) as any[]){if(policy.sev_snp)delete policy.sev_snp.host_data;if(policy.tdx)delete policy.tdx.platform_measurements;}}
   expect(()=>parsePlatformArtifact(artifact)).not.toThrow();
   for(const field of [...required[block],...(config?[]:[block==='tdx'?'platform_measurements':'host_data'])])for(const missing of [true,false]){const bad=copy(artifact);if(missing)delete bad.policies[name][block][field];else bad.policies[name][block][field]=null;expect(()=>parsePlatformArtifact(bad)).toThrow();}
  }
 });
 it('distinguishes required numeric zero from null and out-of-range policy values',()=>{
  for(const [base,block,name,limits] of [[sev,'sev_snp','sev-policy',{minimum_build:255,minimum_guest_svn:0xffffffff,vmpl:3,minimum_launch_mitigation_vector:0xffffffffffffffffn,minimum_current_mitigation_vector:0xffffffffffffffffn}],[tdx,'tdx','tdx-policy',{minimum_tcb_evaluation_data_number:Number.MAX_SAFE_INTEGER}]] as const){
   for(const [field,max] of Object.entries(limits))for(const value of [0,max,null,-1,1.5,typeof max==='bigint'?max+1n:max+1]){const artifact=copy(base.refs.platformArtifact);artifact.policies[name][block][field]=value;if(value===0||value===max)expect(()=>parsePlatformArtifact(artifact)).not.toThrow();else expect(()=>parsePlatformArtifact(artifact)).toThrow();}
  }
  for(const field of ['bl_spl','tee_spl','snp_spl','ucode_spl','fmc_spl'])for(const value of [0,255,null,-1,256,1.5]){const artifact=copy(sev.refs.platformArtifact);artifact.policies['sev-policy'].sev_snp.minimum_tcb[field]=value;if(value===0||value===255)expect(()=>parsePlatformArtifact(artifact)).not.toThrow();else expect(()=>parsePlatformArtifact(artifact)).toThrow();}
 });
 it('rejects array MRSEAM alternatives and machine metadata values',()=>{
  const artifact=copy(tdx.refs.platformArtifact),id=Object.keys(artifact.machines)[0],policy=artifact.machines[id];
  artifact.policies['tdx-policy'].tdx.mr_seam=[artifact.policies['tdx-policy'].tdx.mr_seam];expect(()=>parsePlatformArtifact(artifact)).toThrow();
  for(const value of [{policy,host:'untrusted.invalid'},null,1,[policy]]){const bad=copy(tdx.refs.platformArtifact);bad.machines[id]=value;expect(()=>parsePlatformArtifact(bad)).toThrow();}
 });

});

it.each([3, 4])('rejects signed nonzero mitigation bytes reserved in SNP report v%s', async version => {
  for (const offset of [0x1f8, 0x200, 0x207]) {
    const f = await signed(sev, (r, v) => { v.setUint32(0, version, true); r[offset] = 1; });
    await expect(authenticate(f)).rejects.toMatchObject({ layer: 'quote', cause: { message: 'nonzero reserved SEV report bytes at 1f8' } });
  }
});
it('matches canonical uppercase PCS module IDs for hexadecimal module versions', async () => {
  const quote = await signed(tdx, r => { r[49] = 0x0a; });
  const f = await pcs(quote, 'tcbInfo', info => { info.tdxModuleIdentities[0].id = 'TDX_0A'; });
  await expect(authenticate(f)).resolves.toBeDefined();
});
