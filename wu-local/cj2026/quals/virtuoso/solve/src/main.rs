use anyhow::{anyhow, Result};
use std::ops::Neg;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use ark_bn254::{Bn254, Fr};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Ticket {
    pub proof: String,
    pub vk_bytes: Option<[u8; 32]>,
    pub flip_index: Option<usize>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    Redeem(Ticket),
    Balance,
    BuyFlag,
    BuyTicket,
    ProvingKey,
    VerifyingKey,
    Digest,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Hello(String),
    Ticket(Ticket),
    ProvingKey(String),
    VerifyingKey(String),
    GoodTicket,
    BadTicket,
    LolTooPoor,
    NotAllowed,
    Balance(i64),
    Flag(String),
    Digest(String),
}

fn read_one_line(reader: &mut BufReader<TcpStream>) -> Result<String> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Err(anyhow!("connection closed"));
    }
    Ok(line)
}

fn send_req(stream: &mut TcpStream, reader: &mut BufReader<TcpStream>, req: &Request) -> Result<Response> {
    let line = serde_json::to_string(req)? + "\n";
    stream.write_all(line.as_bytes())?;
    stream.flush()?;
    let resp_line = read_one_line(reader)?;
    Ok(serde_json::from_str(&resp_line)?)
}

fn get_balance(s: &mut TcpStream, r: &mut BufReader<TcpStream>) -> Result<i64> {
    match send_req(s, r, &Request::Balance)? {
        Response::Balance(b) => Ok(b),
        other => Err(anyhow!("unexpected balance resp: {:?}", other)),
    }
}

fn proof_to_hex(proof: &Proof<Bn254>) -> Result<String> {
    let mut bs = vec![];
    proof.serialize(&mut bs)?;
    Ok(hex::encode(bs))
}

fn parse_trunc_digest_hex(s: &str) -> Result<[u8; 30]> {
    let b = hex::decode(s)?;
    if b.len() != 30 {
        return Err(anyhow!("digest len {}, expected 30", b.len()));
    }
    let mut out = [0u8; 30];
    out.copy_from_slice(&b);
    Ok(out)
}

fn g1_to_32bytes(p: &<Bn254 as ark_ec::PairingEngine>::G1Affine) -> Result<[u8; 32]> {
    let mut bs = vec![];
    p.serialize(&mut bs)?;
    if bs.len() != 32 {
        return Err(anyhow!("G1 serialize len {}, expected 32", bs.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bs);
    Ok(out)
}

fn try_redeem(
    s: &mut TcpStream,
    r: &mut BufReader<TcpStream>,
    proof_hex: &str,
    patch: [u8; 32],
    idx: usize,
) -> Result<bool> {
    let t = Ticket {
        proof: proof_hex.to_string(),
        vk_bytes: Some(patch),
        flip_index: Some(idx),
    };
    let resp = send_req(s, r, &Request::Redeem(t))?;
    Ok(matches!(resp, Response::GoodTicket))
}

fn main() -> Result<()> {
    let host = "127.0.0.1:8001";
    let mut s = TcpStream::connect(host)?;
    let mut r = BufReader::new(s.try_clone()?);

    let hello_line = read_one_line(&mut r)?;
    let hello: Response = serde_json::from_str(&hello_line)?;
    eprintln!("[*] hello = {:?}", hello);

    let vk_hex = match send_req(&mut s, &mut r, &Request::VerifyingKey)? {
        Response::VerifyingKey(h) => h,
        other => return Err(anyhow!("unexpected vk resp: {:?}", other)),
    };
    let vk_ser = hex::decode(&vk_hex)?;
    eprintln!("[*] vk bytes = {}", vk_ser.len());
    let vk: VerifyingKey<Bn254> = VerifyingKey::deserialize(&vk_ser[..])?;

    let dg_hex = match send_req(&mut s, &mut r, &Request::Digest)? {
        Response::Digest(h) => h,
        other => return Err(anyhow!("unexpected digest resp: {:?}", other)),
    };
    let dg30 = parse_trunc_digest_hex(&dg_hex)?;
    eprintln!("[*] digest(30B) = {}", dg_hex);

    if vk_ser.len() != 296 {
        return Err(anyhow!("unexpected vk length {}, expected 296", vk_ser.len()));
    }
    let gamma_abc1_offset = 264usize; // fixed for this layout
    eprintln!("[*] using gamma_abc[1] offset = {}", gamma_abc1_offset);

    let alpha = vk.alpha_g1;
    let beta = vk.beta_g2;
    let delta = vk.delta_g2;

    let b_proj = beta.into_projective() + delta.into_projective();
    let b_aff = b_proj.into_affine();

    let base_proof = Proof::<Bn254> { a: alpha, b: b_aff, c: alpha };
    let base_hex = proof_to_hex(&base_proof)?;
    eprintln!("[*] base proof hex len = {}", base_hex.len());

    let g0 = vk.gamma_abc_g1[0];
    let mut found_patch: Option<([u8; 32], Fr)> = None;

    let mut full = [0u8; 32];
    full[..30].copy_from_slice(&dg30);

    let mut inf_bytes = [0u8; 32];
    inf_bytes[31] = 64;

    eprintln!("[*] bruting missing 16 bits…");
    'outer: for hi in 0u32..=0xFFFF {
        full[30] = (hi & 0xFF) as u8;
        full[31] = ((hi >> 8) & 0xFF) as u8;

        let digest = match Fr::deserialize(&full[..]) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if digest.is_zero() {
            continue;
        }
        let inv = match digest.inverse() {
            Some(v) => v,
            None => continue,
        };

        let neg_g0 = g0.into_projective().neg().into_affine();
        let g1_proj = neg_g0.mul(inv.into_repr());
        let g1_aff = g1_proj.into_affine();

        let patch = g1_to_32bytes(&g1_aff)?;
        if patch == inf_bytes {
            continue;
        }

        if try_redeem(&mut s, &mut r, &base_hex, patch, gamma_abc1_offset)? {
            eprintln!("[+] FOUND correct digest hi={:04x}", hi);
            found_patch = Some((patch, digest));
            break 'outer;
        }

        if hi % 2048 == 0 {
            eprintln!("[*] tried hi={:04x}", hi);
        }
    }

    let (patch, digest) = found_patch.ok_or_else(|| anyhow!("failed to find digest/patch"))?;
    eprintln!("[*] patch ready. balance={}", get_balance(&mut s, &mut r)?);

    let mut x: u64 = 2;
    let mut ok = 0;

    while get_balance(&mut s, &mut r)? < 20 {
        let k = Fr::from(x);
        if k.is_zero() { x += 1; continue; }
        let kinv = match k.inverse() { Some(v) => v, None => { x += 1; continue; } };

        let a2 = alpha.mul(k.into_repr()).into_affine();
        let b2 = b_aff.mul(kinv.into_repr()).into_affine();
        let p2 = Proof::<Bn254> { a: a2, b: b2, c: alpha };
        let p2_hex = proof_to_hex(&p2)?;

        if try_redeem(&mut s, &mut r, &p2_hex, patch, gamma_abc1_offset)? {
            ok += 1;
            if ok % 5 == 0 {
                eprintln!("[*] redeemed {ok}, balance={}", get_balance(&mut s, &mut r)?);
            }
        }

        x += 1;
        if x > 200000 {
            return Err(anyhow!("farming too long;"));
        }
    }

    eprintln!("[*] final balance={}", get_balance(&mut s, &mut r)?);
    let flag = send_req(&mut s, &mut r, &Request::BuyFlag)?;
    println!("{:?}", flag);

    let mut dbg = vec![];
    digest.serialize(&mut dbg)?;
    eprintln!("[*] recovered digest full32 = {}", hex::encode(dbg));

    Ok(())
}
