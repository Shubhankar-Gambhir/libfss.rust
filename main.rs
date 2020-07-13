use std::ptr;
use std::convert::TryInto;
#[macro_use]
extern crate arrayref;

// taking AES LONG; don't know how to handle ifdef
struct AES_KEY{
	rd_key: [u64;60],
	rounds: i32
}
 struct Fss<'a>{
	aes_keys: &'a AES_KEY, 
	//AES KEY type will require some other header.
	numBits: u32,
	//prime: mpz_t,
	numParties: u32,
	numKeys: u32
}
const M: usize = 2;
const N: usize = 16;

struct CWLt {
    cs : [[u8; 16]; 2],
    ct: [u8; 2],
    cv: [u64; 2]
}

struct ServerKeyLt {
    s : [[u8; 16]; 2],
    t: [u8; 2],
    v: [u64; 2],
    cw: [ Vec<CWLt>; 2],
}
// Figure out how to reurn & AES_KEY later. not used even
fn prf<'a>(out : [u8; 64], key: [u8; 16], in_size : u64,  aes_keys: &'a AES_KEY,  numKeys: u32) -> AES_KEY {
	println!("Came here too!");
	let dummyKey = AES_KEY {
		rd_key: [0;60],
		rounds: 2
	};
	return dummyKey;
	//return &dummyKey.to_owned();
}
fn byteArr2Int64(arr: &[u8; 8]) -> u64 {
	let i:u64  = ((arr[7] as u64 ) << 56 )  | ((arr[6] as u64 ) << 48 )  | ((arr[5] as u64 ) << 40 )  | 
	((arr[4] as u64 ) << 32 )  | ((arr[3] as u64 ) << 24 )  | 
	((arr[2] as u64 ) << 16 )  | ((arr[1] as u64 ) << 8 )  | ((arr[0] as u64 ) ) ;
	return i;
}

fn getBit(n: u64, pos: u64) -> i32{
	return ((n & (1<< (64-pos))) >> (64 - pos)) as i32;
}
fn evaluateLt(f : &Fss, k : &ServerKeyLt, x: u64) -> u64 {
	println!("Function called");

	let n: u32 = f.numBits;
	let mut xi: i32 = getBit(x, (64 - (n as u64) + 1));

	let mut s: [u8; 16] = [0;16];

	unsafe{
		ptr::copy(&k.s[xi as usize][0], &mut s[0], 16);
	}
	let mut t: u8 = k.t[xi as usize];
	let mut v: u64 = k.v[xi as usize];

	let mut sArray: [u8; 32] = [0;32];
	let mut temp: [u8; 2] = [0;2];
	let out: [u8; 64] = [0;64];
	let mut temp_v: u64;

	for (i,_ij) in (1..(n)).enumerate() {
		if i != (n as usize) {
			xi = getBit(x, (64 - n + (i as u32) + 1) as u64);
		} else {
			xi = 0;
		}
		prf(out, s, 64, f.aes_keys, f.numKeys);

		unsafe {
			ptr::copy(&out[0], &mut sArray[0], 32);
		}
		temp[0] = out[32] % 2;
		temp[1] = out[33] % 2;
		let index = &out[40+8*(xi as usize)..48+8*(xi as usize)];
		let y = array_ref!(index, 0, 8).clone();
		temp_v = byteArr2Int64(&y);

		let xStart: i32 = 16 * xi;
		unsafe{
			ptr::copy((&(sArray[xStart as usize]) as &u8), &mut s[0], 16);
		}
		for (j, _jk) in (0..16).enumerate() {
			s[j] = s[j] ^ (k.cw[t as usize])[(i-1) as usize].cs[xi as usize][j]; // k.cw was a 1d array no?
		}
		v = v + temp_v;
		v = (v + k.cw[t as usize][i-1].cv[xi as usize]);
		t = temp[xi as usize] ^ k.cw[t as usize][i-1].ct[xi as usize];
	}
	return v;
}
fn main() {
    println!("---------------- Evaluator Starts -------------");
    let dummyKey = AES_KEY {
		rd_key: [0;60],
		rounds: 2
	};
    let dummyFss = Fss {
    	aes_keys: &dummyKey,
    	numBits: 16,
    	numParties: 2,
    	numKeys: 2
    };
    let dummyCWLt = CWLt {
    	cs : [[0u8; N]; M],
    	ct: [0u8; M],
    	cv: [0u64; M]
    };
    let dummyCWLt1 = CWLt {
    	cs : [[0u8; N]; M],
    	ct: [0u8; M],
    	cv: [0u64; M]
    };
    let mut dummyVec  = Vec::<CWLt>::new();
    dummyVec.push(dummyCWLt);
    let mut dummyVec1  = Vec::<CWLt>::new();
    dummyVec1.push(dummyCWLt1);
    let dummyServerKeyLt = ServerKeyLt {
    	s : [[0u8; N]; M],
    	t: [0u8; M],
    	v: [0u64; M],
    	cw: [dummyVec, dummyVec1],
    };
    evaluateLt(&dummyFss, &dummyServerKeyLt, 1);
}
