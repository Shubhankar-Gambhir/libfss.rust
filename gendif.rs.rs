//use std::io;
use std::process::exit;
use std::ptr;
use cty;
//use rand::Rng;
//use multiarray::*;
use std::convert::TryInto;

//use std::cmp::Ordering;
#[repr(C)]

pub struct Fss<'a>{
	aes_keys: &'a AES_KEY, 
	//AES KEY type will require some other header.
	pub numBits: u32,
	//prime: mpz_t,
	// Will get appropriate type for mpz_class
	pub numParties: u32,
	pub numKeys: u32
}

pub struct CWLt {
    pub cs:[[cty::c_uchar;16];2],
    pub ct:[cty::c_uchar;2],
    pub cv:[u64;2],
}

pub struct ServerKeyLt<'a> {
    pub s:[[cty::c_uchar;16];2],
    pub t:[cty::c_uchar;2],
    pub v:[u64;2],
    pub  cw:[ Vec<CWLt>;2],//used only CWLt instead of *CWLT EERRRROORR
}


//Assumes integers are 64 bits
 #[inline]
fn getBit( n:cty::uint64_t,  pos:cty::uint64_t)->usize {
    return ((n & ( 1 << (64-pos))) >> (64-pos) as usize).try_into().unwrap();
}
fn prf<'a>(out : [u8;64], key: [u8;16]  , in_size : u64,  aes_keys: &AES_KEY,  numKeys: u32) -> &'a AES_KEY {
	println!("Came here too!");
	let dummyKey = AES_KEY {
		rd_key: [0;60],
		rounds: 2
	};
	return &dummyKey;
}
fn byteArr2Int64( arr:[u8;8])->u64
{
    
    let a7:u64=arr[7].into();
    let a6:u64=arr[6].into();
    let a5:u64=arr[5].into();
    let a4:u64=arr[4].into();
    let a3:u64=arr[3].into();
    let a2:u64=arr[2].into();
    let a1:u64=arr[1].into();
    let a0:u64=arr[0].into();

    let i:u64 =  (a7  << 56) | (a6 << 48)   | (a5  << 40)  |
                (a4 << 32) | (a3  << 24) |
                (a2 << 16)| ( a1 << 8)  |  (a0) ;
    return i;
}



//2 party less than FSS
fn generateTreeLt(f:&Fss,  k0:&ServerKeyLt,  k1:&ServerKeyLt,  a_i:u64,  b_i:u64){
	let n:u32=f.numBits;
	// Set up num_bits and allocate memory
	 k0.cw[0]=Vec::<CWLt>::with_capacity(n-1);//mutable
	k1.cw[1]=Vec::<CWLt>::with_capacity(n-1);
	k0.cw[0]=Vec::<CWLt>::with_capacity(n-1);
	k1.cw[1]=Vec::<CWLt>::with_capacity(n-1);

	// Figure out first relevant bit
    	// n is the number of least significant bits to compare
	let a:usize=getBit(a_i,(64-n+1) as u64);
	let na:usize=a^1;
    //let a:u8=a as u8;   //experimenting
    //let na:u8=na as u8; //experimenting
	//create arrays size (AES_key_size^2 + 2)
	let mut s0:[u8;32];
	let mut s1:[u8;32];
	let aStart:usize=(16*a).into();
	let naStart:usize=(16*na).into();
	
	//Set initial Seeds for prf
	if !RAND_bytes(&(s0[aStart]) as (& u8),16){
		println!("Random bytes failed");
		exit(1);
	}
	if !RAND_bytes(&(s1[aStart]) as (& u8),16){
		println!("Random bytes failed");
		exit(1);
	}	
	if !RAND_bytes(&(s0[naStart]) as (& u8),16){
		println!("Random bytes failed");
		exit(1);
	}
	s1[naStart..(naStart+16)].copy_from_slice(&s0[naStart..(naStart+16)]);
	//ptr::copy(s1+nastart,s0+nastart,16);
	
	let t0:[u8;2];
	let t1:[u8;2];
	let temp:[u8;2];
	
	if !RAND_bytes( temp, 2) {
        println!("Random bytes failed\n");
        exit(1);
    	}


	// Figure out initial ts
   	// Make sure t0a and t1a are different
    	t0[a] = temp[0] % 2;
    	t1[a] = (t0[a] + 1) % 2;
	// Make sure t0na = t1na
    	t0[na] = temp[1] % 2;
    	t1[na] = t0[na];

    	// Set initial v's
	let temp_v:[u8;8];
	if !RAND_bytes(temp_v, 8) {
        println!("Random bytes failed.\n");
        exit(1);
    	}
	k0.v[a]=byteArr2Int64(temp_v);
	k1.v[a]=k0.v[a];
	
	if !RAND_bytes(temp_v, 8) {
        println!("Random bytes failed.\n");
        exit(1);
        }
	k0.v[na] = byteArr2Int64(temp_v);
	k1.v[na] = k0.v[na] - b_i*(a as u64);
	k0.s[0][0..16].copy_from_slice(&s0[0..16]);
	//ptr::copy(k0.s[0] as &u8,s1 as &mut u8,16);
    k0.s[1][0..16].copy_from_slice(&s0[16..32]);
    //ptr::copy(k0.s[1]as &u8,(s0+16) as (&mut u8),16);
    k1.s[0][0..16].copy_from_slice(&s1[0..16]);
    // ptr::copy(k1.s[0] as &u8,s1 as &mut u8,16);
    k1.s[1][0..16].copy_from_slice(&s1[16..32]);
    //ptr::copy(k1.s[1] as &u8,(s1+16) as (&mut u8),16);
	k0.t[0] = t0[0];
    	k0.t[1] = t0[1];
    	k1.t[0] = t1[0];
    	k1.t[1] = t1[1];
	
	// Pick right keys to put into cipher
        let mut key0:[u8;16];
        let mut key1:[u8;16];
        key0[0..16].copy_from_slice(&s0[aStart..(aStart+16)]);
        // ptr::copy(key0, (s0 as (&mut u8) + aStart), 16);
        key1[0..16].copy_from_slice(&s1[aStart..(aStart+16)]); 
        //ptr::copy(key1, (s1 as (&u8) + aStart) , 16);
	
	let mut tbit0:usize=t0[a].into();
	let mut tbit1:usize=t1[a].into();	

	let mut cs0:[u8;32];
	let mut cs1:[u8;32];
	let mut ct0:[u8;2];
	let mut ct1:[u8;2];
	let mut out0:[u8;64];
	let mut out1:[u8;64];
	
	let mut v0:[u64;2];
	let mut v1:[u64;2];
	let mut cv:[[u64;2];2];
	let mut v:u64;
    for i in 0..(n-1){
	    f.aes_keys = prf(out0, key0, 64, f.aes_keys, f.numKeys);
        f.aes_keys = prf(out1, key1, 64, f.aes_keys, f.numKeys);
	    s0[0..32].copy_from_slice(&out0[0..32]);
	    //ptr::copy(s0 as &u8,out0 as &mut u8,32);
        s0[0..32].copy_from_slice(&out0[0..32]);
        //ptr::copy(s1 as &u8,out1 as &mut u8,32);
	    t0[0]=out0[32]%2;
	    t0[1]=out0[33]%2;
	    t1[0]=out1[32]%2;
        t1[1]=out1[33]%2;
    
	    v0[0] = byteArr2Int64(out0[40..48].try_into().expect("slice with incorrect length"));
        v0[1] = byteArr2Int64( out0 [48..56].try_into().expect("slice with incorrect length"));
        v1[0] = byteArr2Int64( out1 [40..48].try_into().expect("slice with incorrect length"));
        v1[1] = byteArr2Int64( out1 [48..56].try_into().expect("slice with incorrect length"));

    	//printf("out0: %d %d\n", out0[32], out0[33]);

        // Reset a and na bits
	    a = getBit(a_i,(64-n+i+2).into());
        na = a ^ 1;
	 // Redefine aStart and naStart based on new a's
        aStart = 16 * a;
        naStart = 16 * na;

        // Create cs and ct for next bit
	    if !RAND_bytes( (cs0 + aStart) as u8, 16) {
            println!("Random bytes failed.\n");
            exit(1);
        }
        if !RAND_bytes((cs1 + aStart as u8), 16) {
            println!("Random bytes failed.\n");
            exit(1);
        }
        if !RAND_bytes( (cs0 + naStart) as u8, 16) {
            println!("Random bytes failed.\n");
            exit(1);
        }
	
	    for j in 0..16{
	        cs1[naStart+j] = s0[naStart+j] ^ s1[naStart+j] ^ cs0[naStart+j];
	    }

	    if !RAND_bytes(temp, 2) {
            println!("Random bytes failed.\n");
            exit(1);
        }

	    ct0[a] = temp[0] % 2;
        ct1[a] = ct0[a] ^ t0[a] ^ t1[a] ^ 1;

        ct0[na] = temp[1] % 2;
        ct1[na] = ct0[na] ^ t0[na] ^ t1[na];

        if !RAND_bytes(temp_v, 8) {
            println!("Random bytes failed.\n");
            exit(1);
        }

        cv[tbit0][a] = byteArr2Int64(temp_v);
        v = (cv[tbit0 ][a] + v0[a]);


        v = (v - v1[a]);
        cv[tbit1][a] = v;
        if !RAND_bytes(temp_v, 8) {
            println!("Random bytes failed.\n");
            exit(1);
        }
	
	cv[tbit0][na] = byteArr2Int64(temp_v);
        v = (cv[tbit0][na] + v0[na]);

        v = (v - v1[na]);
        cv[tbit1][na] = (v - b_i*a.into());


    // Copy appropriate values into key
    let mut cwlt00:CWLt;
    let mut cwlt01:CWLt;
    let mut cwlt10:CWLt;
    let mut cwlt11:CWLt;
        cwlt00.cs[0][0..16].copy_from_slice(cs0[0..16]);
        //memcpy(, cs0, 16);
        cwlt00.cs[1][0..16].copy_from_slice(cs0[16..32]);
        //memcpy(k0->cw[0][i].cs[1], (unsigned char*) (cs0 + 16), 16);
        cwlt00.ct[0] = ct0[0];
        cwlt00.ct[1] = ct0[1];
        cwlt01.cs[0][0..16].copy_from_slice(cs1[0..16]);
        cwlt01.cs[1][0..16].copy_from_slice(cs0[16..32]);
        //ptr::copy(k0.cw[1][i].cs[0], cs1, 16);
        //ptr::copy(k0.cw[1][i].cs[1], ( (cs1 + 16) as (&u8)), 16);
        cwlt01.ct[0] = ct1[0];
        cwlt01.ct[1] = ct1[1];

        cwlt00.cv[0] = cv[0][0];
        cwlt00.cv[1] = cv[0][1];
        cwlt01.cv[0] = cv[1][0];
        cwlt01.cv[1] = cv[1][1];
        cwlt10.cs[0][0..16].copy_from_slice(cs0[0..16]);
        //ptr::copy(k1.cw[0][i].cs[0], cs0, 16);
        cwlt10.cs[1][0..16].copy_from_slice(cs0[16..32]);
        //ptr::copy(k1.cw[0][i].cs[1], ( (cs0 + 16) as(&u8)), 16);
        cwlt10.ct[0] = ct0[0];
        cwlt10.ct[1] = ct0[1];
        
        cwlt11.cs[0][0..16].copy_from_slice(cs1[0..16]);
        cwlt11.cs[1][0..16].copy_from_slice(cs0[16..32]);
        //memcpy(k1.cw[1][i].cs[0], cs1, 16);
        //memcpy(k1.cw[1][i].cs[1], ( (cs1 + 16) as (&u8)), 16);
        cwlt11.ct[0] = ct1[0];
        cwlt11.ct[1] = ct1[1];

        cwlt10.cv[0] = cv[0][0];
        cwlt10.cv[1] = cv[0][1];
        cwlt11.cv[0] = cv[1][0];
        cwlt11.cv[1] = cv[1][1];

        let  cs:[u8;32];
        let ct:[u8;2];

        if (tbit0 == 1) {
            cs = cs1;
            ct = ct1;
        } else {
            cs = cs0;
            ct = ct0;
        }
        let mut j:usize=17;
        j=0;
	    while j<16 { 
            key0[j] = s0[aStart+j] ^ cs[aStart+j];j+=1;
        }
        tbit0 = t0[a] ^ ct[a];

        //printf("After XOR: ");
        //printByteArray(key0, 16);
        if (tbit1 == 1) {
            cs = cs1;
            ct = ct1;
        } else {
            cs = cs0;
            ct = ct0;

        }
            j=0;
	while j<16 {
            key1[j] = s1[aStart+j] ^ cs[aStart+j];j+=1;
        }
        tbit1 = t1[a] ^ ct[a];

        k0.cw[0].push(cwlt00);
        k0.cw[1].push(cwlt01);
        k1.cw[0].push(cwlt10);
        k1.cw[1].push(cwlt11);
        




    }
}



//fn main() {
  //  println!("Hello, world!");
//}
