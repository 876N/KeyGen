pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut data = msg.to_vec();
    let bits: u64 = (data.len() as u64).wrapping_mul(8);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    for i in (0..8).rev() {
        data.push(((bits >> (i * 8)) & 0xFF) as u8);
    }

    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let mut chunk = 0;
    while chunk < data.len() {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = ((data[chunk + i * 4] as u32) << 24)
                | ((data[chunk + i * 4 + 1] as u32) << 16)
                | ((data[chunk + i * 4 + 2] as u32) << 8)
                | (data[chunk + i * 4 + 3] as u32);
        }
        for i in 16..80 {
            let t = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = (t << 1) | (t >> 31);
        }
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        for i in 0..80 {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5A827999)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else {
                (b ^ c ^ d, 0xCA62C1D6)
            };
            let tmp = ((a << 5) | (a >> 27))
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = tmp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        chunk += 64;
    }

    let mut out = [0u8; 20];
    for i in 0..4 {
        out[i] = ((h0 >> (24 - i * 8)) & 0xFF) as u8;
        out[4 + i] = ((h1 >> (24 - i * 8)) & 0xFF) as u8;
        out[8 + i] = ((h2 >> (24 - i * 8)) & 0xFF) as u8;
        out[12 + i] = ((h3 >> (24 - i * 8)) & 0xFF) as u8;
        out[16 + i] = ((h4 >> (24 - i * 8)) & 0xFF) as u8;
    }
    out
}

pub fn md5(input: &str) -> [u8; 16] {
    static S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    static K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut data: Vec<u8> = input.as_bytes().to_vec();
    let bits: u64 = (data.len() as u64).wrapping_mul(8);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    for i in 0..8 {
        data.push(((bits >> (i * 8)) & 0xFF) as u8);
    }
    let mut chunk = 0;
    while chunk < data.len() {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = (data[chunk + i * 4] as u32)
                | ((data[chunk + i * 4 + 1] as u32) << 8)
                | ((data[chunk + i * 4 + 2] as u32) << 16)
                | ((data[chunk + i * 4 + 3] as u32) << 24);
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | ((!b) & d), i)
            } else if i < 32 {
                ((d & b) | ((!d) & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * i) % 16)
            };
            let tmp = d;
            d = c;
            c = b;
            let x = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add((x << S[i]) | (x >> (32 - S[i])));
            a = tmp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        chunk += 64;
    }
    let mut out = [0u8; 16];
    for i in 0..4 {
        out[i * 4] = (state[i] & 0xFF) as u8;
        out[i * 4 + 1] = ((state[i] >> 8) & 0xFF) as u8;
        out[i * 4 + 2] = ((state[i] >> 16) & 0xFF) as u8;
        out[i * 4 + 3] = ((state[i] >> 24) & 0xFF) as u8;
    }
    out
}

pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k: Vec<u8> = if key.len() > 64 {
        sha1(key).to_vec()
    } else {
        key.to_vec()
    };
    while k.len() < 64 {
        k.push(0);
    }
    let mut opad = vec![0u8; 64];
    let mut ipad = vec![0u8; 64];
    for i in 0..64 {
        opad[i] = k[i] ^ 0x5c;
        ipad[i] = k[i] ^ 0x36;
    }
    let mut inner = ipad;
    inner.extend_from_slice(msg);
    let inner_hash = sha1(&inner);
    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}
