/*!
ترميز/فك ترميز RLE بسيط صفر تبعية للنصوص الثنائية الصغيرة والمتوسطة.
Simple zero‑deps RLE encoder/decoder for small/medium binary/text payloads.
*/

pub fn rle_compress(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        let mut run = 1usize;
        while i + run < input.len() && input[i + run] == b && run < 255 {
            run += 1;
        }
        out.push(b);
        out.push(run as u8);
        i += run;
    }
    out
}

pub fn rle_decompress(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() % 2 != 0 {
        return Err("invalid rle length");
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        let cnt = input[i + 1] as usize;
        if cnt == 0 {
            return Err("invalid rle count");
        }
        out.extend(std::iter::repeat_n(b, cnt));
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg(mut x: u64, len: usize) -> Vec<u8> {
        x |= 1; // ensure odd
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.push((x & 0xFF) as u8);
        }
        out
    }

    #[test]
    fn roundtrip_small_patterns() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"aaaaaa",
            b"abababab",
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ];
        for &c in cases {
            let enc = rle_compress(c);
            let dec = rle_decompress(&enc).expect("decompress");
            assert_eq!(dec, c);
        }
    }

    #[test]
    fn roundtrip_random_lcg() {
        for seed in [1u64, 12345, 0xDEADBEEFCAFEBABE, 987654321] {
            for &len in &[0usize, 1, 2, 3, 7, 16, 31, 64, 255, 512, 1024] {
                let data = lcg(seed, len);
                let enc = rle_compress(&data);
                let dec = rle_decompress(&enc).expect("decompress");
                assert_eq!(dec, data, "seed={seed} len={len}");
            }
        }
    }

    #[test]
    fn invalid_streams_rejected() {
        assert!(rle_decompress(&[1]).is_err()); // odd length
        assert!(rle_decompress(&[0xAA, 0x00]).is_err()); // zero count invalid
    }
}
