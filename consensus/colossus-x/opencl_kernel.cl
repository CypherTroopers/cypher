#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable
#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable

__constant ulong COLOSSUSX_FNV_OFFSET = 14695981039346656037UL;
__constant ulong COLOSSUSX_FNV_PRIME = 1099511628211UL;

__constant ulong KECCAKF_RNDC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL,
};

__constant uint KECCAKF_ROTC[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44,
};

__constant uint KECCAKF_PILN[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
};

__constant uint BLAKE3_IV[8] = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U,
};

__constant uchar BLAKE3_MSG_PERMUTATION[16] = {
    2, 6, 3, 10, 7, 0, 4, 13,
    1, 11, 12, 5, 9, 14, 15, 8,
};

#define BLAKE3_FLAG_CHUNK_START 1U
#define BLAKE3_FLAG_CHUNK_END   2U
#define BLAKE3_FLAG_ROOT        8U

typedef struct {
    uchar Pow256[32];
    uchar Full512[64];
} opencl_hash_result;

inline ulong rotl64(ulong x, uint n) {
    return (x << n) | (x >> (64U - n));
}

inline uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32U - n));
}

inline ulong load64_le_private(__private const uchar *src) {
    ulong out = 0;
    for (uint i = 0; i < 8; ++i) out |= ((ulong)src[i]) << (8U * i);
    return out;
}

inline uint load32_le_private(__private const uchar *src) {
    return ((uint)src[0]) | ((uint)src[1] << 8) | ((uint)src[2] << 16) | ((uint)src[3] << 24);
}

inline void store64_le_private(__private uchar *dst, ulong value) {
    for (uint i = 0; i < 8; ++i) dst[i] = (uchar)(value >> (8U * i));
}

inline void store32_le_private(__private uchar *dst, uint value) {
    dst[0] = (uchar)(value);
    dst[1] = (uchar)(value >> 8);
    dst[2] = (uchar)(value >> 16);
    dst[3] = (uchar)(value >> 24);
}

inline ulong colossusx_fnv1a40(__private const uchar *data) {
    ulong h = COLOSSUSX_FNV_OFFSET;
    for (uint i = 0; i < 40; ++i) {
        h ^= (ulong)data[i];
        h *= COLOSSUSX_FNV_PRIME;
    }
    return h;
}

inline void keccakf(__private ulong st[25]) {
    __private ulong bc[5];
    for (uint round = 0; round < 24; ++round) {
        for (uint i = 0; i < 5; ++i) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (uint i = 0; i < 5; ++i) {
            ulong t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (uint j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        ulong t = st[1];
        for (uint i = 0; i < 24; ++i) {
            uint j = KECCAKF_PILN[i];
            bc[0] = st[j];
            st[j] = rotl64(t, KECCAKF_ROTC[i]);
            t = bc[0];
        }
        for (uint j = 0; j < 25; j += 5) {
            for (uint i = 0; i < 5; ++i) bc[i] = st[j + i];
            for (uint i = 0; i < 5; ++i) st[j + i] = bc[i] ^ ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
        }
        st[0] ^= KECCAKF_RNDC[round];
    }
}

inline void sha3_512(__private const uchar *msg, uint msg_len, __private uchar out[64]) {
    __private ulong st[25];
    __private uchar block[72];
    for (uint i = 0; i < 25; ++i) st[i] = 0;
    uint full = msg_len / 72U;
    uint rem = msg_len % 72U;
    for (uint blk = 0; blk < full; ++blk) {
        __private const uchar *chunk = msg + blk * 72U;
        for (uint i = 0; i < 9; ++i) st[i] ^= load64_le_private(chunk + i * 8U);
        keccakf(st);
    }
    for (uint i = 0; i < 72; ++i) block[i] = 0;
    for (uint i = 0; i < rem; ++i) block[i] = msg[full * 72U + i];
    block[rem] = 0x06;
    block[71] |= 0x80;
    for (uint i = 0; i < 9; ++i) st[i] ^= load64_le_private(block + i * 8U);
    keccakf(st);
    for (uint i = 0; i < 8; ++i) store64_le_private(out + i * 8U, st[i]);
}

inline void blake3_g(__private uint st[16], uint a, uint b, uint c, uint d, uint mx, uint my) {
    st[a] = st[a] + st[b] + mx;
    st[d] = rotr32(st[d] ^ st[a], 16);
    st[c] = st[c] + st[d];
    st[b] = rotr32(st[b] ^ st[c], 12);
    st[a] = st[a] + st[b] + my;
    st[d] = rotr32(st[d] ^ st[a], 8);
    st[c] = st[c] + st[d];
    st[b] = rotr32(st[b] ^ st[c], 7);
}

inline void blake3_round_fn(__private uint st[16], __private const uint msg[16]) {
    blake3_g(st, 0, 4, 8, 12, msg[0], msg[1]);
    blake3_g(st, 1, 5, 9, 13, msg[2], msg[3]);
    blake3_g(st, 2, 6, 10, 14, msg[4], msg[5]);
    blake3_g(st, 3, 7, 11, 15, msg[6], msg[7]);
    blake3_g(st, 0, 5, 10, 15, msg[8], msg[9]);
    blake3_g(st, 1, 6, 11, 12, msg[10], msg[11]);
    blake3_g(st, 2, 7, 8, 13, msg[12], msg[13]);
    blake3_g(st, 3, 4, 9, 14, msg[14], msg[15]);
}

inline void blake3_permute(__private uint msg[16]) {
    __private uint tmp[16];
    for (uint i = 0; i < 16; ++i) tmp[i] = msg[BLAKE3_MSG_PERMUTATION[i]];
    for (uint i = 0; i < 16; ++i) msg[i] = tmp[i];
}

inline void blake3_compress_xof(
    __private const uint cv[8],
    __private const uint block_words[16],
    uint counter_low,
    uint counter_high,
    uint block_len,
    uint flags,
    __private uint out_words[16]
) {
    __private uint st[16];
    __private uint msg[16];
    for (uint i = 0; i < 8; ++i) st[i] = cv[i];
    st[8] = BLAKE3_IV[0]; st[9] = BLAKE3_IV[1]; st[10] = BLAKE3_IV[2]; st[11] = BLAKE3_IV[3];
    st[12] = counter_low; st[13] = counter_high; st[14] = block_len; st[15] = flags;
    for (uint i = 0; i < 16; ++i) msg[i] = block_words[i];
    for (uint round = 0; round < 7; ++round) {
        blake3_round_fn(st, msg);
        if (round != 6) blake3_permute(msg);
    }
    for (uint i = 0; i < 8; ++i) {
        out_words[i] = st[i] ^ st[i + 8];
        out_words[i + 8] = st[i + 8] ^ cv[i];
    }
}

inline void blake3_hash_64(__private const uchar msg[64], __private uchar out[32]) {
    __private uint block_words[16];
    __private uint xof[16];
    for (uint i = 0; i < 16; ++i) block_words[i] = load32_le_private(msg + i * 4U);
    blake3_compress_xof(
        BLAKE3_IV,
        block_words,
        0U,
        0U,
        64U,
        BLAKE3_FLAG_CHUNK_START | BLAKE3_FLAG_CHUNK_END | BLAKE3_FLAG_ROOT,
        xof
    );
    for (uint i = 0; i < 8; ++i) store32_le_private(out + i * 4U, xof[i]);
}

__kernel void colossusx_hash(
    __global const uchar *dag,
    __global const uchar *header,
    const uint header_len,
    const ulong start_nonce,
    const uint node_size,
    const ulong node_count,
    const ulong reads_per_hash,
    __global opencl_hash_result *out
) {
    size_t gid = get_global_id(0);
    ulong nonce = start_nonce + (ulong)gid;
    __private uchar seed_input[256];
    __private uchar seed512[64];
    __private uchar mix[32];
    __private uchar fnv_input[40];
    __private uchar node[64];
    __private uchar blake_input[64];
    __private uchar final_input[96];
    if (node_count == 0UL || node_size < 64U) {
        for (uint i = 0; i < 32; ++i) out[gid].Pow256[i] = 0;
        for (uint i = 0; i < 64; ++i) out[gid].Full512[i] = 0;
        return;
    }
    if (header_len + 8U > 256U) return;
    for (uint i = 0; i < header_len; ++i) seed_input[i] = header[i];
    for (uint i = 0; i < 8; ++i) seed_input[header_len + i] = (uchar)(nonce >> (8U * i));
    sha3_512(seed_input, header_len + 8U, seed512);
    for (uint i = 0; i < 32; ++i) mix[i] = seed512[i];
    for (ulong r = 0; r < reads_per_hash; ++r) {
        for (uint i = 0; i < 32; ++i) fnv_input[i] = mix[i];
        for (uint i = 0; i < 8; ++i) fnv_input[32U + i] = (uchar)(r >> (8U * i));
        ulong node_idx = colossusx_fnv1a40(fnv_input) % node_count;
        __global const uchar *node_ptr = dag + node_idx * (ulong)node_size;
        for (uint i = 0; i < 64; ++i) node[i] = node_ptr[i];
        for (uint i = 0; i < 32; ++i) {
            blake_input[i] = mix[i] ^ node[i];
            blake_input[32U + i] = mix[i] ^ node[32U + i];
        }
        blake3_hash_64(blake_input, mix);
    }
    for (uint i = 0; i < 64; ++i) final_input[i] = seed512[i];
    for (uint i = 0; i < 32; ++i) final_input[64U + i] = mix[i];
    sha3_512(final_input, 96U, out[gid].Full512);
    for (uint i = 0; i < 32; ++i) out[gid].Pow256[i] = out[gid].Full512[i];
}
