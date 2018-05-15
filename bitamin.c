#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define N_HASHES_FOR_CLOCK (1000)
#define SECONDS_PER_BLOCK (10)

#ifdef RAND_BLOCK
#	include <fcntl.h>
#	include <unistd.h>
#	define BLOCK_INIT { 0, 0, { 0 } }
#else
#	define BLOCK_INIT { 0, { 0 } }
#endif

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
#	define IS_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#else
#	error "__BYTE_ORDER__ or __ORDER_BIG_ENDIAN__ not defined"
#endif

#ifndef __has_builtin
#	define __has_builtin(a) (0)
#endif

typedef struct {
#ifdef RAND_BLOCK
	uint64_t rand;
#endif
	uint64_t nonce;
	uint64_t prev[8];
} block_h;

/*
Instruction Format: OPCODE (4 bit) | SRC1 (4 bit) | SRC2 (4 bit) | DEST (4 bit) | (SHIFT (6 bit) || IMM (16 bit))
*/

typedef struct {
	uint8_t opcode : 4, src1 : 4, src2 : 4, dest : 4;
	union {
		uint8_t shift : 6;
		uint16_t imm;
	} shift_or_imm;
} insn_h;

typedef struct {
	insn_h insns[16];
	uint64_t regs[16];
} vm_h;

static const uint64_t keccakf_rndc[24] = {
	0x1ull, 0x8082ull, 0x800000000000808aull,
	0x8000000080008000ull, 0x808bull, 0x80000001ull,
	0x8000000080008081ull, 0x8000000000008009ull, 0x8aull,
	0x88ull, 0x80008009ull, 0x8000000aull,
	0x8000808bull, 0x800000000000008bull, 0x8000000000008089ull,
	0x8000000000008003ull, 0x8000000000008002ull, 0x8000000000000080ull,
	0x800aull, 0x800000008000000aull, 0x8000000080008081ull,
	0x8000000000008080ull, 0x80000001ull, 0x8000000080008008ull
};

static const int8_t blake2b_sigma[12][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
	{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
	{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
	{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
	{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
	{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
	{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
	{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
	{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

enum {
	INSN_MOV,
	INSN_MOV_IMM,
	INSN_ADD,
	INSN_ADD_IMM,
	INSN_SUB,
	INSN_SUB_IMM,
	INSN_AND,
	INSN_AND_IMM,
	INSN_XOR,
	INSN_XOR_IMM,
	INSN_OR,
	INSN_OR_IMM,
	INSN_NOT,
	INSN_SHIFTL,
	INSN_SHIFTR,
	INSN_ROTL
};

static inline __attribute__((always_inline)) uint64_t
rotl64(const uint64_t a, const unsigned b) {
	return (a << b) | (a >> (-b & 63u));
}

static inline __attribute__((always_inline)) uint64_t
rotr64(const uint64_t a, const unsigned b) {
	return (a >> b) | (a << (-b & 63u));
}

static inline __attribute__((always_inline)) void
memcpy_bswap64(uint64_t *out, const uint64_t *in, const size_t in_len) {
#if IS_BIG_ENDIAN
	size_t i;
	for(i = 0; i < in_len >> 3u; ++i) {
#	if (defined(__GNUC__) && defined(__GNUC_MINOR__) && (__GNUC__ * 100 + __GNUC_MINOR__ >= 403)) || __has_builtin(__builtin_bswap64)
		out[i] = __builtin_bswap64(in[i]);
#	else
		out[i] = ((in[i] & 0xffull) << 56) | ((in[i] & 0xff00ull) << 40) | ((in[i] & 0xff0000ull) << 24) | ((in[i] & 0xff000000ull) << 8) | ((in[i] & 0xff00000000ull) >> 8) | ((in[i] & 0xff0000000000ull) >> 24) | ((in[i] & 0xff000000000000ull) >> 40) | ((in[i] & 0xff00000000000000ull) >> 56);
#	endif
	}
#else
	memcpy(out, in, in_len);
#endif
}

#define G(r, i, a, b, c, d)                    \
do {                                           \
	(a) += (b) + m[blake2b_sigma[r][2*(i)]];   \
	(d) = rotr64((d) ^ (a), 32);               \
	(c) += (d);                                \
	(b) = rotr64((b) ^ (c), 24);               \
	(a) += (b) + m[blake2b_sigma[r][2*(i)+1]]; \
	(d) = rotr64((d) ^ (a), 16);               \
	(c) += (d);                                \
	(b) = rotr64((b) ^ (c), 63);               \
} while(0)

#define ROUND(r)                       \
do {                                   \
	G(r, 0, v[0], v[4], v[8], v[12]);  \
	G(r, 1, v[1], v[5], v[9], v[13]);  \
	G(r, 2, v[2], v[6], v[10], v[14]); \
	G(r, 3, v[3], v[7], v[11], v[15]); \
	G(r, 4, v[0], v[5], v[10], v[15]); \
	G(r, 5, v[1], v[6], v[11], v[12]); \
	G(r, 6, v[2], v[7], v[8], v[13]);  \
	G(r, 7, v[3], v[4], v[9], v[14]);  \
} while(0)

#define V_0 (0x6a09e667f3bcc908ull)
#define V_1 (0xbb67ae8584caa73bull)
#define V_2 (0x3c6ef372fe94f82bull)
#define V_3 (0xa54ff53a5f1d36f1ull)
#define V_4 (0x510e527fade682d1ull)
#define V_5 (0x9b05688c2b3e6c1full)
#define V_6 (0x1f83d9abfb41bd6bull)
#define V_7 (0x5be0cd19137e2179ull)
#define H_0 (V_0 ^ 0x1010040ull)

#define TARGET_MAX (UINT64_MAX)

static inline bool
blake2b_hash(const void *in, const size_t len, uint64_t *out, const uint64_t target) {
	uint64_t v[16] = { H_0, V_1, V_2, V_3, V_4, V_5, V_6, V_7, V_0, V_1, V_2, V_3, V_4,
		V_5, V_6, V_7 }, m[16] = { 0 }, tmp;
	
	assert(len <= sizeof(m));
	memcpy_bswap64(m, in, len);
	v[12] ^= len;

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);
	
	tmp = (H_0 ^ v[0] ^ v[8]);
	if(tmp > target) {
		return false;
	}
	
	out[0] = tmp;
	out[1] = (V_1 ^ v[1] ^ v[9]);
	out[2] = (V_2 ^ v[2] ^ v[10]);
	out[3] = (V_3 ^ v[3] ^ v[11]);
	out[4] = (V_4 ^ v[4] ^ v[12]);
	out[5] = (V_5 ^ v[5] ^ v[13]);
	out[6] = (V_6 ^ v[6] ^ v[14]);
	out[7] = (V_7 ^ v[7] ^ v[15]);
	return true;
}

#define REPEAT5(a, b, c) \
do {                     \
	a(b);                \
	a((b) + (c));        \
	a((b) + 2 * (c));    \
	a((b) + 3 * (c));    \
	a((b) + 4 * (c));    \
} while(0)

#define THETA_0(i) t[i] = st[i] ^ st[(i) + 5] ^ st[(i) + 10] ^ st[(i) + 15] ^ st[(i) + 20]

#define THETA_1(i)                                      \
do {                                                    \
	u = t[((i) + 4) % 5] ^ rotl64(t[((i) + 1) % 5], 1); \
	st[i] ^= u;                                         \
	st[(i) + 5] ^= u;                                   \
	st[(i) + 10] ^= u;                                  \
	st[(i) + 15] ^= u;                                  \
	st[(i) + 20] ^= u;                                  \
} while(0)

#define CHI(i)                                   \
do {                                             \
	t[0] = st[i];                                \
	t[1] = st[(i) + 1];                          \
	st[i] ^= (~t[1]) & st[(i) + 2];              \
	st[(i) + 1] ^= (~st[(i) + 2]) & st[(i) + 3]; \
	st[(i) + 2] ^= (~st[(i) + 3]) & st[(i) + 4]; \
	st[(i) + 3] ^= (~st[(i) + 4]) & t[0];        \
	st[(i) + 4] ^= (~t[0]) & t[1];               \
} while(0)

static inline void
keccak_hash(const void *in, const size_t in_len, void *out, const size_t out_len) {
	int_fast8_t r;
	uint64_t st[25] = { 0 }, t[5], u;
	
	assert(in_len <= sizeof(st) && in_len <= out_len);
	memcpy_bswap64(st, in, in_len);
	
	st[24] ^= 0x8000000000000000ull;
	st[in_len >> 3u] ^= 0x6ull;

	for (r = 0; r < 24; ++r) {
		REPEAT5(THETA_0, 0, 1);
		REPEAT5(THETA_1, 0, 1);
		
		u = st[1];
		st[ 1] = rotl64(st[ 6], 44);
		st[ 6] = rotl64(st[ 9], 20);
		st[ 9] = rotl64(st[22], 61);
		st[22] = rotl64(st[14], 39);
		st[14] = rotl64(st[20], 18);
		st[20] = rotl64(st[ 2], 62);
		st[ 2] = rotl64(st[12], 43);
		st[12] = rotl64(st[13], 25);
		st[13] = rotl64(st[19],  8);
		st[19] = rotl64(st[23], 56);
		st[23] = rotl64(st[15], 41);
		st[15] = rotl64(st[ 4], 27);
		st[ 4] = rotl64(st[24], 14);
		st[24] = rotl64(st[21],  2);
		st[21] = rotl64(st[ 8], 55);
		st[ 8] = rotl64(st[16], 45);
		st[16] = rotl64(st[ 5], 36);
		st[ 5] = rotl64(st[ 3], 28);
		st[ 3] = rotl64(st[18], 21);
		st[18] = rotl64(st[17], 15);
		st[17] = rotl64(st[11], 10);
		st[11] = rotl64(st[ 7],  6);
		st[ 7] = rotl64(st[10],  3);
		st[10] = rotl64(u,       1);
		
		REPEAT5(CHI, 0, 5);
		
		st[0] ^= keccakf_rndc[r];
	}
	
	memcpy_bswap64(out, st, out_len);
}

static inline void
execute_vm(vm_h vm) {
	int_fast8_t i;
	for(i = 0; i < 16; ++i) {
		const insn_h insn = vm.insns[i];
		uint8_t opcode = insn.opcode, src1 = insn.src1, src2 = insn.src2, dest = insn.dest, shift = insn.shift_or_imm.shift;
		uint16_t imm = insn.shift_or_imm.imm;
		switch(opcode) {
			case INSN_MOV:
				vm.regs[dest] = vm.regs[src1];
				break;
			case INSN_MOV_IMM:
				vm.regs[dest] = imm;
				break;
			case INSN_ADD:
				vm.regs[dest] = vm.regs[src1] + vm.regs[src2];
				break;
			case INSN_ADD_IMM:
				vm.regs[dest] = vm.regs[src1] + imm;
				break;
			case INSN_SUB:
				vm.regs[dest] = vm.regs[src1] - vm.regs[src2];
				break;
			case INSN_SUB_IMM:
				vm.regs[dest] = vm.regs[src1] - imm;
				break;
			case INSN_AND:
				vm.regs[dest] = vm.regs[src1] & vm.regs[src2];
				break;
			case INSN_AND_IMM:
				vm.regs[dest] = vm.regs[src1] & imm;
				break;
			case INSN_XOR:
				vm.regs[dest] = vm.regs[src1] ^ vm.regs[src2];
				break;
			case INSN_XOR_IMM:
				vm.regs[dest] = vm.regs[src1] ^ imm;
				break;
			case INSN_OR:
				vm.regs[dest] = vm.regs[src1] | vm.regs[src2];
				break;
			case INSN_OR_IMM:
				vm.regs[dest] = vm.regs[src1] | imm;
				break;
			case INSN_NOT:
				vm.regs[dest] = ~vm.regs[src1];
				break;
			case INSN_SHIFTL:
				vm.regs[dest] = vm.regs[src1] >> shift;
				break;
			case INSN_SHIFTR:
				vm.regs[dest] = vm.regs[src1] << shift;
				break;
			case INSN_ROTL:
				vm.regs[dest] = rotl64(vm.regs[src1], shift);
				break;
			default:
				assert(false);
				break;
		}
	}
}

static inline __attribute__((always_inline)) uint64_t
get_target_hash(void) {
	size_t i;
	block_h block = BLOCK_INIT;
	vm_h vm;
	clock_t start;
	
	start = clock();
	for(i = 0; i < N_HASHES_FOR_CLOCK; ++i) {
		keccak_hash(&block, sizeof(block), &vm, sizeof(vm));
		execute_vm(vm);
		blake2b_hash(vm.regs, sizeof(vm.regs), block.prev, TARGET_MAX);
	}
	return TARGET_MAX / (uint64_t)((N_HASHES_FOR_CLOCK / ((double)(clock() - start) / CLOCKS_PER_SEC)) * SECONDS_PER_BLOCK);
}

static inline __attribute__((always_inline)) void
print_hash(const uint64_t *hash) {
	int_fast8_t i;
	for(i = 0; i < 8; ++i) {
		printf("%016" PRIx64, hash[i]);
	}
	putchar('\n');
}

int
main(void)
{
	vm_h vm;
	clock_t start, end;
	block_h block = BLOCK_INIT;
	uint_fast64_t b_cnt;
	uint64_t target = get_target_hash();
	
#ifdef RAND_BLOCK
	int fd = open("/dev/urandom", O_RDONLY);
	assert(fd != -1);
	read(fd, &(block.rand), sizeof(block.rand));
	close(fd);
	printf("Rand: 0x%" PRIx64 "\n", block.rand);
#endif
	
	printf("Target: 0x%016" PRIx64 "\n", target);
	for(b_cnt = 0; b_cnt < UINT_FAST64_MAX; ++b_cnt) {
		start = clock();
		for(block.nonce = 0; block.nonce < UINT64_MAX; ++block.nonce) {
			keccak_hash(&block, sizeof(block), &vm, sizeof(vm));
			execute_vm(vm);
			if(blake2b_hash(vm.regs, sizeof(vm.regs), block.prev, target)) {
				break;
			}
		}
		end = clock();
		assert(block.nonce < UINT64_MAX);
		printf("Block: %" PRIuFAST64 ", Nonce: 0x%" PRIx64 ", Time Taken: %f seconds, Hash: 0x", b_cnt, block.nonce, (double)(end - start) / CLOCKS_PER_SEC);
		print_hash(block.prev);
	}
}
