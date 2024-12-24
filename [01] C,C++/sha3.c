#include "sha3.h"

#define KECCAK_SPONGE_BIT		1600
#define KECCAK_ROUND			24
#define KECCAK_STATE_SIZE		200

#define KECCAK_SHA3_224			224
#define KECCAK_SHA3_256			256
#define KECCAK_SHA3_384			384
#define KECCAK_SHA3_512			512
#define KECCAK_SHAKE128			128
#define KECCAK_SHAKE256			256

#define KECCAK_SHA3_SUFFIX		0x06
#define KECCAK_SHAKE_SUFFIX		0x1F


typedef enum
{
	SHA3_OK = 0,
	SHA3_PARAMETER_ERROR = 1,
} SHA3_RETRUN;


typedef enum
{
	SHA3_SHAKE_NONE = 0,
	SHA3_SHAKE_USE = 1,
} SHA3_USE_SHAKE;



static unsigned int keccakRate = 0;
static unsigned int keccakCapacity = 0;
static unsigned int keccakSuffix = 0;

static uint8_t keccak_state[KECCAK_STATE_SIZE] = { 0x00, };
static int end_offset;

static const uint32_t keccakf_rndc[KECCAK_ROUND][2] =
{
	{0x00000001, 0x00000000}, {0x00008082, 0x00000000},
	{0x0000808a, 0x80000000}, {0x80008000, 0x80000000},
	{0x0000808b, 0x00000000}, {0x80000001, 0x00000000},
	{0x80008081, 0x80000000}, {0x00008009, 0x80000000},
	{0x0000008a, 0x00000000}, {0x00000088, 0x00000000},
	{0x80008009, 0x00000000}, {0x8000000a, 0x00000000},

	{0x8000808b, 0x00000000}, {0x0000008b, 0x80000000},
	{0x00008089, 0x80000000}, {0x00008003, 0x80000000},
	{0x00008002, 0x80000000}, {0x00000080, 0x80000000},
	{0x0000800a, 0x00000000}, {0x8000000a, 0x80000000},
	{0x80008081, 0x80000000}, {0x00008080, 0x80000000},
	{0x80000001, 0x00000000}, {0x80008008, 0x80000000}
};

static const unsigned keccakf_rotc[KECCAK_ROUND] =
{
	 1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[KECCAK_ROUND] =
{
	10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
	15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};


void ROL64(uint32_t* in, uint32_t* out, int offset)
{
	int shift = 0;

	if (offset == 0)
	{
		out[1] = in[1];
		out[0] = in[0];
	}
	else if (offset < 32)
	{
		shift = offset;

		out[1] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
		out[0] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
	}
	else if (offset < 64)
	{
		shift = offset - 32;

		out[1] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
		out[0] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
	}
	else
	{
		out[1] = in[1];
		out[0] = in[0];
	}
}
// 열거형 정의 (SHA3_RETURN 및 SHA3_USE_SHAKE):

// SHA3_RETURN: SHA-3 함수의 반환 상태를 나타내는 열거형입니다. SHA3_OK는 정상적인 상태를, SHA3_PARAMETER_ERROR는 매개변수 오류를 나타냅니다.
// SHA3_USE_SHAKE: SHA-3 함수에서 SHAKE 모드를 사용할지 여부를 나타내는 열거형입니다. SHA3_SHAKE_NONE은 사용하지 않음을, SHA3_SHAKE_USE는 사용함을 나타냅니다.
// 정적 변수 및 배열 정의:

// keccakRate, keccakCapacity, keccakSuffix: Keccak 상태에 대한 변수로서, 알고리즘에 사용되는 일부 상태 파라미터를 나타냅니다.
// keccak_state: Keccak 상태를 나타내는 배열로서, 해시 처리 중간 결과를 저장합니다.
// end_offset: 회전 연산 함수에서 사용되는 변수로, 회전 시프트의 최대 값입니다.
// keccakf_rndc, keccakf_rotc, keccakf_piln: Keccak 알고리즘에서 사용되는 상수 배열로서, 라운드에 따라 다른 값을 가집니다.
// Keccak 라운드 상수 정의:

// keccakf_rndc: Keccak 라운드 상수로서, 각 라운드에 대한 상수 값을 나타냅니다.
// keccakf_rotc, keccakf_piln: Keccak 라운드에 대한 회전 상수와 순열 상수를 나타냅니다.
// 회전 연산 함수 (ROL64):

// ROL64 함수는 64비트 값에 대한 왼쪽으로의 회전 연산을 수행합니다.
// 함수는 입력으로 받은 in 배열의 값을 주어진 offset만큼 왼쪽으로 회전시켜 out 배열에 저장합니다.


void keccakf(uint8_t* state)
{
	uint32_t t[2], bc[5][2], s[25][2] = { 0x00, };
	int i, j, round;

	for (i = 0; i < 25; i++)
	{
		s[i][0] = (uint32_t)(state[i * 8 + 0]) |
			(uint32_t)(state[i * 8 + 1] << 8) |
			(uint32_t)(state[i * 8 + 2] << 16) |
			(uint32_t)(state[i * 8 + 3] << 24);
		s[i][1] = (uint32_t)(state[i * 8 + 4]) |
			(uint32_t)(state[i * 8 + 5] << 8) |
			(uint32_t)(state[i * 8 + 6] << 16) |
			(uint32_t)(state[i * 8 + 7] << 24);
	}

	for (round = 0; round < KECCAK_ROUND; round++)
	{
		/* Theta */
		for (i = 0; i < 5; i++)
		{
			bc[i][0] = s[i][0] ^ s[i + 5][0] ^ s[i + 10][0] ^ s[i + 15][0] ^ s[i + 20][0];
			bc[i][1] = s[i][1] ^ s[i + 5][1] ^ s[i + 10][1] ^ s[i + 15][1] ^ s[i + 20][1];
		}

		for (i = 0; i < 5; i++)
		{
			ROL64(bc[(i + 1) % 5], t, 1);

			t[0] ^= bc[(i + 4) % 5][0];
			t[1] ^= bc[(i + 4) % 5][1];

			for (j = 0; j < 25; j += 5)
			{
				s[j + i][0] ^= t[0];
				s[j + i][1] ^= t[1];
			}
		}

		/* Rho & Pi */
		t[0] = s[1][0];
		t[1] = s[1][1];

		for (i = 0; i < KECCAK_ROUND; i++)
		{
			j = keccakf_piln[i];

			bc[0][0] = s[j][0];
			bc[0][1] = s[j][1];

			ROL64(t, s[j], keccakf_rotc[i]);

			t[0] = bc[0][0];
			t[1] = bc[0][1];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5)
		{
			for (i = 0; i < 5; i++)
			{
				bc[i][0] = s[j + i][0];
				bc[i][1] = s[j + i][1];
			}

			for (i = 0; i < 5; i++)
			{
				s[j + i][0] ^= (~bc[(i + 1) % 5][0]) & bc[(i + 2) % 5][0];
				s[j + i][1] ^= (~bc[(i + 1) % 5][1]) & bc[(i + 2) % 5][1];
			}
		}

		/* Iota */
		s[0][0] ^= keccakf_rndc[round][0];
		s[0][1] ^= keccakf_rndc[round][1];
	}

	for (i = 0; i < 25; i++)
	{
		state[i * 8 + 0] = (uint8_t)(s[i][0]);
		state[i * 8 + 1] = (uint8_t)(s[i][0] >> 8);
		state[i * 8 + 2] = (uint8_t)(s[i][0] >> 16);
		state[i * 8 + 3] = (uint8_t)(s[i][0] >> 24);
		state[i * 8 + 4] = (uint8_t)(s[i][1]);
		state[i * 8 + 5] = (uint8_t)(s[i][1] >> 8);
		state[i * 8 + 6] = (uint8_t)(s[i][1] >> 16);
		state[i * 8 + 7] = (uint8_t)(s[i][1] >> 24);
	}
}
// 코드는 Keccak 알고리즘의 한 라운드를 수행하는 keccakf 함수입니다. 주어진 상태 배열을 입력으로 받아 Theta, Rho & Pi, Chi, Iota 단계를 수행하여 상태를 갱신합니다.

// 여러 단계에 대한 간략한 설명을 제공하겠습니다.

// Theta 단계:

// 상태 배열에서 각 열에 대해 Theta 단계를 수행합니다.
// bc 배열은 각 열에 대한 XOR 연산 결과를 저장합니다.
// 해당 결과를 이용하여 열에 대한 회전 연산을 수행하고, 상태 배열을 갱신합니다.
// Rho & Pi 단계:

// 각 행에 대해 Rho & Pi 단계를 수행합니다.
// t 변수에 현재 위치의 값을 저장하고, Pi 단계를 통해 해당 위치를 변경합니다.
// Rho 단계에서는 회전 연산을 수행하여 상태 배열을 갱신합니다.
// Chi 단계:

// 각 열에 대해 Chi 단계를 수행합니다.
// 상태 배열의 각 열을 조합하여 XOR 연산을 수행하고, 결과를 상태 배열에 적용합니다.
// Iota 단계:

// 라운드 상수를 현재 상태 배열의 첫 번째 워드에 XOR 연산을 수행하여 Iota 단계를 수행합니다.
// 상태 배열 업데이트:

// 각 단계를 거치면서 계산된 상태 배열을 최종적으로 출력 형태로 변환하여 state 배열에 저장합니다.
// 코드는 Keccak 알고리즘의 한 라운드를 구현한 것이며, 전체 알고리즘은 여러 라운드의 반복을 통해 작동합니다. 더 많은 라운드를 거치면서 입력 데이터의 해시 값을 계산할 수 있습니다. 이 코드가 하나의 라운드에 해당하므로, 전체 알고리즘에서는 이를 반복 호출하여 사용합니다.

int keccak_absorb(uint8_t* input, int inLen, int rate, int capacity)
{
	uint8_t* buf = input;
	int iLen = inLen;
	int rateInBytes = rate / 8;
	int blockSize = 0;
	int i = 0;

	if ((rate + capacity) != KECCAK_SPONGE_BIT)
		return SHA3_PARAMETER_ERROR;

	if (((rate % 8) != 0) || (rate < 1))
		return SHA3_PARAMETER_ERROR;

	while (iLen > 0)
	{
		if ((end_offset != 0) && (end_offset < rateInBytes))
		{
			blockSize = (((iLen + end_offset) < rateInBytes) ? (iLen + end_offset) : rateInBytes);

			for (i = end_offset; i < blockSize; i++)
				keccak_state[i] ^= buf[i - end_offset];

			buf += blockSize - end_offset;
			iLen -= blockSize - end_offset;
		}
		else
		{
			blockSize = ((iLen < rateInBytes) ? iLen : rateInBytes);

			for (i = 0; i < blockSize; i++)
				keccak_state[i] ^= buf[i];

			buf += blockSize;
			iLen -= blockSize;
		}

		if (blockSize == rateInBytes)
		{
			keccakf(keccak_state);
			blockSize = 0;
		}

		end_offset = blockSize;
	}

	return SHA3_OK;
}
// 이 코드는 Keccak 알고리즘에서 메시지를 흡수하는 keccak_absorb 함수입니다. 함수는 입력으로 받은 데이터를 특정한 블록 크기로 나누어 상태에 흡수하며, 필요에 따라 내부 상태를 업데이트합니다.

// 여러 부분에 대한 간략한 설명을 제공하겠습니다:

// 매개변수 확인:

// 함수는 입력 매개변수로 데이터(input), 데이터 길이(inLen), 레이트(rate), 그리고 캐패시티(capacity)를 받습니다.
// rate와 capacity의 합이 Keccak 스펀지 함수의 비트 길이(KECCAK_SPONGE_BIT)와 같은지 확인합니다.
// rate는 8의 배수이어야 하며, 1보다 커야 합니다.
// 메시지 흡수 루프:

// 데이터가 남아 있는 동안, 내부 상태에 데이터를 흡수합니다.
// end_offset 변수는 이전 블록에서 남은 데이터의 크기를 나타냅니다.
// blockSize 변수는 현재 블록의 크기를 나타냅니다.
// 내부 상태 업데이트:

// 현재 블록이 완성되면 (blockSize == rateInBytes), 내부 상태를 keccakf 함수를 통해 업데이트합니다.
// end_offset 변수는 이전 블록에서 남은 데이터의 크기로 설정됩니다.
// 함수 반환:

// 함수는 수행 결과에 따라 SHA3_OK 또는 SHA3_PARAMETER_ERROR를 반환합니다.
// 이 함수는 Keccak 알고리즘에서 데이터를 흡수하는 역할을 수행합니다. 이 함수를 여러 번 호출하여 전체 메시지를 처리한 다음, 마지막으로 keccak_squeeze 등의 함수를 사용하여 최종 해시 값을 추출할 수 있습니다.

int keccak_squeeze(uint8_t* output, int outLen, int rate, int suffix)
{
	uint8_t* buf = output;
	int oLen = outLen;
	int rateInBytes = rate / 8;
	int blockSize = end_offset;
	int i = 0;

	keccak_state[blockSize] ^= suffix;

	if (((suffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
		keccakf(keccak_state);

	keccak_state[rateInBytes - 1] ^= 0x80;

	keccakf(keccak_state);

	while (oLen > 0)
	{
		blockSize = ((oLen < rateInBytes) ? oLen : rateInBytes);
		for (i = 0; i < blockSize; i++)
			buf[i] = keccak_state[i];
		buf += blockSize;
		oLen -= blockSize;

		if (oLen > 0)
			keccakf(keccak_state);
	}

	return SHA3_OK;
}
//  코드는 Keccak 알고리즘에서 해시 값을 추출하는 keccak_squeeze 함수입니다. 함수는 상태를 사용하여 출력 데이터를 생성하고, 필요에 따라 상태를 업데이트합니다.

// 여러 부분에 대한 간략한 설명을 제공하겠습니다:

// 매개변수 확인:

// 함수는 출력 데이터(output), 출력 데이터 길이(outLen), 레이트(rate), 그리고 서픽스(suffix)를 입력으로 받습니다.
// rate는 8의 배수이어야 합니다.
// 상태 업데이트:

// suffix를 이용하여 상태 배열의 마지막 블록에 데이터를 추가합니다.
// 만약 서픽스의 최상위 비트가 1이고 현재 블록이 마지막 블록이라면, keccakf 함수를 호출하여 상태를 업데이트합니다.
// 출력 생성 루프:

// 출력 데이터 길이(oLen)가 0보다 큰 동안, 상태 배열에서 데이터를 가져와 출력 데이터에 저장합니다.
// 블록 크기(blockSize)는 현재 블록의 크기를 나타냅니다.
// 출력 데이터의 포인터를 업데이트하고, 남은 출력 데이터의 길이를 갱신합니다.
// 함수 반환:

// 함수는 수행 결과에 따라 SHA3_OK를 반환합니다.
// 이 함수는 Keccak 알고리즘에서 상태를 사용하여 데이터를 추출하고, 필요에 따라 상태를 업데이트하여 최종 해시 값을 얻어내는 역할을 합니다. 이 함수를 호출하여 최종적인 해시 값을 얻을 수 있습니다.


void sha3_init(int bitSize, int useSHAKE)
{
	keccakCapacity = bitSize * 2;
	keccakRate = KECCAK_SPONGE_BIT - keccakCapacity;

	if (useSHAKE)
		keccakSuffix = KECCAK_SHAKE_SUFFIX;
	else
		keccakSuffix = KECCAK_SHA3_SUFFIX;

	memset(keccak_state, 0x00, KECCAK_STATE_SIZE);

	end_offset = 0;
}


int sha3_update(uint8_t* input, int inLen)
{
	return keccak_absorb(input, inLen, keccakRate, keccakCapacity);
}


int sha3_final(uint8_t* output, int outLen)
{
	int ret = 0;

	ret = keccak_squeeze(output, outLen, keccakRate, keccakSuffix);

	keccakRate = 0;
	keccakCapacity = 0;
	keccakSuffix = 0;

	memset(keccak_state, 0x00, KECCAK_STATE_SIZE);

	return ret;
}
// 이 코드는 SHA-3 해시 함수를 사용하기 위한 초기화(sha3_init), 업데이트(sha3_update), 및 최종화(sha3_final)를 수행하는 함수들을 제공합니다.

// sha3_init 함수:

// sha3_init 함수는 Keccak 알고리즘의 초기화를 수행합니다.
// bitSize를 기반으로 keccakCapacity와 keccakRate를 설정하고, 사용 여부에 따라 keccakSuffix를 설정합니다.
// memset 함수를 사용하여 상태 배열과 관련된 변수들을 초기화합니다.
// sha3_update 함수:

// sha3_update 함수는 입력 데이터를 흡수하여 Keccak 상태를 업데이트합니다.
// 내부적으로 keccak_absorb 함수를 호출하여 입력 데이터를 상태에 흡수합니다.
// 반환값은 keccak_absorb 함수의 반환값을 그대로 전달합니다.
// sha3_final 함수:

// sha3_final 함수는 최종 해시 값을 추출하는 단계를 수행합니다.
// 내부적으로 keccak_squeeze 함수를 호출하여 최종 해시 값을 얻습니다.
// 이후에는 관련된 변수들을 초기화하고, 상태 배열을 초기화합니다.
// 이 함수들을 순서대로 호출하여 원하는 데이터에 대한 SHA-3 해시 값을 얻을 수 있습니다. 코드의 구조는 SHA-3 알고리즘의 특징을 반영하고 있습니다.

int sha3_hash(uint8_t* output, int outLen, uint8_t* input, int inLen, int bitSize, int useSHAKE)
{
	int ret = 0;

	if (useSHAKE == SHA3_SHAKE_USE)
	{
		if ((bitSize != KECCAK_SHAKE128) && (bitSize != KECCAK_SHAKE256))
			return SHA3_PARAMETER_ERROR;

		sha3_init(bitSize, SHA3_SHAKE_USE);
	}
	else
	{
		if ((bitSize != KECCAK_SHA3_224) && (bitSize != KECCAK_SHA3_256) &&
			(bitSize != KECCAK_SHA3_384) && (bitSize != KECCAK_SHA3_512))
			return SHA3_PARAMETER_ERROR;

		if ((bitSize / 8) != outLen)
			return SHA3_PARAMETER_ERROR;

		sha3_init(bitSize, SHA3_SHAKE_NONE);
	}

	sha3_update(input, inLen);

	ret = sha3_final(output, outLen);

	return ret;
}
// sha3_hash 함수는 사용자에게 편리한 인터페이스를 제공하여 주어진 입력 데이터에 대한 SHA-3 해시 값을 계산하는 역할을 합니다. 여러 부분에 대한 설명을 제공하겠습니다:

// 매개변수 확인:

// 함수는 출력 데이터(output), 출력 데이터 길이(outLen), 입력 데이터(input), 입력 데이터 길이(inLen), 해시 비트 크기(bitSize), 그리고 SHAKE 모드 사용 여부(useSHAKE)를 입력으로 받습니다.
// SHA-3 모드 및 해시 비트 크기 확인:

// SHAKE 모드를 사용할 경우, bitSize는 KECCAK_SHAKE128 또는 KECCAK_SHAKE256이어야 합니다.
// SHA-3 모드를 사용할 경우, bitSize는 KECCAK_SHA3_224, KECCAK_SHA3_256, KECCAK_SHA3_384, 또는 KECCAK_SHA3_512이어야 합니다.
// SHA-3 모드에서는 출력 데이터 길이(outLen)와 해시 비트 크기(bitSize)가 일치해야 합니다.
// 초기화 및 업데이트:

// sha3_init 함수를 호출하여 Keccak 알고리즘을 초기화합니다.
// SHAKE 모드인 경우 SHAKE_SUFFIX를 사용하고, SHA-3 모드인 경우 적절한 SHA-3_SUFFIX를 사용합니다.
// sha3_update 함수를 호출하여 입력 데이터를 흡수합니다.
// 최종 해시 값 추출:

// sha3_final 함수를 호출하여 최종 해시 값을 추출합니다.
// 함수의 반환값은 sha3_final 함수의 반환값을 그대로 전달합니다.
// 이 함수를 호출함으로써 사용자는 간단하게 SHA-3 해시 값을 얻을 수 있습니다. 반환값에 따라 오류 여부를 확인할 수 있습니다.
void main()
{
	uint8_t out[512] = { 0, };
	uint8_t in[200] = { 0, };

	int out_length = 0;		//byte size
	int in_length = 200;	//byte size
	int hash_bit = 0;		//bit(224,256,384,512)
	int SHAKE = 0;			//0 or 1

	int i, result;

	memset(in, 0xA3, 200);	



	printf("* SHA-3 test *\n\n");
	printf("test message : A3(x200)\n\n");

	
	/* non-SHAKE test */
	SHAKE = 0;

	/* SHA3-224 test */
	out_length = 224 / 8;
	hash_bit = 224;
	result = sha3_hash(out, out_length, in, in_length, hash_bit, SHAKE);

	printf("SHA3-224 test\n");
	printf("hash : ");
	for (i = 0; i < out_length; i++)
		printf("%02X ", out[i]);
	printf("\n\n");

	/* SHA3-256 test */
	out_length = 256 / 8;
	hash_bit = 256;
	result = sha3_hash(out, out_length, in, in_length, hash_bit, SHAKE);

	printf("SHA3-256 test\n");
	printf("hash : ");
	for (i = 0; i < out_length; i++)
		printf("%02X ", out[i]);
	printf("\n\n");

	/* SHA3-384 test */
	out_length = 384 / 8;
	hash_bit = 384;
	result = sha3_hash(out, out_length, in, in_length, hash_bit, SHAKE);

	printf("SHA3-384 test\n");
	printf("hash : ");
	for (i = 0; i < out_length; i++)
		printf("%02X ", out[i]);
	printf("\n\n");

	/* SHA3-512 test */
	out_length = 512 / 8;
	hash_bit = 512;
	result = sha3_hash(out, out_length, in, in_length, hash_bit, SHAKE);

	printf("SHA3-512 test\n");
	printf("hash : ");
	for (i = 0; i < out_length; i++)
		printf("%02X ", out[i]);
	printf("\n\n");


	/* SHAKE test */
	SHAKE = 1;

	/* SHAKE128 test */
	out_length = 512;
	hash_bit = 128;
	result = sha3_hash(out, out_length, in, in_length, hash_bit, SHAKE);

	printf("SHAKE256 test\n");
	printf("output : 512bytes\n");
	printf("hash : ");
	for (i = 0; i < out_length; i++)
		printf("%02X ", out[i]);
	printf("\n\n");

	/* SHAKE256 test */
	out_length = 512;
	hash_bit = 256;
	result = sha3_hash(out, out_length, in, in_length, hash_bit, SHAKE);

	printf("SHAKE256 test\n");
	printf("output : 512bytes\n");
	printf("hash : ");
	for (i = 0; i < out_length; i++)
		printf("%02X ", out[i]);
	printf("\n\n");




}