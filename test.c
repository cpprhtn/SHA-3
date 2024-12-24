#include <stdint.h>
#include <string.h>

#define KECCAK_ROUNDS 24
#define STATE_SIZE 1600
#define CAPACITY 512
#define RATE (STATE_SIZE - CAPACITY)

typedef uint8_t byte;
typedef uint64_t uint64;

// SPONGE 구조를 나타내는 구조체 정의
typedef struct {
    uint64 state[STATE_SIZE / 64];
    size_t rate;
    size_t capacity;
} sponge;

// Rho 상수 배열 정의
const size_t RHO[25] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44, 19};

// Round Constants 배열 정의
const uint64 RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL
};

// Theta 함수 정의
void theta(uint64 *A) {
    uint64 C[5], D[5];
    for (size_t i = 0; i < 5; i++) {
        C[i] = A[i] ^ A[i + 5] ^ A[i + 10] ^ A[i + 15] ^ A[i + 20];
    }

    for (size_t i = 0; i < 5; i++) {
        D[i] = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
    }

    for (size_t i = 0; i < 5; i++) {
        for (size_t j = 0; j < 5; j++) {
            A[i + 5 * j] ^= D[i];
        }
    }
}

// Rho 함수 정의
void rho(uint64 *A) {
    for (size_t i = 0; i < 25; i++) {
        A[i] = ROTL64(A[i], RHO[i]);
    }
}

// Pi 함수 정의
void pi(uint64 *A) {
    uint64 B[25];
    for (size_t i = 0; i < 25; i++) {
        size_t x = i % 5;
        size_t y = (2 * i + 3 * (i / 5)) % 5;
        size_t index = 5 * x + y;
        B[index] = A[i];
    }
    memcpy(A, B, sizeof(B));
}


// Chi 함수 정의
void chi(uint64 *A) {
    uint64 B[25];
    for (size_t i = 0; i < 25; i++) {
        size_t x = i % 5;
        size_t y = (2 * i + 3 * (i / 5)) % 5;
        size_t index = 5 * x + y;
        B[index] = A[index] ^ ((~A[5 * x + ((y + 1) % 5)]) & A[5 * x + ((y + 2) % 5)]);
    }
    memcpy(A, B, sizeof(B));
}

// Iota 함수 정의
void iota(uint64 *A, size_t round) {
    A[0] ^= RC[round];
}

// Rho 및 Pi 함수 정의
// void rhoPi(uint64 *A) {
//     uint64 B[25];
//     for (size_t i = 0; i < 25; i++) {
//         size_t x = i % 5;
//         size_t y = (2 * i + 3 * (i / 5)) % 5;
//         size_t index = 5 * x + y;
//         B[index] = ROTL64(A[i], RHO[i]);
//     }
//     memcpy(A, B, sizeof(B));
// }

// Keccak-f 함수 정의
void keccakF(uint64 *A) {
    for (size_t round = 0; round < KECCAK_ROUNDS; round++) {
        theta(A);
        rho(A);
        pi(A);
        // rhoPi(A);
        chi(A);
        iota(A, round);
    }
}

// SPONGE에 데이터를 흡수하는 함수
void absorb(sponge *s, const byte *input, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        // 바이트 단위로 데이터를 XOR하여 흡수
        s->state[i / 8] ^= (uint64)input[i] << (8 * (i % 8));
        // 블록 크기에 도달하거나 입력이 끝났을 때 Keccak-f 순열 적용
        if ((i + 1) % s->rate == 0 || i == len - 1) {
            // Keccak-f 적용 부분 (간략화됨)
            keccakF(s->state);
        }
    }
}

// SPONGE로부터 데이터를 추출하는 함수
void squeeze(sponge *s, byte *output, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        // 블록 크기에 도달할 때마다 Keccak-f 순열 적용
        if (i % s->rate == 0) {
            // Keccak-f 적용 부분 (간략화됨)
            keccakF(s->state);
        }
        // 바이트 단위로 데이터를 추출
        output[i] = s->state[i / 8] >> (8 * (i % 8));
    }
}

int main() {
    // SPONGE 구조체 초기화
    sponge mySponge;
    memset(mySponge.state, 0, sizeof(mySponge.state));
    mySponge.rate = RATE;
    mySponge.capacity = CAPACITY;

    // 예시
    byte input[] = "Hello, cpprhtn!";
    size_t inputLen = sizeof(input) - 1; // 널 종료 문자를 제외한 길이

    // SPONGE에 데이터 흡수
    absorb(&mySponge, input, inputLen);

    // SPONGE로부터 데이터 추출
    byte output[32]; // SHA3-256 출력 크기
    squeeze(&mySponge, output, sizeof(output));

    // 'output'에는 입력의 SHA3-256 해시가 포함됨
    return 0;
}
