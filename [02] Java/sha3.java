public class sha3 {
    private static final int SHA3_OK = 0;
    private static final int SHA3_PARAMETER_ERROR = 1;
    private static final int SHA3_SHAKE_NONE = 0;
    private static final int SHA3_SHAKE_USE = 1;

    private static final int KECCAK_SPONGE_BIT = 1600;
    private static final int KECCAK_ROUND = 24;
    private static final int KECCAK_STATE_SIZE = 200;

    private static final int KECCAK_SHA3_224 = 224;
    private static final int KECCAK_SHA3_256 = 256;
    private static final int KECCAK_SHA3_384 = 384;
    private static final int KECCAK_SHA3_512 = 512;
    private static final int KECCAK_SHAKE128 = 128;
    private static final int KECCAK_SHAKE256 = 256;

    private static final int KECCAK_SHA3_SUFFIX = 0x06;
    private static final int KECCAK_SHAKE_SUFFIX = 0x1F;

    private static int keccakRate = 0;
    private static int keccakCapacity = 0;
    private static int keccakSuffix = 0;

    private static byte keccak_state[] = new byte[KECCAK_STATE_SIZE];
    private static int end_offset;

    private static final int keccakf_rndc[][] = {
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

    private static final int keccakf_rotc[] = {
        1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
        27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
    };

    private static final int keccakf_piln[] = {
        10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
        15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
    };

    private static void ROL64(int in[], int out[], int offset) {
        int mask = (1 << offset) - 1;
        int shift = 0;

        if (offset == 0)
        {
            out[1] = in[1];
            out[0] = in[0];
        }
        else if (offset < 32)
        {
            shift = offset;

            out[1] = (((in[1] << shift) & (~mask)) ^ ((in[0] >> (32 - shift)) & mask));
            out[0] = (((in[0] << shift) & (~mask)) ^ ((in[1] >> (32 - shift)) & mask));
        }
        else if (offset < 64)
        {
            shift = offset - 32;

            out[1] = (((in[0] << shift) & (~mask)) ^ ((in[1] >> (32 - shift)) & mask));
            out[0] = (((in[1] << shift) & (~mask)) ^ ((in[0] >> (32 - shift)) & mask));
        }
        else
        {
            out[1] = in[1];
            out[0] = in[0];
        }
    };

    private static final void keccakf(byte[] state) {
        int t[] = new int[2], bc[][] = new int[5][2], s[][] = new int[25][2];
        int i, j, round;

        for (i = 0; i < 25; i++)
        {
            s[i][0] = ((0x0FF & state[i * 8 + 0]) | ((0x0FF & state[i * 8 + 1]) << 8) | ((0x0FF & state[i * 8 + 2]) << 16) | ((0x0FF & state[i * 8 + 3]) << 24));
            s[i][1] = ((0x0FF & state[i * 8 + 4]) | ((0x0FF & state[i * 8 + 5]) << 8) | ((0x0FF & state[i * 8 + 6]) << 16) | ((0x0FF & state[i * 8 + 7]) << 24));
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
            state[i * 8 + 0] = (byte)((s[i][0])       & 0x0FF);
            state[i * 8 + 1] = (byte)((s[i][0] >> 8)  & 0x0FF);
            state[i * 8 + 2] = (byte)((s[i][0] >> 16) & 0x0FF);
            state[i * 8 + 3] = (byte)((s[i][0] >> 24) & 0x0FF);
            state[i * 8 + 4] = (byte)((s[i][1])       & 0x0FF);
            state[i * 8 + 5] = (byte)((s[i][1] >> 8)  & 0x0FF);
            state[i * 8 + 6] = (byte)((s[i][1] >> 16) & 0x0FF);
            state[i * 8 + 7] = (byte)((s[i][1] >> 24) & 0x0FF);
        }
    };

    private static final int keccak_absorb(byte[] input, int inLen, int rate, int capacity) {
        int offset = 0;
        int iLen = inLen;
        int rateInBytes = rate / 8;
        int blockSize = 0;
        int i = 0;

        if ((rate + capacity) != KECCAK_SPONGE_BIT)
            return SHA3_PARAMETER_ERROR;

        if (((rate % 8) != 0) || (rate < 1))
            return SHA3_PARAMETER_ERROR;

        offset = 0;
        while (iLen > 0)
        {
            if ((end_offset != 0) && (end_offset < rateInBytes))
            {
                blockSize = (((iLen + end_offset) < rateInBytes) ? (iLen + end_offset) : rateInBytes);

                for (i = end_offset; i < blockSize; i++)
                    keccak_state[i] ^= input[i - end_offset];

                offset += blockSize - end_offset;
                iLen -= blockSize - end_offset;
            }
            else
            {
                blockSize = ((iLen < rateInBytes) ? iLen : rateInBytes);

                for (i = 0; i < blockSize; i++)
                    keccak_state[i] ^= input[i + offset];

                offset += blockSize;
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
    };

    private static final int keccak_squeeze(byte[] output, int outLen, int rate, int suffix) {
        int offset = 0;
        int oLen = outLen;
        int rateInBytes = rate / 8;
        int blockSize = end_offset;
        int i = 0;

        keccak_state[blockSize] ^= suffix;

        if (((suffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
            keccakf(keccak_state);

        keccak_state[rateInBytes - 1] ^= 0x80;

        keccakf(keccak_state);

        offset = 0;
        while (oLen > 0)
        {
            blockSize = ((oLen < rateInBytes) ? oLen : rateInBytes);
            for (i = 0; i < blockSize; i++)
                output[i + offset] = keccak_state[i];

            offset += blockSize;
            oLen -= blockSize;

            if (oLen > 0)
                keccakf(keccak_state);
        }

        return SHA3_OK;
    };

    public final void sha3_init(int bitSize, int useSHAKE) {
        keccakCapacity = bitSize * 2;
        keccakRate = KECCAK_SPONGE_BIT - keccakCapacity;

        if (useSHAKE == SHA3_SHAKE_USE)
            keccakSuffix = KECCAK_SHAKE_SUFFIX;
        else
            keccakSuffix = KECCAK_SHA3_SUFFIX;

        for (int i = 0; i < KECCAK_STATE_SIZE; i++)
            keccak_state[i] = 0;

        end_offset = 0;
    };

    public final int sha3_update(byte[] input, int inLen) {
        return keccak_absorb(input, inLen, keccakRate, keccakCapacity);
    };

    public final int sha3_final(byte[] output, int outLen) {
        int ret = 0;

        ret = keccak_squeeze(output, outLen, keccakRate, keccakSuffix);

        keccakRate = 0;
        keccakCapacity = 0;
        keccakSuffix = 0;

        for (int i = 0; i < KECCAK_STATE_SIZE; i++)
            keccak_state[i] = 0;

        return ret;
    };

    public final int sha3_hash(byte[] output, int outLen, byte[] input, int inLen, int bitSize, int useSHAKE) {
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
    };
}