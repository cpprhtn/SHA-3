<?php

    class sha3
    {
        static $SHA3_OK = 0;
        static $SHA3_PARAMETER_ERROR = 1;
        static $SHA3_SHAKE_NONE = 0;
        static $SHA3_SHAKE_USE = 1;

        static $KECCAK_SPONGE_BIT = 1600;
        static $KECCAK_ROUND = 24;
        static $KECCAK_STATE_SIZE = 200;

        static $KECCAK_SHA3_224 = 224;
        static $KECCAK_SHA3_256 = 256;
        static $KECCAK_SHA3_384 = 384;
        static $KECCAK_SHA3_512 = 512;
        static $KECCAK_SHAKE128 = 128;
        static $KECCAK_SHAKE256 = 256;

        static $KECCAK_SHA3_SUFFIX = 0x06;
        static $KECCAK_SHAKE_SUFFIX = 0x1F;

        static $keccakRate = 0;
        static $keccakCapacity = 0;
        static $keccakSuffix = 0;

        static $keccak_state = array();
        static $end_offset;

        static $keccakf_rndc = array(
            array(0x00000001, 0x00000000), array(0x00008082, 0x00000000),
            array(0x0000808a, 0x80000000), array(0x80008000, 0x80000000),
            array(0x0000808b, 0x00000000), array(0x80000001, 0x00000000),
            array(0x80008081, 0x80000000), array(0x00008009, 0x80000000),
            array(0x0000008a, 0x00000000), array(0x00000088, 0x00000000),
            array(0x80008009, 0x00000000), array(0x8000000a, 0x00000000),
            array(0x8000808b, 0x00000000), array(0x0000008b, 0x80000000),
            array(0x00008089, 0x80000000), array(0x00008003, 0x80000000),
            array(0x00008002, 0x80000000), array(0x00000080, 0x80000000),
            array(0x0000800a, 0x00000000), array(0x8000000a, 0x80000000),
            array(0x80008081, 0x80000000), array(0x00008080, 0x80000000),
            array(0x80000001, 0x00000000), array(0x80008008, 0x80000000)
        );

        static $keccakf_rotc = array(
            1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
            27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
        );

        static $keccakf_piln = array(
            10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
            15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
        );

        static function ROL64($in, &$out, $offset) {
            $shift = 0;

            if ($offset == 0)
            {
                $out[1] = $in[1];
                $out[0] = $in[0];
            }
            else if ($offset < 32)
            {
                $shift = $offset;

                $out[1] = ((($in[1] << $shift) | ($in[0] >> (32 - $shift))) & 0xFFFFFFFF);
                $out[0] = ((($in[0] << $shift) | ($in[1] >> (32 - $shift))) & 0xFFFFFFFF);
            }
            else if ($offset < 64)
            {
                $shift = $offset - 32;

                $out[1] = ((($in[0] << $shift) | ($in[1] >> (32 - $shift))) & 0xFFFFFFFF);
                $out[0] = ((($in[1] << $shift) | ($in[0] >> (32 - $shift))) & 0xFFFFFFFF);
            }
            else
            {
                $out[1] = $in[1];
                $out[0] = $in[0];
            }
        }

        static function keccakf(&$state) {
            $t = array_pad(array(),2,0);
            $bc = array(
                array_pad(array(),2,0),
                array_pad(array(),2,0),
                array_pad(array(),2,0),
                array_pad(array(),2,0),
                array_pad(array(),2,0),
            );
            $s = array(
                array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0),
                array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0),
                array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0),
                array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0),
                array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0), array_pad(array(),2,0),
            );

            for ($i = 0; $i < 25; $i++)
            {
                $s[$i][0] = ((0xFF & $state[$i * 8 + 0]) |
                    ((0xFF & $state[$i * 8 + 1]) <<  8) |
                    ((0xFF & $state[$i * 8 + 2]) << 16) |
                    ((0xFF & $state[$i * 8 + 3]) << 24));
                $s[$i][1] = ((0xFF & $state[$i * 8 + 4]) |
                    ((0xFF & $state[$i * 8 + 5]) <<  8) |
                    ((0xFF & $state[$i * 8 + 6]) << 16) |
                    ((0xFF & $state[$i * 8 + 7]) << 24));
            }

            for ($round = 0; $round < sha3::$KECCAK_ROUND; $round++)
            {
                /* Theta */
                for ($i = 0; $i < 5; $i++)
                {
                    $bc[$i][0] = $s[$i][0] ^ $s[$i + 5][0] ^ $s[$i + 10][0] ^ $s[$i + 15][0] ^ $s[$i + 20][0];
                    $bc[$i][1] = $s[$i][1] ^ $s[$i + 5][1] ^ $s[$i + 10][1] ^ $s[$i + 15][1] ^ $s[$i + 20][1];
                }

                for ($i = 0; $i < 5; $i++)
                {
                    sha3::ROL64($bc[($i + 1) % 5], $t, 1);
                    
                    $t[0] ^= $bc[($i + 4) % 5][0];
                    $t[1] ^= $bc[($i + 4) % 5][1];

                    for ($j = 0; $j < 25; $j += 5)
                    {
                        $s[$j + $i][0] ^= $t[0];
                        $s[$j + $i][1] ^= $t[1];
                    }
                }

                /* Rho & Pi */
                $t[0] = $s[1][0];
                $t[1] = $s[1][1];

                for ($i = 0; $i < sha3::$KECCAK_ROUND; $i++)
                {
                    $j = sha3::$keccakf_piln[$i];

                    $bc[0][0] = $s[$j][0];
                    $bc[0][1] = $s[$j][1];

                    sha3::ROL64($t, $s[$j], sha3::$keccakf_rotc[$i]);

                    $t[0] = $bc[0][0];
                    $t[1] = $bc[0][1];
                }

                /* Chi */
                for ($j = 0; $j < 25; $j += 5)
                {
                    for ($i = 0; $i < 5; $i++)
                    {
                        $bc[$i][0] = $s[$j + $i][0];
                        $bc[$i][1] = $s[$j + $i][1];
                    }

                    for ($i = 0; $i < 5; $i++)
                    {
                        $s[$j + $i][0] ^= (0xFFFFFFFF - ($bc[($i + 1) % 5][0] & 0xFFFFFFFF)) & $bc[($i + 2) % 5][0];
                        $s[$j + $i][1] ^= (0xFFFFFFFF - ($bc[($i + 1) % 5][1] & 0xFFFFFFFF)) & $bc[($i + 2) % 5][1];
                    }
                }

                /* Iota */
                $s[0][0] ^= sha3::$keccakf_rndc[$round][0];
                $s[0][1] ^= sha3::$keccakf_rndc[$round][1];
            }

            for ($i = 0; $i < 25; $i++)
            {
                $state[$i * 8 + 0] = (($s[$i][0])       & 0x0FF);
                $state[$i * 8 + 1] = (($s[$i][0] >> 8)  & 0x0FF);
                $state[$i * 8 + 2] = (($s[$i][0] >> 16) & 0x0FF);
                $state[$i * 8 + 3] = (($s[$i][0] >> 24) & 0x0FF);
                $state[$i * 8 + 4] = (($s[$i][1])       & 0x0FF);
                $state[$i * 8 + 5] = (($s[$i][1] >> 8)  & 0x0FF);
                $state[$i * 8 + 6] = (($s[$i][1] >> 16) & 0x0FF);
                $state[$i * 8 + 7] = (($s[$i][1] >> 24) & 0x0FF);
            }
        }

        static function keccak_absorb($input, $inLen, $rate, $capacity) {
            $offset = 0;
            $iLen = $inLen;
            $rateInBytes = $rate / 8;
            $blockSize = 0;

            if (($rate + $capacity) != sha3::$KECCAK_SPONGE_BIT)
                return sha3::$SHA3_PARAMETER_ERROR;
        
            if ((($rate % 8) != 0) || ($rate < 1))
                return sha3::$SHA3_PARAMETER_ERROR;

            $offset = 0;
            while ($iLen > 0)
            {
                if ((sha3::$end_offset != 0) && (sha3::$end_offset < $rateInBytes))
                {
                    $blockSize = ((($iLen + sha3::$end_offset) < $rateInBytes) ? ($iLen + sha3::$end_offset) : $rateInBytes);

                    for ($i = sha3::$end_offset; $i < $blockSize; $i++)
                    sha3::$keccak_state[$i] ^= $input[$i - sha3::$end_offset];

                    $offset += $blockSize - sha3::$end_offset;
                    $iLen -= $blockSize - sha3::$end_offset;
                }
                else
                {
                    $blockSize = (($iLen < $rateInBytes) ? $iLen : $rateInBytes);

                    for ($i = 0; $i < $blockSize; $i++)
                    sha3::$keccak_state[$i] ^= $input[$i + $offset];

                    $offset += $blockSize;
                    $iLen -= $blockSize;
                }

                if ($blockSize == $rateInBytes)
                {
                    sha3::keccakf(sha3::$keccak_state);
                    $blockSize = 0;
                }

                sha3::$end_offset = $blockSize;
            }

            return sha3::$SHA3_OK;
        }

        static function keccak_squeeze(&$output, $outLen, $rate, $suffix) {
            $offset = 0;
            $oLen = $outLen;
            $rateInBytes = $rate / 8;
            $blockSize = sha3::$end_offset;

            sha3::$keccak_state[$blockSize] ^= $suffix;

            if ((($suffix & 0x80) != 0) && ($blockSize == ($rateInBytes - 1)))
                sha3::keccakf(sha3::$keccak_state);

            sha3::$keccak_state[$rateInBytes - 1] ^= 0x80;

            sha3::keccakf(sha3::$keccak_state);

            $offset = 0;
            while ($oLen > 0)
            {
                $blockSize = (($oLen < $rateInBytes) ? $oLen : $rateInBytes);
                for ($i = 0; $i < $blockSize; $i++)
                    $output[$i + $offset] = sha3::$keccak_state[$i];

                $offset += $blockSize;
                $oLen -= $blockSize;

                if ($oLen > 0)
                    sha3::keccakf(sha3::$keccak_state);
            }

            return sha3::$SHA3_OK;
        }

        static function sha3_init($bitSize, $useSHAKE) {
            sha3::$keccakCapacity = $bitSize * 2;
            sha3::$keccakRate = sha3::$KECCAK_SPONGE_BIT - sha3::$keccakCapacity;

            if ($useSHAKE)
                sha3::$keccakSuffix = sha3::$KECCAK_SHAKE_SUFFIX;
            else
                sha3::$keccakSuffix = sha3::$KECCAK_SHA3_SUFFIX;

            for ($i = 0; $i < sha3::$KECCAK_STATE_SIZE; $i++)
                sha3::$keccak_state[$i] = 0;

            sha3::$end_offset = 0;
        }

        static function sha3_224_init() {
            sha3::sha3_init(sha3::$KECCAK_SHA3_224, sha3::$SHA3_SHAKE_NONE);
        }

        static function sha3_256_init() {
            sha3::sha3_init(sha3::$KECCAK_SHA3_256, sha3::$SHA3_SHAKE_NONE);
        }

        static function sha3_384_init() {
            sha3::sha3_init(sha3::$KECCAK_SHA3_384, sha3::$SHA3_SHAKE_NONE);
        }

        static function sha3_512_init() {
            sha3::sha3_init(sha3::$KECCAK_SHA3_512, sha3::$SHA3_SHAKE_NONE);
        }

        static function shake128_init() {
            sha3::sha3_init(sha3::$KECCAK_SHAKE128, sha3::$SHA3_SHAKE_USE);
        }

        static function shake256_init() {
            sha3::sha3_init(sha3::$KECCAK_SHAKE256, sha3::$SHA3_SHAKE_USE);
        }

        static function sha3_update($input, $inLen) {
            return sha3::keccak_absorb($input, $inLen, sha3::$keccakRate, sha3::$keccakCapacity);
        }

        static function sha3_final(&$output, $outLen) {
            $ret = sha3::keccak_squeeze($output, $outLen, sha3::$keccakRate, sha3::$keccakSuffix);

            sha3::$keccakRate = 0;
            sha3::$keccakCapacity = 0;
            sha3::$keccakSuffix = 0;

            for ($i = 0; $i < sha3::$KECCAK_STATE_SIZE; $i++)
                sha3::$keccak_state[$i] = 0;

            return $ret;
        }

        static function sha3_hash(&$output, $outLen, $input, $inLen, $bitSize, $useSHAKE) {
            $ret = 0;

            if ($useSHAKE == sha3::$SHA3_SHAKE_USE)
            {
                if (($bitSize != sha3::$KECCAK_SHAKE128) && ($bitSize != sha3::$KECCAK_SHAKE256))
                    return sha3::$SHA3_PARAMETER_ERROR;

                sha3::sha3_init($bitSize, sha3::$SHA3_SHAKE_USE);
            }
            else
            {
                if (($bitSize != sha3::$KECCAK_SHA3_224) && ($bitSize != sha3::$KECCAK_SHA3_256) &&
                    ($bitSize != sha3::$KECCAK_SHA3_384) && ($bitSize != sha3::$KECCAK_SHA3_512))
                    return sha3::$SHA3_PARAMETER_ERROR;

                if (($bitSize / 8) != $outLen)
                    return sha3::$SHA3_PARAMETER_ERROR;

                    sha3::sha3_init($bitSize, sha3::$SHA3_SHAKE_NONE);
            }

            sha3::sha3_update($input, $inLen);

            $ret = sha3::sha3_final($output, $outLen);

            return $ret;
        }
    }

?>