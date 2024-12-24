<%

const OFFSET_4 = 4294967296
const MAXINT_4 = 2147483647
const OFFSET_2 = 65536
const MAXINT_2 = 32767
const HFF = 255
const HFFFF = 65535
const HFFFFFF = 16777215
const HFFFFFFFF = -1
const HFF00FF = 16711935
const HFF00FF00 = -16711936
const HFFFF0000 = -65536
const H7FFFFFFF = 2147483647

class SHA3_C
    private SHA3_OK
    private SHA3_PARAMETER_ERROR
    private SHA3_SHAKE_NONE
    private SHA3_SHAKE_USE
    
    private KECCAK_SPONGE_BIT
    private KECCAK_ROUND
    private KECCAK_STATE_SIZE
    
    private KECCAK_SHA3_224
    private KECCAK_SHA3_256
    private KECCAK_SHA3_384
    private KECCAK_SHA3_512
    private KECCAK_SHAKE128
    private KECCAK_SHAKE256
    
    private KECCAK_SHA3_SUFFIX
    private KECCAK_SHAKE_SUFFIX
    
    private keccakRate
    private keccakCapacity
    private keccakSuffix

    private keccak_state(199)
    private end_offset

    private keccakf_rndc(23,1)
    private keccakf_rotc(23)
    private keccakf_piln(23)

    private sub class_initialize
        SHA3_OK = 0
        SHA3_PARAMETER_ERROR = 1
        SHA3_SHAKE_NONE = 0
        SHA3_SHAKE_USE = 1
        
        KECCAK_SPONGE_BIT = 1600
        KECCAK_ROUND = 24
        KECCAK_STATE_SIZE = 200

        KECCAK_SHA3_224 = 224
        KECCAK_SHA3_256 = 256
        KECCAK_SHA3_384 = 384
        KECCAK_SHA3_512 = 512
        KECCAK_SHAKE128 = 128
        KECCAK_SHAKE256 = 256

        KECCAK_SHA3_SUFFIX = &H06
        KECCAK_SHAKE_SUFFIX = &H1F

        keccakRate = 0
        keccakCapacity = 0
        keccakSuffix = 0

        keccakf_rndc(0,0) = CLng(1)
        keccakf_rndc(0,1) = CLng(0)
        keccakf_rndc(1,0) = CLng(32898)
        keccakf_rndc(1,1) = CLng(0)
        keccakf_rndc(2,0) = CLng(32906)
        keccakf_rndc(2,1) = CLng(-2147483648)
        keccakf_rndc(3,0) = CLng(-2147450880)
        keccakf_rndc(3,1) = CLng(-2147483648)
        keccakf_rndc(4,0) = CLng(32907)
        keccakf_rndc(4,1) = CLng(0)
        keccakf_rndc(5,0) = CLng(-2147483647)
        keccakf_rndc(5,1) = CLng(0)
        keccakf_rndc(6,0) = CLng(-2147450751)
        keccakf_rndc(6,1) = CLng(-2147483648)
        keccakf_rndc(7,0) = CLng(32777)
        keccakf_rndc(7,1) = CLng(-2147483648)
        keccakf_rndc(8,0) = CLng(138)
        keccakf_rndc(8,1) = CLng(0)
        keccakf_rndc(9,0) = CLng(136)
        keccakf_rndc(9,1) = CLng(0)
        keccakf_rndc(10,0) = CLng(-2147450871)
        keccakf_rndc(10,1) = CLng(0)
        keccakf_rndc(11,0) = CLng(-2147483638)
        keccakf_rndc(11,1) = CLng(0)
        keccakf_rndc(12,0) = CLng(-2147450741)
        keccakf_rndc(12,1) = CLng(0)
        keccakf_rndc(13,0) = CLng(139)
        keccakf_rndc(13,1) = CLng(-2147483648)
        keccakf_rndc(14,0) = CLng(32905)
        keccakf_rndc(14,1) = CLng(-2147483648)
        keccakf_rndc(15,0) = CLng(32771)
        keccakf_rndc(15,1) = CLng(-2147483648)
        keccakf_rndc(16,0) = CLng(32770)
        keccakf_rndc(16,1) = CLng(-2147483648)
        keccakf_rndc(17,0) = CLng(128)
        keccakf_rndc(17,1) = CLng(-2147483648)
        keccakf_rndc(18,0) = CLng(32778)
        keccakf_rndc(18,1) = CLng(0)
        keccakf_rndc(19,0) = CLng(-2147483638)
        keccakf_rndc(19,1) = CLng(-2147483648)
        keccakf_rndc(20,0) = CLng(-2147450751)
        keccakf_rndc(20,1) = CLng(-2147483648)
        keccakf_rndc(21,0) = CLng(32896)
        keccakf_rndc(21,1) = CLng(-2147483648)
        keccakf_rndc(22,0) = CLng(-2147483647)
        keccakf_rndc(22,1) = CLng(0)
        keccakf_rndc(23,0) = CLng(-2147450872)
        keccakf_rndc(23,1) = CLng(-2147483648)
    
        keccakf_rotc(0) = 1
        keccakf_rotc(1) = 3
        keccakf_rotc(2) = 6
        keccakf_rotc(3) = 10
        keccakf_rotc(4) = 15
        keccakf_rotc(5) = 21
        keccakf_rotc(6) = 28
        keccakf_rotc(7) = 36
        keccakf_rotc(8) = 45
        keccakf_rotc(9) = 55
        keccakf_rotc(10) = 2
        keccakf_rotc(11) = 14
        keccakf_rotc(12) = 27
        keccakf_rotc(13) = 41
        keccakf_rotc(14) = 56
        keccakf_rotc(15) = 8
        keccakf_rotc(16) = 25
        keccakf_rotc(17) = 43
        keccakf_rotc(18) = 62
        keccakf_rotc(19) = 18
        keccakf_rotc(20) = 39
        keccakf_rotc(21) = 61
        keccakf_rotc(22) = 20
        keccakf_rotc(23) = 44
        
        keccakf_piln(0) = 10
        keccakf_piln(1) = 7
        keccakf_piln(2) = 11
        keccakf_piln(3) = 17
        keccakf_piln(4) = 18
        keccakf_piln(5) = 3
        keccakf_piln(6) = 5
        keccakf_piln(7) = 16
        keccakf_piln(8) = 8
        keccakf_piln(9) = 21
        keccakf_piln(10) = 24
        keccakf_piln(11) = 4
        keccakf_piln(12) = 15
        keccakf_piln(13) = 23
        keccakf_piln(14) = 19
        keccakf_piln(15) = 13
        keccakf_piln(16) = 12
        keccakf_piln(17) = 2
        keccakf_piln(18) = 20
        keccakf_piln(19) = 14
        keccakf_piln(20) = 22
        keccakf_piln(21) = 9
        keccakf_piln(22) = 6
        keccakf_piln(23) = 1
    end sub

    private function UnsignedToLong(Value)
        if Value < 0 Or Value >= OFFSET_4 then
            UnsignedToLong = Value
        else
            if Value <= MAXINT_4 then
                UnsignedToLong = Value
            else
                UnsignedToLong = Value - OFFSET_4
            end if
        end if
    end function

    private function LongToUnsigned(Value)
        if Value < 0 then
            LongToUnsigned = Value + OFFSET_4
        else
            LongToUnsigned = Value
        end if
    end function

    private function LShift(v, s)
        if s = 0 then
            LShift = v
            exit function
        elseif s > 31 then
            LShift = 0
            exit function
        end if

        m = 1
        for i=1 to (s-1)
        m = m * 2 + 1
        next

        m2 = not m
        m3 = LongToUnsigned(m2)
        m4 = FIX(m3 / 2^s) + 1
        m5 = DMOD(v, m4)

        LShift = m5 * 2^s
    end function

    private function RShift(v, s)
        RShift = FIX(v / (2^s))
    end function

    private function SLShift(v, s)
        SLShift = UnsignedToLong(LShift(LongToUnsigned(v), s))
    end function

    private function SRShift(v, s)
        SRShift = UnsignedToLong(RShift(LongToUnsigned(v), s))
    end function

    private function DMOD(v, d)
        dim result
        result = v - (FIX(v / d) * d)
        DMOD = result
    end function

    private function MASK(v, m)
        MASK = UnsignedToLong(DMOD(LongToUnsigned(v), LongToUnsigned(m)+1))
    end function

    private function ROL64(ibuf0, ibuf1, byref obuf0, byref obuf1, offset)
        dim shift

        if offset = 0 then
            obuf1 = ibuf1
            obuf0 = ibuf0
        elseif offset < 32 then
            shift = offset
            obuf1 = SLShift(ibuf1, shift) xor SRShift(ibuf0, 32 - shift)
            obuf0 = SLShift(ibuf0, shift) xor SRShift(ibuf1, 32 - shift)
        elseif offset < 64 then
            shift = offset - 32
            obuf1 = SLShift(ibuf0, shift) xor SRShift(ibuf1, 32 - shift)
            obuf0 = SLShift(ibuf1, shift) xor SRShift(ibuf0, 32 - shift)
        else
            obuf1 = ibuf1
            obuf0 = ibuf0
        end if
    end function

    private function keccakf(byref state)
        dim t(1)
        dim bc(4,1)
        dim s(24,1)
        dim round
        dim i
        dim j

        for i = 0 to 24
            s(i,0) = SLShift(MASK(state(i * 8 + 3),HFF),24) or _
                SLShift(MASK(state(i * 8 + 2),HFF),16) or _
                SLShift(MASK(state(i * 8 + 1),HFF),8) or _
                SLShift(MASK(state(i * 8 + 0),HFF),0)
            s(i,1) = SLShift(MASK(state(i * 8 + 7),HFF),24) or _
                SLShift(MASK(state(i * 8 + 6),HFF),16) or _
                SLShift(MASK(state(i * 8 + 5),HFF),8) or _
                SLShift(MASK(state(i * 8 + 4),HFF),0)
        next

        for round = 0 to KECCAK_ROUND - 1
            ' Theta '
            for i = 0 to 4
                bc(i,0) = s(i,0) xor s(i + 5,0) xor s(i + 10,0) xor s(i + 15,0) xor s(i + 20,0)
                bc(i,1) = s(i,1) xor s(i + 5,1) xor s(i + 10,1) xor s(i + 15,1) xor s(i + 20,1)
            next

            for i = 0 to 4
                call ROL64(bc((i + 1) mod 5,0), bc((i + 1) mod 5,1), t(0), t(1), 1)

                t(0) = t(0) xor bc((i + 4) mod 5,0)
                t(1) = t(1) xor bc((i + 4) mod 5,1)

                for j = 0 to 24 step 5
                    s(j + i,0) = s(j + i,0) xor t(0)
                    s(j + i,1) = s(j + i,1) xor t(1)
                next
            next

            ' Rho & Pi '
            t(0) = s(1,0)
            t(1) = s(1,1)

            for i = 0 to KECCAK_ROUND - 1
                j = keccakf_piln(i)

                bc(0,0) = s(j,0)
                bc(0,1) = s(j,1)

                call ROL64(t(0), t(1), s(j,0), s(j,1), keccakf_rotc(i))

                t(0) = bc(0,0)
                t(1) = bc(0,1)
            next

            ' Chi '
            for j = 0 to 24 step 5
                for i = 0 to 4
                    bc(i,0) = s(j + i,0)
                    bc(i,1) = s(j + i,1)
                next

                for i = 0 to 4
                    s(j + i,0) = s(j + i,0) xor ((&HFFFFFFFF - bc((i + 1) mod 5,0)) and bc((i + 2) mod 5,0))
                    s(j + i,1) = s(j + i,1) xor ((&HFFFFFFFF - bc((i + 1) mod 5,1)) and bc((i + 2) mod 5,1))
                next
            next

            ' Iota '
            s(0,0) = s(0,0) xor keccakf_rndc(round,0)
            s(0,1) = s(0,1) xor keccakf_rndc(round,1)
        next

        for i = 0 to 24
            state(i * 8 + 0) = &HFF and (SRShift(s(i,0),  0))
            state(i * 8 + 1) = &HFF and (SRShift(s(i,0),  8))
            state(i * 8 + 2) = &HFF and (SRShift(s(i,0), 16))
            state(i * 8 + 3) = &HFF and (SRShift(s(i,0), 24))
            state(i * 8 + 4) = &HFF and (SRShift(s(i,1),  0))
            state(i * 8 + 5) = &HFF and (SRShift(s(i,1),  8))
            state(i * 8 + 6) = &HFF and (SRShift(s(i,1), 16))
            state(i * 8 + 7) = &HFF and (SRShift(s(i,1), 24))
        next
    end function

    private function keccak_absorb(input, inLen, rate, capacity)
        dim offset
        dim iLen
        dim rateInBytes
        dim blockSize

        iLen = inLen
        rateInBytes = rate / 8
        
        if (rate + capacity) <> KECCAK_SPONGE_BIT then
            keccak_absorb = SHA3_PARAMETER_ERROR
        end if

        if (((rate mod 8) <> 0) or (rateInBytes < 1)) then
            keccak_absorb = SHA3_PARAMETER_ERROR
        end if

        offset = 0
        while iLen > 0
            if ((end_offset <> 0) and (end_offset < rateInBytes)) then
                if (iLen + end_offset) < rateInBytes then
                    blockSize = iLen + end_offset
                else
                    blockSize = rateInBytes
                end if

                for i = end_offset to blockSize - 1
                    keccak_state(i) = keccak_state(i) xor input(i - end_offset)
                next

                offset = offset + blockSize - end_offset
                iLen = iLen - blockSize = end_offset
            else
                if iLen < rateInBytes then
                    blockSize = iLen
                else
                    blockSize = rateInBytes
                end if

                for i = 0 to blockSize - 1
                    keccak_state(i) = keccak_state(i) xor input(i + offset)
                next

                offset = offset + blockSize
                iLen = iLen - blockSize
            end if

            if blockSize = rateInBytes then
                call keccakf(keccak_state)

                blockSize = 0
            end if

            end_offset = blockSize
        wend

        keccak_absorb = SHA3_OK
    end function

    private function keccak_squeeze(byref output, outLen, rate, suffix)
        dim offset
        dim oLen
        dim rateInBytes
        dim blockSize

        oLen = outLen
        rateInBytes = rate / 8
        blockSize = end_offset
        
        keccak_state(blockSize) = keccak_state(blockSize) xor suffix

        if (((suffix and &H80) <> 0) and (blockSize = (rateInBytes - 1))) then
            call keccakf(keccak_state)
        end if

        keccak_state(rateInBytes - 1) = keccak_state(rateInBytes - 1) xor &H80

        call keccakf(keccak_state)

        offset = 0
        while oLen > 0
            if oLen < rateInBytes then
                blockSize = oLen
            else
                blockSize = rateInBytes
            end if

            for i = 0 to blockSize - 1
                output(i + offset) = keccak_state(i)
            next

            offset = offset + blockSize
            oLen = oLen - blockSize

            if oLen > 0 then
                call keccakf(keccak_state)
            end if
        wend

        keccak_squeeze = SHA3_OK
    end function

    public function sha3_init(bitSize, useSHAKE)
        keccakCapacity = bitSize * 2
        keccakRate = KECCAK_SPONGE_BIT - keccakCapacity

        if (useSHAKE = SHA3_SHAKE_USE) then
            keccakSuffix = KECCAK_SHAKE_SUFFIX
        else
            keccakSuffix = KECCAK_SHA3_SUFFIX
        end if

        for i = 0 to 199
            keccak_state(i) = 0
        next

        end_offset = 0
    end function

    public function sha3_224_init()
        call sha3_init(KECCAK_SHA3_224, SHA3_SHAKE_NONE)
    end function

    public function sha3_256_init()
        call sha3_init(KECCAK_SHA3_256, SHA3_SHAKE_NONE)
    end function

    public function sha3_384_init()
        call sha3_init(KECCAK_SHA3_384, SHA3_SHAKE_NONE)
    end function

    public function sha3_512_init()
        call sha3_init(KECCAK_SHA3_512, SHA3_SHAKE_NONE)
    end function

    public function shake128_init()
        call sha3_init(KECCAK_SHAKE128, SHA3_SHAKE_USE)
    end function

    public function shake256_init()
        call sha3_init(KECCAK_SHAKE256, SHA3_SHAKE_USE)
    end function

    public function sha3_update(input, inLen)
        sha3_update = keccak_absorb(input, inLen, keccakRate, keccakCapacity)
    end function

    public function sha3_final(byref output, outLen)
        dim ret

        ret = keccak_squeeze(output, outLen, keccakRate, keccakSuffix)

        keccakRate = 0
        keccakCapacity = 0
        keccakSuffix = 0

        for i = 0 to 199
            keccak_state(i) = 0
        next

        sha3_final = ret
    end function

    public function sha3_hash(byref output, outLen, input, inLen, bitSize, useSHAKE)
        dim ret

        if (useSHAKE = SHA3_SHAKE_USE) then
            if (bitSize <> KECCAK_SHAKE128) and (bitSize <> KECCAK_SHAKE256) then
                sha3_hash = SHA3_PARAMETER_ERROR
            end if

            call sha3_init(bitSize, SHA3_SHAKE_USE)
        else
            if (bitSize <> KECCAK_SHA3_224) and (bitSize <> KECCAK_SHA3_256) and (bitSize <> KECCAK_SHA3_384) and (bitSize <> KECCAK_SHA3_512) then
                sha3_hash = SHA3_PARAMETER_ERROR
            end if

            call sha3_init(bitSize, SHA3_SHAKE_NONE)
        end if

        call sha3_update(input, inLen)

        ret = sha3_final(output, outLen)

        sha3_hash = ret
    end function
end class

set SHA3 = new SHA3_C

%>