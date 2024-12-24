<!--#include file="sha3.asp" -->
<%
    dim msg
    dim sha3_224
    dim sha3_256
    dim sha3_384
    dim sha3_512
    dim shake128
    dim shake256

    dim tempMSG
    dim arrMSG
    dim msgLen


    function sha3_224_hash(hmsg, hlen, byref hash)
        dim temp(27)
        dim i
        dim ret

        ret = sha3.sha3_hash(temp, 224/8, hmsg, hlen, 224, 0)

        if ret <> 0 then
            hash = "Failure!"
        else
            hash = ""
            for i = 0 to (ubound(temp))
                hash = hash & Right("0000" & hex(temp(i)), 2)

                if (i <> ubound(temp)) then
                    hash = hash & ","
                end if
            next
        end if
    end function

    function sha3_256_hash(hmsg, hlen, byref hash)
        dim temp(31)
        dim i
        dim ret

        ret = sha3.sha3_hash(temp, 256/8, hmsg, hlen, 256, 0)

        if ret <> 0 then
            hash = "Failure!"
        else
            hash = ""
            for i = 0 to (ubound(temp))
                hash = hash & Right("0000" & hex(temp(i)), 2)

                if (i <> ubound(temp)) then
                    hash = hash & ","
                end if
            next
        end if
    end function

    function sha3_384_hash(hmsg, hlen, byref hash)
        dim temp(47)
        dim i
        dim ret

        ret = sha3.sha3_hash(temp, 384/8, hmsg, hlen, 384, 0)

        if ret <> 0 then
            hash = "Failure!"
        else
            hash = ""
            for i = 0 to (ubound(temp))
                hash = hash & Right("0000" & hex(temp(i)), 2)

                if (i <> ubound(temp)) then
                    hash = hash & ","
                end if
            next
        end if
    end function

    function sha3_512_hash(hmsg, hlen, byref hash)
        dim temp(63)
        dim i
        dim ret

        ret = sha3.sha3_hash(temp, 512/8, hmsg, hlen, 512, 0)

        if ret <> 0 then
            hash = "Failure!"
        else
            hash = ""
            for i = 0 to (ubound(temp))
                hash = hash & Right("0000" & hex(temp(i)), 2)

                if (i <> ubound(temp)) then
                    hash = hash & ","
                end if
            next
        end if
    end function

    function shake128_hash(hmsg, hlen, byref hash)
        dim temp(511)
        dim i
        dim ret

        ret = sha3.sha3_hash(temp, 512, hmsg, hlen, 128, 1)

        if ret <> 0 then
            hash = "Failure!"
        else
            hash = ""
            for i = 0 to (ubound(temp))
                hash = hash & Right("0000" & hex(temp(i)), 2)

                if (i <> ubound(temp)) then
                    hash = hash & ","
                end if
            next
        end if
    end function

    function shake256_hash(hmsg, hlen, byref hash)
        dim temp(511)
        dim i
        dim ret

        ret = sha3.sha3_hash(temp, 512, hmsg, hlen, 256, 1)

        if ret <> 0 then
            hash = "Failure!"
        else
            hash = ""
            for i = 0 to (ubound(temp))
                hash = hash & Right("0000" & hex(temp(i)), 2)

                if (i <> ubound(temp)) then
                    hash = hash & ","
                end if
            next
        end if
    end function

    msg = Trim(request.form("MSG"))

    if (IsNull(msg) or (Len(Trim(msg)) = 0)) then
        msgLen = 0
    else
        tempMSG = split(msg,",")
        redim arrMSG(ubound(tempMSG))

        for i = 0 to (ubound(tempMSG))
            arrMSG(i) = (Cbyte)("&H" & (right("0000" & tempMSG(i), 4)))
        next
        msgLen = ubound(arrMSG) + 1
    end if

    call sha3_224_hash(arrMSG, msgLen, sha3_224)
    call sha3_256_hash(arrMSG, msgLen, sha3_256)
    call sha3_384_hash(arrMSG, msgLen, sha3_384)
    call sha3_512_hash(arrMSG, msgLen, sha3_512)
    call shake128_hash(arrMSG, msgLen, shake128)
    call shake256_hash(arrMSG, msgLen, shake256)

%>

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8"> 
        <title>[SHA3] 테스트 페이지</title>
    </head>
    <body>
        <center>
            <h1>[SHA3] 테스트 페이지</h1>
        <form name="myform" method="post" action="./sha3_test.asp">
            <input type="hidden" name="method" id="method" />
            <table border="0">
                <tr>
                <td style="text-align:center;">
                <form method="post" action="./sha3_test.asp">
                    <table border="0">
                    <tr>
                        <td>메시지   : </td> 
                        <td><textarea name="MSG" style="width:680px;height:150px;"><%=msg%></textarea></td>
                    </tr>
                    <tr>
                        <td></td>
                        <td><input type="submit" name="gogo" value="▼ Hash"> </td>
                    </tr>
                    <tr>
                        <td>SHA3-224 : </td> 
                        <td><textarea name="SHA3_224" style="width:680px;height:20px;"><%=sha3_224%></textarea></td>
                    </tr>
                    <tr>
                        <td>SHA3-256 : </td> 
                        <td><textarea name="SHA3_256" style="width:680px;height:20px;"><%=sha3_256%></textarea></td>
                    </tr>
                    <tr>
                        <td>SHA3-384 : </td>
                        <td><textarea name="SHA3_384" style="width:680px;height:40px;"><%=sha3_384%></textarea></td>
                    </tr>
                    <tr>
                        <td>SHA3-512 : </td>
                        <td><textarea name="SHA3_512" style="width:680px;height:40px;"><%=sha3_512%></textarea></td>
                    </tr>
                    <tr>
                        <td>SHAKE128 : </td> 
                        <td><textarea name="SHAKE128" style="width:680px;height:250px;"><%=shake128%></textarea></td>
                    </tr>
                    <tr>
                        <td>SHAKE256 : </td>
                        <td><textarea name="SHAKE256" style="width:680px;height:250px;"><%=shake256%></textarea></td>
                    </tr>
                    </table>
                </form>	
                </td>
                </tr>
            </table>
            <div style="margin-top:20px;margin-bottom:20px;"><font color="#ff0000">※ 평문은 Hex 값의 0x를 제외하고 콤마로 구분하여 띄어쓰기 없이 입력합니다.(ex : 00,01,0A,0B)</font>
            </div>
            <div style="border: 1px solid #aaaaff; background-color:#ddddff;">
                <table border="0">
                    <tr>
                        <td>&lt;메시지&gt; : </td>
                        <td>FC,58,7C,16,26,93,E6,CD,63,EE,D5,39,B5,7B,EA,09</td>
                    </tr>
                    <tr>
                        <td>&lt;SHA3-224&gt; : </td>
                        <td>AB,ED,8E,C0,17,40,36,62,1A,FF,27,B9,95,95,F5,91,4D,A6,F5,E8,55,65,83,D0,D8,BC,EA,BC</td>
                    </tr>
                    <tr>
                        <td>&lt;SHA3-256&gt; : </td>
                        <td>3F,0F,79,36,D2,80,95,B8,CF,B0,3C,1B,C1,C8,B8,2A,DC,5D,28,E3,25,9E,25,96,42,F8,A8,44,14,29,46,75</td>
                    </tr>
                </table>
            </div>
            </form>
        </center>
    </body>
</html>
