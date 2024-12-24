<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ include file="sha3.jsp" %>

<%!
    public byte[] getBytes(String data)
    {
        String[] str = data.split(",");
        byte[] result = new byte[str.length];

        for (int i = 0; i < result.length; i++)
        {
            result[i] = getHex(str[i]);
        }

        return result;
    }

    public String getString(byte[] data)
    {
        String result = "";

        for (int i = 0; i < data.length; i++)
        {
            result = result + toHex(data[i]);

            if (i < data.length - 1)
                result = result + ",";
        }

        return result;
    }

    public byte getHex(String str)
    {
        str = str.trim();

        if (str.length() == 0)
            str = "00";
        else if (str.length() == 1)
            str = "0" + str;
        
        str = str.toUpperCase();

        return (byte)(getHexNibble(str.charAt(0)) * 16 + getHexNibble(str.charAt(1)));
    }

    public byte getHexNibble(char c)
    {
        if ((c >= '0') && (c <= '9'))
            return (byte)(c - '0');
        
        if ((c >= 'A') && (c <='F'))
            return (byte)(c - 'A' + 10);

        return 0;
    }

    public String toHex(int b)
    {
        char c[] = new char[2];

        c[0] = toHexNibble((b >> 4) & 0x0f);
        c[1] = toHexNibble(b & 0x0f);

        return new String(c);
    }

    public char toHexNibble(int b)
    {
        if ((b >= 0) && (b <= 9))
            return (char)(b + '0');

        if ((b >= 0x0a) && (b <= 0x0f))
            return (char)(b + 'A' - 10);

        return '0';
    }
%>

<%
String method = request.getParameter("method");

String msg = "";
String sha3_224 = "";
String sha3_256 = "";
String sha3_384 = "";
String sha3_512 = "";
String shake128 = "";
String shake256 = "";

if ((method != null) && (method.equals("h")))
{
    String inputStr = request.getParameter("msg");
    byte[] input = getBytes(inputStr);
    String outputStr;
    byte[] output;
    int inputLen = 0;
    int ret = 0;

    if ((inputStr == null) || (inputStr.equals("null")) || (inputStr.equals("")))
        inputLen = 0;
    else
        inputLen = (int)input.length;
        
    input = getBytes(inputStr);

    output = new byte[28];
    ret = sha3_hash(output, 224/8, input, inputLen, 224, 0);

    if (ret == 0)
    {
        outputStr = getString(output);
        sha3_224 = outputStr;
    }
    else
    {
        sha3_224 = String.format("Failure!");
    }

    output = new byte[32];
    ret = sha3_hash(output, 256/8, input, inputLen, 256, 0);

    if (ret == 0)
    {
        outputStr = getString(output);
        sha3_256 = outputStr;
    }
    else
    {
        sha3_256 = String.format("Failure!");
    }

    output = new byte[48];
    ret = sha3_hash(output, 384/8, input, inputLen, 384, 0);

    if (ret == 0)
    {
        outputStr = getString(output);
        sha3_384 = outputStr;
    }
    else
    {
        sha3_384 = String.format("Failure!");
    }

    output = new byte[64];
    ret = sha3_hash(output, 512/8, input, inputLen, 512, 0);

    if (ret == 0)
    {
        outputStr = getString(output);
        sha3_512 = outputStr;
    }
    else
    {
        sha3_512 = String.format("Failure!");
    }

    output = new byte[512];
    ret = sha3_hash(output, 512, input, inputLen, 128, 1);

    if (ret == 0)
    {
        outputStr = getString(output);
        shake128 = outputStr;
    }
    else
    {
        shake128 = String.format("Failure!");
    }

    output = new byte[512];
    ret = sha3_hash(output, 512, input, inputLen, 256, 1);

    if (ret == 0)
    {
        outputStr = getString(output);
        shake256 = outputStr;
    }
    else
    {
        shake256 = String.format("Failure!");
    }
}
%>

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8"> 
        <title>[SHA3] 테스트 페이지</title>
        <script type="text/javascript">
            function hash()
            {
                var frm = document.myform;
                document.getElementById("method").value = "h";
                frm.submit();
            }
        </script>
    </head>
    <body>
        <center>
            <h1>[SHA3] 테스트 페이지</h1>
        <form name="myform" method="post" action="./sha3_test.jsp">
            <input type="hidden" name="method" id="method" />
            <table border="0">
                <tr>
                <td style="text-align:center;">
                    <table border="0">
                    <tr>
                        <td>메시지   : </td> 
                        <td><textarea name="msg" style="width:680px;height:150px;"><%=msg %></textarea></td>
                    </tr>
                    <tr>
                        <td></td>
                        <td><button onclick="hash();">▼ Hash</button></td>
                    </tr>
                    <tr>
                        <td>SHA3-224 : </td> 
                        <td><textarea name="sha3_224" style="width:680px;height:20px;"><%=sha3_224 %></textarea></td>
                    </tr>
                    <tr>
                        <td>SHA3-256 : </td> 
                        <td><textarea name="sha3_256" style="width:680px;height:20px;"><%=sha3_256 %></textarea></td>
                    </tr>
                    <tr>
                        <td>SHA3-384 : </td>
                        <td><textarea name="sha3_384" style="width:680px;height:40px;"><%=sha3_384 %></textarea></td>
                    </tr>
                    <tr>
                        <td>SHA3-512 : </td>
                        <td><textarea name="sha3_512" style="width:680px;height:40px;"><%=sha3_512 %></textarea></td>
                    </tr>
                    <tr>
                        <td>SHAKE128 : </td> 
                        <td><textarea name="shake128" style="width:680px;height:250px;"><%=shake128 %></textarea></td>
                    </tr>
                    <tr>
                        <td>SHAKE256 : </td>
                        <td><textarea name="shake256" style="width:680px;height:250px;"><%=shake256 %></textarea></td>
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
