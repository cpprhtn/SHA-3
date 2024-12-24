public class sha3_test {

    private static final int MSG_0_BUF_SIZE = 200;
    private static final int MSG_1600_BUF_SIZE = 200;
    private static final int OUTPUT_BUF_SIZE = 512;

    public static void main(String[] args) {
        sha3_0msg_test();
        sha3_1600msg_test();
    }

    private static void sha3_0msg_test() {
        byte msg[] = new byte[MSG_0_BUF_SIZE];
        byte buf_sha3_224[] = new byte[OUTPUT_BUF_SIZE];
        byte buf_sha3_256[] = new byte[OUTPUT_BUF_SIZE];
        byte buf_sha3_384[] = new byte[OUTPUT_BUF_SIZE];
        byte buf_sha3_512[] = new byte[OUTPUT_BUF_SIZE];
        byte buf_shake128[] = new byte[OUTPUT_BUF_SIZE];
        byte buf_shake256[] = new byte[OUTPUT_BUF_SIZE];
        int len = 0, i = 0;

        sha3 sha3_test = new sha3();

        for (i = 0; i < MSG_0_BUF_SIZE; i++)
            msg[i] = 0;

        // SHA3-224 0_Msg test
        len = 224 / 8;
        sha3_test.sha3_hash(buf_sha3_224, len, msg, 0, 224, 0);

        print_hex("sha3-224", buf_sha3_224, len);

        // SHA3-256 0_Msg test
        len = 256 / 8;
        sha3_test.sha3_hash(buf_sha3_256, len, msg, 0, 256, 0);

        print_hex("sha3-256", buf_sha3_256, len);

        // SHA3-384 0_Msg test
        len = 384 / 8;
        sha3_test.sha3_hash(buf_sha3_384, len, msg, 0, 384, 0);

        print_hex("sha3-384", buf_sha3_384, len);

        // SHA3-512 0_Msg test
        len = 512 / 8;
        sha3_test.sha3_hash(buf_sha3_512, len, msg, 0, 512, 0);

        print_hex("sha3-512", buf_sha3_512, len);

        // SHAKE128 0_Msg test
        len = 512;
        sha3_test.sha3_hash(buf_shake128, len, msg, 0, 128, 1);

        print_hex("shake128", buf_shake128, len);

        // SHAKE256 0_Msg test
        len = 512;
        sha3_test.sha3_hash(buf_shake256, len, msg, 0, 256, 1);

        print_hex("shake256", buf_shake256, len);
    }

    private static void sha3_1600msg_test() {
        byte msg[] = new byte[MSG_1600_BUF_SIZE];
        byte buf_sha3_224[] = new byte[OUTPUT_BUF_SIZE];
        byte buf_sha3_256[] = new byte[OUTPUT_BUF_SIZE];
        byte buf_sha3_384[] = new byte[OUTPUT_BUF_SIZE];
        byte buf_sha3_512[] = new byte[OUTPUT_BUF_SIZE];
        byte buf_shake128[] = new byte[OUTPUT_BUF_SIZE];
        byte buf_shake256[] = new byte[OUTPUT_BUF_SIZE];
        int len = 0, i = 0;

        sha3 sha3_test = new sha3();

        for (i = 0; i < MSG_1600_BUF_SIZE; i++)
            msg[i] = (byte)163; // 0xA3

        // SHA3-224 1600_Msg test
        len = 224 / 8;
        sha3_test.sha3_hash(buf_sha3_224, len, msg, MSG_1600_BUF_SIZE, 224, 0);

        print_hex("sha3-224", buf_sha3_224, len);

        // SHA3-256 1600_Msg test
        len = 256 / 8;
        sha3_test.sha3_hash(buf_sha3_256, len, msg, MSG_1600_BUF_SIZE, 256, 0);

        print_hex("sha3-256", buf_sha3_256, len);

        // SHA3-384 1600_Msg test
        len = 384 / 8;
        sha3_test.sha3_hash(buf_sha3_384, len, msg, MSG_1600_BUF_SIZE, 384, 0);

        print_hex("sha3-384", buf_sha3_384, len);

        // SHA3-512 1600_Msg test
        len = 512 / 8;
        sha3_test.sha3_hash(buf_sha3_512, len, msg, MSG_1600_BUF_SIZE, 512, 0);

        print_hex("sha3-512", buf_sha3_512, len);

        // SHAKE128 1600_Msg test
        len = 512;
        sha3_test.sha3_hash(buf_shake128, len, msg, MSG_1600_BUF_SIZE, 128, 1);

        print_hex("shake128", buf_shake128, len);

        // SHAKE256 1600_Msg test
        len = 512;
        sha3_test.sha3_hash(buf_shake256, len, msg, MSG_1600_BUF_SIZE, 256, 1);

        print_hex("shake256", buf_shake256, len);
    }

    private static void print_hex(String valName, byte[] data, int dataLen)
    {
        int i = 0;

        System.out.printf("%s :", valName);
        for (i = 0; i < dataLen; i++)
        {
            if ((i & 0x0F) == 0)
                System.out.println("");

            System.out.printf(" %02X", data[i]);
        }
        System.out.println("");
    }
}