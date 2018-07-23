package com.duideduo.security;




import com.duideduo.aes.AESUtil;
import com.duideduo.rsa.RSAUtil;
import com.duideduo.sha.SHAUtil;

import javax.crypto.BadPaddingException;
        import javax.crypto.IllegalBlockSizeException;
        import javax.crypto.NoSuchPaddingException;
        import java.security.InvalidKeyException;
        import java.security.NoSuchAlgorithmException;
        import java.security.spec.InvalidKeySpecException;
        import java.util.Base64;
        import java.util.Random;

/**
 * @author victor
 * @version V1.0
 * @Title: ${file_name}
 * @Package ${package_name}
 * @Description: 天天兑加密工具类
 * @date ${date} ${time}
 */
public class SecurityUtil {
    private static String publicKey="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMfySi/iKzbED4sDbUScxQvk5SxSBNp35zB0OizQ4SmxpPkqHKuL78LWqJ6qS/+02yIv9Wv1dp+ui/o7StGfuJkCAwEAAQ==";
    private static String privateKey="MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAx/JKL+IrNsQPiwNtRJzFC+TlLFIE2nfnMHQ6LNDhKbGk+Socq4vvwtaonqpL/7TbIi/1a/V2n66L+jtK0Z+4mQIDAQABAkEAmaSdTV5GRrcyGmhvtqGg6Rri38PG5vnsNVeavIVmAFqd7eMu9wufDm7jIrwF7DUhEjkdS5C/mJ1du2jPoolQAQIhAOJeB44RrQc08dn18vTCWe7LEVNXz+5E5EAw+s7vNdJBAiEA4h7Zsooej+4VB9QxlUGHQ6f0drQkLK8Rbm4/ASJBoFkCICCNBOkZAZiXtG9zPoyTpfsAmG0zo2LP5UKVyHsZStQBAiEAzGlRKXp86GY08s/bRu9nBT1W3Nw6e36Dxo25PSAnrXkCIGhLQwYUQhQfBZ1CJ0kGlD5xlGonaVjySdp2w0Ud3oCS";

    public static String clientEncode(String param,String aesKey) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        //sign参数签名
        byte[] signParam = SHAUtil.SHA256(param).getBytes();
        //rsa加密aes的key
        byte[] rsaAesKey = RSAUtil.publicKeyEncode(aesKey.getBytes(),RSAUtil.getPublicKeyByString(publicKey));
        //aes加密参数
        byte[] aesParam = AESUtil.encode(param,aesKey);
        //转string
        return Base64.getEncoder().encodeToString(SecurityUtil.byteMergerAll(signParam,rsaAesKey,aesParam));
    }

    public static String clientDecode(String secResult,String aesKey) throws Exception {
        byte[] secResultByte = Base64.getDecoder().decode(secResult);
        byte[] signResult = new byte[64],aesResult=new byte[secResultByte.length-signResult.length];
        System.arraycopy(secResultByte,0,signResult,0,signResult.length);
        System.arraycopy(secResultByte,signResult.length,aesResult,0,aesResult.length);

        byte[] result =  AESUtil.decode(aesResult,aesKey);

        if(!RSAUtil.checkSign(result,signResult,RSAUtil.getPublicKeyByString(SecurityUtil.publicKey))){
            throw new Exception("签名错误");
        }
        return new String(result);
    }

    public static String serverEncode(String result,String aesKey) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        byte[] signResult = RSAUtil.sign(result.getBytes(),RSAUtil.getPrivateKeyByString(SecurityUtil.privateKey)); //RSA签名
        byte[] aesResult = AESUtil.encode(result,aesKey);
        return Base64.getEncoder().encodeToString(SecurityUtil.byteMergerAll(signResult,aesResult));
    }

    public static String[] serverDecode(String secParam) throws Exception {
        byte[] byteParam = Base64.getDecoder().decode(secParam);
        byte[] signParam = new byte[64],rsaAesKey=new byte[64],aesParam=new byte[byteParam.length-signParam.length-rsaAesKey.length];
        System.arraycopy(byteParam,0,signParam,0,signParam.length);
        System.arraycopy(byteParam,signParam.length,rsaAesKey,0,rsaAesKey.length);
        System.arraycopy(byteParam,signParam.length+rsaAesKey.length,aesParam,0,aesParam.length);

        byte[] aesKey = RSAUtil.privateKeyDecode(rsaAesKey,RSAUtil.getPrivateKeyByString(SecurityUtil.privateKey));
        byte[] param = AESUtil.decode(aesParam,new String(aesKey));
        String signParamFromParam = SHAUtil.SHA256(new String(param));

        if(!signParamFromParam.equals(new String(signParam))){
            throw new Exception("签名错误");
        }
        //返回结果与aeskey,返回key是为了后面的解密
        return new String[]{new String(param), new String(aesKey)};
    }

    /**
     * 组合byte
     * @param values
     * @return
     */
    private static byte[] byteMergerAll(byte[]... values) {
        int length_byte = 0;
        for (int i = 0; i < values.length; i++) {
            length_byte += values[i].length;
        }
        byte[] all_byte = new byte[length_byte];
        int countLength = 0;
        for (int i = 0; i < values.length; i++) {
            byte[] b = values[i];
            System.arraycopy(b, 0, all_byte, countLength, b.length);
            countLength += b.length;
        }
        return all_byte;
    }

    /**
     * 生成随机数
     * @param random
     * @param len
     * @return
     */
    public static String createPassWord(int random,int len){
        Random rd = new Random(random);
        final int  maxNum = 62;
        StringBuffer sb = new StringBuffer();
        int rdGet;//取得随机数
        char[] str = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
                'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
                'x', 'y', 'z', 'A','B','C','D','E','F','G','H','I','J','K',
                'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
                'X', 'Y' ,'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

        int count=0;
        while(count < len){
            rdGet = Math.abs(rd.nextInt(maxNum));//生成的数最大为62-1
            if (rdGet >= 0 && rdGet < str.length) {
                sb.append(str[rdGet]);
                count ++;
            }
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception{
        //System.out.println(SecurityUtil.createPassWord(0,32));

        //客户端模拟aeskey
        String aesKey = Integer.toString(new Random().nextInt(99999)%(99999-10000+1) + 10000);

        String scParam = SecurityUtil.clientEncode("hello victor",aesKey);
        String[] param = SecurityUtil.serverDecode(scParam);
        String sParam = param[0];//结果
        aesKey = param[1];//结果
        System.out.println(sParam);
        System.out.println(aesKey);

        String scResult = SecurityUtil.serverEncode("服务器结果",aesKey);
        System.out.println(SecurityUtil.clientDecode(scResult,aesKey));

    }
}

