package security.org.jwt.been;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.jose4j.base64url.Base64;

/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2018年12月3日 上午11:04:32
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/
public class KeyFormat {
	
	public  PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = Base64.decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
  }
	
	public  PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes =  Base64.decode(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
  }

}
