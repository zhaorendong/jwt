package security.org.jwt.util;
/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2018年12月4日 下午5:15:53
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/
public class TokenValidationException extends RuntimeException  {
	   public TokenValidationException(String msg) {
           super(msg);
       }
}
