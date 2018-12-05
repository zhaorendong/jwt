package security.org.jwt.been;
/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2018年12月5日 下午2:03:39
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/
public class Jwk {
	private String kty;
	private String kid;
	private String n;
	private String e;
	
	public String getKty() {
		return kty;
	}
	public void setKty(String kty) {
		this.kty = kty;
	}
	public String getKid() {
		return kid;
	}
	public void setKid(String kid) {
		this.kid = kid;
	}
	public String getN() {
		return n;
	}
	public void setN(String n) {
		this.n = n;
	}
	public String getE() {
		return e;
	}
	public void setE(String e) {
		this.e = e;
	}
	
}
