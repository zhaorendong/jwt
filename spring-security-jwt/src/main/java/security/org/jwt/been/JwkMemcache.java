package security.org.jwt.been;
/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2019年1月22日 下午4:00:34
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/
public class JwkMemcache {

	private String name;
	private JwkBean jwkBean;
	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public JwkBean getJwkBean() {
		return jwkBean;
	}
	public void setJwkBean(JwkBean jwkBean) {
		this.jwkBean = jwkBean;
	}
	
}
