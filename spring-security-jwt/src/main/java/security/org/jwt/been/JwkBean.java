package security.org.jwt.been;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2018年12月5日 上午11:43:40
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/
@JsonIgnoreProperties(ignoreUnknown = true) 
public class JwkBean {

	private List<Jwk> keys;

	public List<Jwk> getKeys() {
		return keys;
	}

	public void setKeys(List<Jwk> keys) {
		this.keys = keys;
	}
	
}
