package security.org.jwt.domain;

import java.util.Date;

/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2018年11月29日 下午3:57:08
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/
public class Jwt {
	private Integer id;
	private Integer tenantId;
	private String owner;
	private String privateKey;
	private String publicKey;
	private String Jwk;
	private String note;
	private String jsonSpec;
	private Date lastUpdated;
	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public Integer getTenantId() {
		return tenantId;
	}
	public void setTenantId(Integer tenantId) {
		this.tenantId = tenantId;
	}
	public String getOwner() {
		return owner;
	}
	public void setOwner(String owner) {
		this.owner = owner;
	}
	public String getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}
	public String getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}
	public String getJwk() {
		return Jwk;
	}
	public void setJwk(String jwk) {
		Jwk = jwk;
	}
	public String getJsonSpec() {
		return jsonSpec;
	}
	public void setJsonSpec(String jsonSpec) {
		this.jsonSpec = jsonSpec;
	}
	public Date getLastUpdated() {
		return lastUpdated;
	}
	public void setLastUpdated(Date lastUpdated) {
		this.lastUpdated = lastUpdated;
	}
	public String getNote() {
		return note;
	}
	public void setNote(String note) {
		this.note = note;
	}
	
}
