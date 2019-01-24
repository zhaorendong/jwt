package security.org.jwt.service;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.jose4j.base64url.Base64;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

import security.org.jwt.been.JwkBean;
import security.org.jwt.been.KeyFormat;
import security.org.jwt.domain.Jwt;
import security.org.jwt.domain.User;
import security.org.jwt.mapping.JwtMapper;
import security.org.jwt.util.JSONUtil;
import security.org.jwt.util.ShowApi;
import security.org.jwt.util.SystemUtil;
import security.org.jwt.util.TokenValidationException;

/**
 * @author zhaorendong
 * @Email: 13552066077@163.com
 * @Date: 2018年11月28日 上午9:31:18
 * @Description: jwt Service 
 */
@Service
public class JwtService {

	private static final Logger log = Logger.getLogger(JwtService.class);
    public static final String TOKEN_PREFIX = "Bearer";
    public static final String HEADER_STRING = "Authorization";
    public static final long EFFECTIVE_TIME = 60*60*1000;
    
	@Autowired
	private JwtMapper jwtDao;
	@Autowired
	private ShowApi showApi;
	
	@Value("${ladp.dn}")
	private String dn;
	@Value("${ladp.url}")
	private String url;
	@Value("${ladp.port}")
	private String port;
	@Value("${ladp.user}")
	private String user;
	@Value("${ladp.pass}")
	private String pass;
	
	/**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年11月28日 上午9:31:18
	* @version 1.0
	* @return List<{@link Jwt}>
	* @Description get Jwts
	*/
	@Transactional(propagation = Propagation.NOT_SUPPORTED)
	public List<Jwt> getJwts() {
		return jwtDao.selectAll();
	}
	
	/**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年11月28日 上午9:32:38
	* @version 1.0
	* @param tenantId
	* @return List<{@link Jwt}>
	* @Description get Jwt By Tenant
	*/
	@Transactional(propagation = Propagation.NOT_SUPPORTED)
	public Jwt getJwtByTenant(int tenantId) {
		return jwtDao.selectByTenant(tenantId);
	}

	/**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年12月4日 下午4:41:48
	* @version 1.0
	* @param tenantId
	* @param owner
	* @return Jwt
	* @Description get Jwt By Tenant And Owner
	*/
	@Transactional(propagation = Propagation.NOT_SUPPORTED)
	public Jwt getJwtByTenantAndOwner(int tenantId, String owner) {
		return jwtDao.selectByTenantIdAndOwner(tenantId, owner);
	}
	
	/**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年11月28日 上午9:34:17
	* @version 1.0
	* @param id
	* @return Jwt
	* @Description get Jwt
	*/
	@Transactional(propagation = Propagation.NOT_SUPPORTED)
	public Jwt getJwt(int id) {
		return jwtDao.selectByPrimaryKey(id);
	}
	

	/**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年11月29日 下午5:39:26
	* @version 1.0
	* @param tenantId
	* @param owner
	* @param privateKey
	* @param publicKey
	* @param jwk
	* @param note
	* @param json
	* @return int
	* @Description add Jwt into db
	*/
	@Transactional(propagation = Propagation.REQUIRED)
	public int addJwt(int tenantId, String owner, String privateKey, String publicKey, String jwk, String note, String json) {
		Jwt jwt = new Jwt();
		jwt.setTenantId(tenantId);
		jwt.setOwner(owner);
		jwt.setPrivateKey(privateKey);
		jwt.setPublicKey(publicKey);
		jwt.setJwk(jwk);
		jwt.setJsonSpec(json);
		jwt.setNote(note);
		jwt.setJsonSpec(json);
		jwtDao.insert(jwt);
		return jwt.getId();
	}

	/**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年11月29日 下午5:40:59
	* @version 1.0
	* @param jwt
	* @return int
	* @Description update Jwt
	*/
	@Transactional(propagation = Propagation.REQUIRED)
	public int updateJwt(Jwt jwt) {
		return jwtDao.updateByPrimaryKey(jwt);
	}
	
	/**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年12月5日 下午2:44:00
	* @version 1.0
	* @param username
	* @param tenantId
	* @return Jwt
	* @Description create Jwt
	*/
	public Jwt createJwt(String username,int tenantId){
		try {
			RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
		    rsaJsonWebKey.setKeyId("k1");
		    log.debug("jwk: "+rsaJsonWebKey.toJson());
		    JwtClaims claims = new JwtClaims();
		    claims.setIssuer("testing@secure.istio.io");  // who creates the token and signs it
		    claims.setAudience("Audience"); // to whom the token is intended to be sent
//		    claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
		    claims.setExpirationTimeMinutesInTheFuture(EFFECTIVE_TIME/(60*1000));
		    claims.setGeneratedJwtId(); // a unique identifier for the token
		    claims.setIssuedAtToNow();  // when the token was issued/created (now)
		    claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
		    claims.setSubject("subject"); // the subject/principal is whom the token is about
		    claims.setClaim("email","mail@example.com"); // additional claims/attributes about the subject can be added
		    claims.setClaim("tenantId",String.valueOf(tenantId));
		    claims.setClaim("userName",username); 
		    claims.setClaim("userRole",username); 
		    List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
		    claims.setStringListClaim("groups", groups); // multi-valued claims work too and will end up as a JSON array
		    JsonWebSignature jws = new JsonWebSignature();
		    jws.setPayload(claims.toJson());
		    jws.setKey(rsaJsonWebKey.getPrivateKey());
		    log.debug("getPrivateKey: "+Base64.encode(rsaJsonWebKey.getPrivateKey().getEncoded()));
		    log.debug("getPublicKey: "+Base64.encode(rsaJsonWebKey.getPublicKey().getEncoded()));
		    jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
		    jws.setHeader("typ", "JWT");
		    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		    String jwt = jws.getCompactSerialization();
		    log.debug("JWT: " + jwt);
		    Jwt jwtObject = new Jwt();
		    jwtObject.setJwk(rsaJsonWebKey.toJson());
		    jwtObject.setJsonSpec("");
		    jwtObject.setNote(jwt);
		    jwtObject.setOwner(username);
		    jwtObject.setPrivateKey(Base64.encode(rsaJsonWebKey.getPrivateKey().getEncoded()));
		    jwtObject.setPublicKey(Base64.encode(rsaJsonWebKey.getPublicKey().getEncoded()));
		    jwtObject.setTenantId(tenantId);
		    return jwtObject;
		} catch (JoseException e) {
			e.printStackTrace();
			log.error("create jwt error");
			return null;
		}
	}
	
	/**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年12月5日 下午2:44:36
	* @version 1.0
	* @param username
	* @param password
	* @return String
	* @Description authentication
	*/
	public String authentication(String username, String password) {
		log.info("Check username and password");
		User user = checkLogin(username, password);
		if (user == null) {
			log.error("username or password error");
			return null;
		}
		String token = null;
		Jwt jwtdb = getJwtByTenant(user.getTenantId());
		if(jwtdb == null){
			log.info("Create new jwt");
			Jwt jwt = createJwt(username, user.getTenantId());
			if (jwt == null) {
				log.error("create jwt error");
				return null;
			}
			addJwt(jwt.getTenantId(), username, jwt.getPrivateKey(), jwt.getPublicKey(), jwt.getJwk(), jwt.getNote(), jwt.getJsonSpec());
			token = jwt.getNote();
		}else{
			//判断是否是超时的jwt，如果超时则更新不超时返回
			if(jwtdb != null && (System.currentTimeMillis() - jwtdb.getLastUpdated().getTime() >= EFFECTIVE_TIME))
			{
				log.info("Out of effective jwt time");
				Jwt jwt = createJwt(username, user.getTenantId());
				if (jwt == null) {
					log.error("create jwt error");
					return null;
				}
				log.info("Update new jwt");
				jwt.setId(jwtdb.getId());
				updateJwt(jwt);
				return jwt.getNote();
			}
			token = jwtdb.getNote();
		}
		return token;
	  }

	
	/**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年12月5日 下午2:44:55
	* @version 1.0
	* @param request
	* @return JwtContext
	* @throws MalformedClaimException
	* @Description validate Jwt
	*/
	public JwtContext validateJwt(HttpServletRequest request) throws MalformedClaimException{
	 try
	    {
		 String jwt = request.getHeader(HEADER_STRING);
	        if (jwt == null){
	        	log.error("Missing token");
	        	throw new TokenValidationException("Missing token");
	        }
	     jwt = jwt.replace(TOKEN_PREFIX, "");
		 log.debug("jwt is "+jwt);
		 //一段校验，只获取jwt中信息
		 JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
		            .setSkipAllValidators()
		            .setDisableRequireSignature()
		            .setSkipSignatureVerification()
		            .build();
		    JwtContext jwtContext = firstPassJwtConsumer.process(jwt);
		    String userName = jwtContext.getJwtClaims().getStringClaimValue("userName");
		    String tenantId = jwtContext.getJwtClaims().getStringClaimValue("tenantId");
		    if(userName == null && tenantId == null){
		    	log.error("Can not get userName and tenantId from jwt");
		    	return null;
		    }
		   Jwt jwtdb = getJwtByTenantAndOwner(Integer.parseInt(tenantId), userName);
		   if(jwtdb == null ){
			   log.error("Can found jwt from db by tenantId and userName");
			   return null;
		   }
		  // format public key
		  KeyFormat keyFormat = new KeyFormat();
		  PublicKey publickey = keyFormat.getPublicKey(jwtdb.getPublicKey());
		 //二段校验，检验签名是否有效
		    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
		            .setRequireExpirationTime() // the JWT must have an expiration time
		            .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
		            .setRequireSubject() // the JWT must have a subject claim
		            .setExpectedIssuer("testing@secure.istio.io") // whom the JWT needs to have been issued by
		            .setExpectedAudience("Audience") // to whom the JWT is intended for
		            .setVerificationKey(publickey) // verify the signature with the public key
		            .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
		                    new AlgorithmConstraints(ConstraintType.WHITELIST, // which is only RS256 here
		                            AlgorithmIdentifiers.RSA_USING_SHA256))
		            .build(); // create the JwtConsumer instance
	        //  Validate the JWT and process it to the Claims
	        JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
	        log.debug("JWT validation succeeded! " + jwtClaims);
	        return jwtContext;
	    }
	    catch (InvalidJwtException e)
	    {
	        // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
	        // Hopefully with meaningful explanations(s) about what went wrong.
	        log.warn("Invalid JWT! " + e);
	        // Programmatic access to (some) specific reasons for JWT invalidity is also possible
	        // should you want different error handling behavior for certain conditions.
	        // Whether or not the JWT has expired being one common reason for invalidity
	        if (e.hasExpired())
	        {
	            try {
					log.warn("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
				} catch (MalformedClaimException e1) {
					log.error("error messages "+e1);
					e1.printStackTrace();
				}
	        }
	        // Or maybe the audience was invalid
	        if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID))
	        {
	            try {
					log.warn("JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
				} catch (MalformedClaimException e1) {
					log.error("error messages "+e1);
					e1.printStackTrace();
				}
	        }
	    } catch (Exception e) {
	    	log.error("error messages "+e);
			e.printStackTrace();
		}
	return null;
}
		
	 /**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年12月5日 下午2:45:12
	* @version 1.0
	* @param username
	* @param password
	* @return User check Login
	* @Description
	*/
	public User checkLogin(String username, String password) {
		  log.info(username + " login..");
//			String[] base64ReverseArray = password.split("");
//			String tmppassword = "";
//			for (String s : base64ReverseArray)
//				tmppassword = s + tmppassword;
//			password = new String(Base64.decode(tmppassword));
			User user = checkLoginFromLdap(username, password);
			if (user != null) {
				if (username.equals("admin")) {
					user.setPassword(password);
				}
			}
			return user;
	 }
		
	  /**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年12月5日 下午2:45:25
	* @version 1.0
	* @param username
	* @param password
	* @return User
	* @Description check Login From Ldap
	*/
	public User checkLoginFromLdap(String username, String password) {
			LDAPConnection lc = null;
			try {
				lc = connection();
				String attrs[] = { "*" };
				String _dn = dn;
				LDAPSearchResults searchResults = lc.search(_dn, // container to
						1, // search scope 0查自己 1 查下属一级 2 下属全部包含自己
						"(uid=" + username + ")", // search filter
						attrs, // "1.1" returns entry name only
						false); // no attributes are retu
				if (searchResults.hasMore()) {
					LDAPEntry nextEntry = searchResults.next();
					log.debug("user passwrod:"+SystemUtil.MD5(password));
					log.debug("get user password from ldap: " + nextEntry.getAttribute("userPassWord").getStringValue());
					if (!SystemUtil.MD5(password).equalsIgnoreCase(nextEntry.getAttribute("userPassWord").getStringValue())) {
						return null;
					}
					User u = new User();
					u.setAlias(nextEntry.getAttribute("title").getStringValue());
					u.setNote(nextEntry.getAttribute("description").getStringValue());
					u.setPassword(nextEntry.getAttribute("userPassWord").getStringValue());
					u.setTenantId(Integer.valueOf(nextEntry.getAttribute("gidNumber").getStringValue()));
					u.setUserId(nextEntry.getAttribute("sn").getStringValue());
					u.setUserType(nextEntry.getAttribute("employeeType").getStringValue());
					u.setUserGroup(Integer.valueOf(nextEntry.getAttribute("roomNumber").getStringValue()));
					LDAPAttribute businessCategory = nextEntry.getAttribute("businessCategory");
					u.setBusinessCategory(businessCategory!=null?businessCategory.getStringValue():null);
					return u;
				}
			} catch (Exception e) {
				log.error("ldap checkPassword error:--->>", e);
			} finally {
				if (null != lc && lc.isConnected()) {
					try {
						lc.disconnect();
					} catch (LDAPException e) {
						log.error("ldap disconnect error:--->>", e);
					}
				}
			}
			log.info(username + " can not login..");
			return null;
		}
	  
	/**
	* @author zhaorendong
	* @E-mail 13552066077@163.com
	* @date 2018年12月5日 下午2:46:10
	* @version 1.0
	* @return LDAPConnection
	* @throws Exception
	* @Description connection ldap
	*/
	private LDAPConnection connection() throws Exception {
		log.info("\n ldap connection " + url + ":" + port + "  " + user + "  " + dn);
		LDAPConnection lc = new LDAPConnection();
		lc.connect(url, Integer.parseInt(port));
		lc.bind(3, "cn=" + user + "," + dn, pass.getBytes("UTF8"));
		return lc;
	}

	public JwkBean getJwksByDB(){
		List<Jwt> jwts = getJwts();
		log.debug("get jwk from db size is "+jwts.size());
		List<security.org.jwt.been.Jwk> newjwks = new ArrayList<>();
		JwkBean jwkBean = new JwkBean();
		for(Jwt jwt:jwts){
			if(System.currentTimeMillis() - jwt.getLastUpdated().getTime() < EFFECTIVE_TIME){
			String jwk = jwt.getJwk();
			security.org.jwt.been.Jwk jwkObject = JSONUtil.toObject(jwk, security.org.jwt.been.Jwk.class);
			newjwks.add(jwkObject);
			}
		}
		log.debug("get effective jwk from db size is "+newjwks.size());
		jwkBean.setKeys(newjwks);
//		return JSONUtil.getJSONString(jwkBean);
		return jwkBean;
	}
	
	public JwkBean getJwksByMemcache(String userName){
		log.info("get jwk from memcache name "+userName);
		JwkBean jwkBean = new JwkBean();
		String jwksStr = showApi.showQuery(userName);
		if(jwksStr == null){
			//目前逻辑是memcache中没有就返回null，以后如果没有要不要去kem中再次获取再议
			log.info("get jwk from memcache name "+userName+" jwksStr is "+jwksStr);
			return null;
		}else{
			jwkBean = JSONUtil.toObject(jwksStr, JwkBean.class);
		}
		return jwkBean;
	}
	
	public boolean takeJwksToMemcache(String userName,JwkBean jwks){
		try {
			log.info("take jwk to memcache userName "+userName);
			String jwksStr = JSONUtil.getJSONString(jwks);
			if(jwksStr == null){
				log.error("jwks formart error");
				return false;
			}
			return showApi.showAdd(userName, jwksStr);
		} catch (Exception e) {
			log.error("take jwk to memcache userName "+userName+" error "+e.getMessage());
			return false;
		}
	}
	
	public String test() {
		System.out.println(url);
		return "test";

	}
}