package security.org.jwt.ctrl;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import security.org.jwt.been.Account;
import security.org.jwt.been.JwkBean;
import security.org.jwt.been.JwkMemcache;
import security.org.jwt.service.JwtService;
import security.org.jwt.util.AjaxReponse;
import security.org.jwt.util.ShowApi;

/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2018年11月29日 下午3:42:55
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/
@RestController
public class OauthController {
	private static final Logger log = Logger.getLogger(OauthController.class);
	
	@Autowired
	private JwtService jwtService;
	@Autowired
	private ShowApi showApi;
	
	 @GetMapping("/api/admin")
	    @PreAuthorize("hasAuthority('admin')")
	    public @ResponseBody
	    Object helloToAdmin(String userId) {
		 
		  	String key = "goods_name";
	        String value = "apple";
	        showApi.showAdd(key, value);
	        String value1 = "apple1";
	        boolean status = showApi.showAdd(key, value1);
	        System.out.println(status);
	        System.out.println(showApi.showQuery(key));
	        System.out.println(showApi.showQuery("333"));
	        System.out.println(showApi.showQuery(key));
	        return "Hello World! You are ADMIN ";
	    }

	    @GetMapping("/api/hello")
	    @PreAuthorize("hasAuthority('user')")
	    public @ResponseBody
	    Object hello(String userId) {
	        return "Hello World! You have valid token";
	    }

	    @GetMapping("/oauth/key")
	    public @ResponseBody
	    Object getJwks(String userName) {
	        return jwtService.getJwksByMemcache(userName);
//	    	return jwtService.getJwksByDB();
	    }
	    
	    @PostMapping("/oauth/jwks")
//	    public AjaxReponse takeJwks(@RequestBody String jwkMemcache) {
	    public AjaxReponse takeJwks(@RequestBody JwkMemcache jwkMemcache) {
	        boolean status = jwtService.takeJwksToMemcache(jwkMemcache.getName(), jwkMemcache.getJwkBean());
//	    	System.out.println(jwkMemcache);
//	    	 boolean status = false;
	        if(status){
	        	log.info("Take Jwks to Memcache Success");
	        	return new AjaxReponse(1, "Take Jwks to Memcache Success");
	        }else{
	        	log.error("Take Jwks to Memcache Failed");
	        	return new AjaxReponse(-1, "Take Jwks to Memcache Failed");
	        }
	    }
	    
	    @PostMapping("/login")
	    public Object login(HttpServletResponse response, @RequestBody Account account) throws IOException {
//	            String jwt = JwtUtil.generateToken(account.getUsername());
//	            String jwt = jwtService.createJwt(account.getUsername());
	          String jwt = jwtService.authentication(account.getUsername(), account.getPassword());
	          if(jwt != null){
	        	  Map<String, String> token = new HashMap<>();
	        	  token.put("token", jwt);
	        	  return token;
	          }else {
		            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
		        }
	    }
	    
}
