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
import security.org.jwt.service.JwtService;

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
	
	 @GetMapping("/api/admin")
	    @PreAuthorize("hasAuthority('admin')")
	    public @ResponseBody
	    Object helloToAdmin(String userId) {
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
	    Object hello() {
	        return jwtService.getJwks();
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
