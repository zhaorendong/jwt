package security.org.jwt;

import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import java.io.IOException;
import java.util.HashMap;



/*
    https://auth0.com/blog/securing-spring-boot-with-jwts/
	https://github.com/auth0-blog/spring-boot-jwts
	https://github.com/szerhusenBC/jwt-spring-security-demo
*/

@SpringBootApplication
@MapperScan(value = "security.org.jwt.mapping")
public class Application {

//    @GetMapping("/api/admin")
//    @PreAuthorize("hasAuthority('ADMIN_USER')")
//    public @ResponseBody
//    Object helloToAdmin(String userId) {
//        return "Hello World! You are ADMIN ";
//    }
//
//    @GetMapping("/api/hello")
//    @PreAuthorize("hasAuthority('GROUP1_USER')")
//    public @ResponseBody
//    Object hello(String userId) {
//        return "Hello World! You have valid token";
//    }
//
//    @PostMapping("/login")
//    public Object login(HttpServletResponse response,
//                      @RequestBody Account account) throws IOException {
//        if(isValidPassword(account)) {
//            String jwt = JwtUtil.generateToken(account.username);
//            return new HashMap<String,String>(){{
//                put("token", jwt);
//            }};
//        }else {
//            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
//        }
//    }


//    private boolean isValidPassword(Account ac) {
//        //we just have 2 hardcoded user
//        if ("admin".equals(ac.username) && "admin".equals(ac.password)
//                || "user".equals(ac.username) && "user".equals(ac.password)) {
//            return true;
//        }
//        return false;
//    }


//    public static class Account {
//        public String username;
//        public String password;
//    }
	
	@Bean(name = "sqlSessionFactory")
	SqlSessionFactoryBean sqlSessionFactory(DataSource dataSource)
	{
		SqlSessionFactoryBean ssfb = new SqlSessionFactoryBean();
		ssfb.setDataSource(dataSource);
		ssfb.setTypeAliasesPackage("security.org.jwt.domain");
		return ssfb;
	}


    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
        
    }
}