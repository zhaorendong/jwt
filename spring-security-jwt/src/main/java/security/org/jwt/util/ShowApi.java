package security.org.jwt.util;
import net.rubyeye.xmemcached.MemcachedClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2019年1月21日 下午4:07:35
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/
@Service
public class ShowApi {

    @Autowired
    private MemcachedClient memcachedClient;

    /**
     * 新增
     * @param key
     * @param value
     */
    public boolean showAdd(String key, String value){
        try {
          return  memcachedClient.set(key, 0, value);
        }catch (Exception e){
            e.printStackTrace();
        	return false;
        }
    }

    public String showQuery(String key){
        try {
            return memcachedClient.get(key);
        }catch (Exception e){
            e.printStackTrace();
        }
        return "";
    }
}