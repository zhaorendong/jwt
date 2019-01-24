package security.org.jwt.been;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2019年1月21日 下午4:05:05
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/
@Component
@ConfigurationProperties(prefix = "memcached")
public class XMemcachedProperties {

    private String servers;
    private int poolSize;
    private boolean sanitizeKeys;
    private boolean openCache;

    public boolean isOpenCache() {
        return openCache;
    }

    public void setOpenCache(boolean openCache) {
        this.openCache = openCache;
    }

    public String getServers() {
        return servers;
    }

    public void setServers(String servers) {
        this.servers = servers;
    }

    public int getPoolSize() {
        return poolSize;
    }

    public void setPoolSize(int poolSize) {
        this.poolSize = poolSize;
    }

    public boolean isSanitizeKeys() {
        return sanitizeKeys;
    }

    public void setSanitizeKeys(boolean sanitizeKeys) {
        this.sanitizeKeys = sanitizeKeys;
    }
}