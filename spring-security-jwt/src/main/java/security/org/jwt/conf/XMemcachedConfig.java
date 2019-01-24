package security.org.jwt.conf;

import net.rubyeye.xmemcached.MemcachedClient;
import net.rubyeye.xmemcached.MemcachedClientBuilder;
import net.rubyeye.xmemcached.XMemcachedClientBuilder;
import net.rubyeye.xmemcached.command.BinaryCommandFactory;
import net.rubyeye.xmemcached.impl.KetamaMemcachedSessionLocator;
import security.org.jwt.been.XMemcachedProperties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
* @author zhaorendong
* @E-mail 13552066077@163.com
* @date 2019年1月21日 下午4:06:14
* @version 1.0
* @parameter
* @return
* @since
* @throws 
* @Description
*/

@Configuration
public class XMemcachedConfig {

    @Autowired
    private XMemcachedProperties xMemcachedProperties;

    // 构建builder
    @Bean
    public MemcachedClientBuilder getXMBuilder(){
        MemcachedClientBuilder memcachedClientBuilder = null;
        try{
            String servers = xMemcachedProperties.getServers();
            System.out.println("servers="+servers);
            memcachedClientBuilder = new XMemcachedClientBuilder(servers);
            // 开启/关闭failure模式
            memcachedClientBuilder.setFailureMode(false);
            memcachedClientBuilder.setSanitizeKeys(xMemcachedProperties.isSanitizeKeys());
            memcachedClientBuilder.setConnectionPoolSize(xMemcachedProperties.getPoolSize());
            memcachedClientBuilder.setCommandFactory(new BinaryCommandFactory());
            memcachedClientBuilder.setOpTimeout(3000);
            memcachedClientBuilder.setSessionLocator(new KetamaMemcachedSessionLocator());

            // 诸多XMemcached配置
            return memcachedClientBuilder;
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }

    // client
    @Bean
    public MemcachedClient getXMClient(MemcachedClientBuilder memcachedClientBuilder){
        MemcachedClient memcachedClient = null;
        try{
            memcachedClient = memcachedClientBuilder.build();
            return memcachedClient;
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;

    }
}
