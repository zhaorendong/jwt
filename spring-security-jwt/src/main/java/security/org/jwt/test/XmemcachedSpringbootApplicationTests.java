package security.org.jwt.test;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import security.org.jwt.util.ShowApi;

@RunWith(SpringRunner.class)
@SpringBootTest
public class XmemcachedSpringbootApplicationTests {

    @Autowired
    private ShowApi showApi;

    @Test
    public void contextLoads() {

        String key = "goods_name";
        String value = "apple";
        showApi.showAdd(key, value);
        System.out.println(showApi.showQuery(key));

    }

}
