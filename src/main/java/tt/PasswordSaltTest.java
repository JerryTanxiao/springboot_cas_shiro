package tt;

import tt.shiro.config.shiro.MyByteSource;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;

/**
 * @Version
 * @Author tan.jie
 * @Created 2019年11月14  21:32:54
 * @Description <p>
 * @Modification <p>
 * Date Author Version Description
 * <p>
 * 2019年11月14  JerryTan  给 密码进行 加密加盐  盐值默认为 用户名
 */
public class PasswordSaltTest {
    public static void main(String[] args) {
        System.out.println(m5("123456", "admin"));//085de60f32b004402326e5ee425a6167
    }
    public static final String m5(String password,String salt){
        //加密方式
        String hashAlgorithName="MD5";
        //盐 为了即使相同的密码不同的盐加密后的结果也不同
        ByteSource bytesSalt =new MyByteSource(salt);
        //密码
        Object source = password;
        //加密次数
        int hashIterations=2;
        SimpleHash result = new SimpleHash(hashAlgorithName, source, bytesSalt, hashIterations);
        return result.toString();
    }
}
