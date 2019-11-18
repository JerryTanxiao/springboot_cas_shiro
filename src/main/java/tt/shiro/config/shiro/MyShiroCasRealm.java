package tt.shiro.config.shiro;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import tt.shiro.modules.user.dao.PermissionMapper;
import tt.shiro.modules.user.dao.RoleMapper;
import tt.shiro.modules.user.dao.UserMapper;
import tt.shiro.modules.user.dao.entity.Permission;
import tt.shiro.modules.user.dao.entity.Role;
import tt.shiro.modules.user.dao.entity.User;
import javax.annotation.PostConstruct;
import java.util.Set;

public class MyShiroCasRealm extends CasRealm {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private RoleMapper roleMapper;

    @Autowired
    private PermissionMapper permissionMapper;



    private static final Logger logger = LoggerFactory.getLogger(MyShiroCasRealm.class);

    @Value("${cas.server-url}")
    public  String casServerUrlPrefix;

    @Value("${cas.service}")
    public  String shiroServerUrlPrefix;

    @PostConstruct
    public void initProperty(){
        // cas server地址
        setCasServerUrlPrefix(casServerUrlPrefix);
        // 客户端回调地址
        setCasService(shiroServerUrlPrefix + "/cas");
    }

    /**
     * 1、CAS认证 ,验证用户身份
     * 2、将用户基本信息设置到会话中(不用了，随时可以获取的)
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
        //获取用户名 密码 第二种方式
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
        String username = usernamePasswordToken.getUsername();
        String password = new String(usernamePasswordToken.getPassword());
        //从数据库查询用户信息
        User user = this.userMapper.findByUserName(username);
        //可以在这里直接对用户名校验,或者调用 CredentialsMatcher 校验
        if (user == null) {
            throw new UnknownAccountException("用户名或密码错误！");
        }
        //这里将 密码对比 注销掉,否则 无法锁定  要将密码对比 交给 密码比较器
        //if (!password.equals(user.getPassword())) {
        //    throw new IncorrectCredentialsException("用户名或密码错误！");
        //}
        if ("1".equals(user.getState())) {
            throw new LockedAccountException("账号已被锁定,请联系管理员！");
        }

        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(),new MyByteSource(user.getUsername()),getName());
        return info;
    }

    /**
     * 权限认证，为当前登录的Subject授予角色和权限
     * 本例中该方法的调用时机为需授权资源被访问时
     * 并且每次访问需授权资源时都会执行该方法中的逻辑，这表明本例中默认并未启用AuthorizationCache
     * 如果连续访问同一个URL（比如刷新），该方法不会被重复调用，Shiro有一个时间间隔（也就是cache时间，在ehcache-shiro.xml中配置），超过这个时间间隔再刷新页面，该方法会被执行
     */

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("查询权限方法调用了！！！");

        //获取用户
        String username = (String)SecurityUtils.getSubject().getPrincipal();
        //从数据库查询用户信息
        User user = this.userMapper.findByUserName(username);

        //获取用户角色
        Set<Role> roles =this.roleMapper.findRolesByUserId(user.getUid());
        //添加角色
        SimpleAuthorizationInfo authorizationInfo =  new SimpleAuthorizationInfo();
        for (Role role : roles) {
            authorizationInfo.addRole(role.getRole());
        }

        //获取用户权限
        Set<Permission> permissions = this.permissionMapper.findPermissionsByRoleId(roles);
        //添加权限
        for (Permission permission:permissions) {
            authorizationInfo.addStringPermission(permission.getPermission());
        }

        return authorizationInfo;
    }

}