//package tt.config;
//import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
//import org.apache.shiro.cas.CasFilter;
//import org.apache.shiro.cas.CasSubjectFactory;
//import org.apache.shiro.spring.LifecycleBeanPostProcessor;
//import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
//import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
//import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
//import org.apache.shiro.web.servlet.SimpleCookie;
//import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
//import org.crazycake.shiro.RedisManager;
//import org.crazycake.shiro.RedisSessionDAO;
//import org.jasig.cas.client.session.SingleSignOutFilter;
//import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.boot.web.servlet.FilterRegistrationBean;
//import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.PropertySource;
//import org.springframework.web.filter.DelegatingFilterProxy;
//
//import javax.servlet.Filter;
//import java.util.HashMap;
//import java.util.LinkedHashMap;
//import java.util.Map;
//
///**
// * shiro+cas配置
// */
//@PropertySource({"classpath:application.properties"})
//@Configuration
//public class ShiroCasConfiguration {
//
//    private static final Logger logger = LoggerFactory.getLogger(ShiroCasConfiguration.class);
//    private final String keyPrefix ="jsession";
//
////    @Bean
////    public EhCacheManager getEhCacheManager() {
////        EhCacheManager em = new EhCacheManager();
////        em.setCacheManagerConfigFile("classpath:ehcache-shiro.xml");
////        return em;
////    }
//
//    @Bean(name = "myShiroCasRealm")
//    public MyShiroCasRealm myShiroCasRealm() {
//        MyShiroCasRealm realm = new MyShiroCasRealm();
//        return realm;
//    }
//
//    /**
//     * 注册单点登出listener
//     *
//     * @return
//     */
//    @Bean
//    public ServletListenerRegistrationBean singleSignOutHttpSessionListener() {
//        ServletListenerRegistrationBean bean = new ServletListenerRegistrationBean();
//        bean.setListener(new SingleSignOutHttpSessionListener());
////        bean.setName(""); //默认为bean name
//        bean.setEnabled(true);
//        //bean.setOrder(Ordered.HIGHEST_PRECEDENCE); //设置优先级
//        return bean;
//    }
//
//    /**
//     * 注册单点登出filter
//     *
//     * @return
//     */
//    @Bean
//    public FilterRegistrationBean singleSignOutFilter() {
//        FilterRegistrationBean bean = new FilterRegistrationBean();
//        bean.setName("singleSignOutFilter");
//        bean.setFilter(new SingleSignOutFilter());
//        bean.addUrlPatterns("/*");
//        bean.setEnabled(true);
//        return bean;
//    }
//
//    /**
//     * 注册DelegatingFilterProxy（Shiro）
//     * @return
//     */
//    @Bean
//    public FilterRegistrationBean delegatingFilterProxy() {
//        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
//        filterRegistration.setFilter(new DelegatingFilterProxy("shiroFilter"));
//        //  该值缺省为false,表示生命周期由SpringApplicationContext管理,设置为true则表示由ServletContainer管理
//        filterRegistration.addInitParameter("targetFilterLifecycle", "true");
//        filterRegistration.setEnabled(true);
//        filterRegistration.addUrlPatterns("/*");
//        return filterRegistration;
//    }
//
//
//    /**
//     *
//     * @return
//     */
//    @Bean(name = "lifecycleBeanPostProcessor")
//    public LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
//        return new LifecycleBeanPostProcessor();
//    }
//
//    /**
//     *
//     * @return
//     */
//    @Bean
//    public DefaultAdvisorAutoProxyCreator getDefaultAdvisorAutoProxyCreator() {
//        DefaultAdvisorAutoProxyCreator daap = new DefaultAdvisorAutoProxyCreator();
//        daap.setProxyTargetClass(true);
//        return daap;
//    }
//
//    /**
//     *
//     * @param myShiroCasRealm
//     * @return
//     */
//    @Bean(name = "securityManager")
//    public DefaultWebSecurityManager getDefaultWebSecurityManager(MyShiroCasRealm myShiroCasRealm) {
//        DefaultWebSecurityManager dwsm = new DefaultWebSecurityManager();
//        dwsm.setRealm(myShiroCasRealm);
////      <!-- 用户授权/认证信息Cache, 采用EhCache 缓存 -->
////        dwsm.setCacheManager(getEhCacheManager());
//        // 指定 SubjectFactory
//        dwsm.setSubjectFactory(new CasSubjectFactory());
//        dwsm.setSessionManager(redisSessionManager());
//        return dwsm;
//    }
//
//    /**
//     *
//     * @param securityManager
//     * @return
//     */
//    @Bean
//    public AuthorizationAttributeSourceAdvisor getAuthorizationAttributeSourceAdvisor(DefaultWebSecurityManager securityManager) {
//        AuthorizationAttributeSourceAdvisor aasa = new AuthorizationAttributeSourceAdvisor();
//        aasa.setSecurityManager(securityManager);
//        return aasa;
//    }
//
//    @Bean
//    public ShiroDialect shiroDialect() {
//        return new ShiroDialect();
//    }
//
//    /**
//     * CAS过滤器
//     * @param casServerUrlPrefix
//     * @param shiroServerUrlPrefix
//     * @return
//     */
//    @Bean(name = "casFilter")
//    public CasFilter getCasFilter(@Value("${cas.server-url}") String casServerUrlPrefix,
//                                  @Value("${cas.service}") String shiroServerUrlPrefix) {
//        String loginUrl = casServerUrlPrefix + "/login?service=" + shiroServerUrlPrefix + "/cas";
//        CasFilter casFilter = new CasFilter();
//        casFilter.setName("casFilter");
//        casFilter.setEnabled(true);
//        // 登录失败后跳转的URL，也就是 Shiro 执行 CasRealm 的 doGetAuthenticationInfo 方法向CasServer验证tiket
//        casFilter.setFailureUrl(loginUrl);// 我们选择认证失败后再打开登录页面
//        return casFilter;
//    }
//
//    /**
//     * ShiroFilter<br/>
//     * 注意这里参数中的 StudentService 和 IScoreDao 只是一个例子，因为我们在这里可以用这样的方式获取到相关访问数据库的对象，
//     * 然后读取数据库相关配置，配置到 shiroFilterFactoryBean 的访问规则中。实际项目中，请使用自己的Service来处理业务逻辑。
//     * @param securityManager
//     * @param casFilter
//     * @param casServerUrlPrefix
//     * @param shiroServerUrlPrefix
//     * @param loginSuccessUrl
//     * @param unauthorizedUrl
//     * @return
//     */
//    @Bean(name = "shiroFilter")
//    public ShiroFilterFactoryBean getShiroFilterFactoryBean(DefaultWebSecurityManager securityManager,
//                                                            CasFilter casFilter,
//                                                            @Value("${cas.server-url}") String casServerUrlPrefix,
//                                                            @Value("${cas.service}") String shiroServerUrlPrefix,
//                                                            @Value("${cas.service.loginSuccessUrl}") String loginSuccessUrl,
//                                                            @Value("${cas.service.unauthorizedUrl}") String unauthorizedUrl) {
//        String loginUrl = casServerUrlPrefix + "/login?service=" + shiroServerUrlPrefix + "/cas";
//        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
//        // 必须设置 SecurityManager
//        shiroFilterFactoryBean.setSecurityManager(securityManager);
//        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
//        shiroFilterFactoryBean.setLoginUrl(loginUrl);
//        // 登录成功后要跳转的连接
//        shiroFilterFactoryBean.setSuccessUrl(loginSuccessUrl);
//        shiroFilterFactoryBean.setUnauthorizedUrl(unauthorizedUrl);
//        // 添加casFilter到shiroFilter中
//        Map<String, Filter> filters = new HashMap<>();
//        filters.put("casFilter", casFilter);
//        // filters.put("logout",logoutFilter());
//        shiroFilterFactoryBean.setFilters(filters);
//
//        loadShiroFilterChain(shiroFilterFactoryBean);
//        return shiroFilterFactoryBean;
//    }
//
//    /**
//     * 加载shiroFilter权限控制规则（从数据库读取然后配置）,角色/权限信息由MyShiroCasRealm对象提供doGetAuthorizationInfo实现获取来的
//     * @param shiroFilterFactoryBean
//     */
//    private void loadShiroFilterChain(ShiroFilterFactoryBean shiroFilterFactoryBean) {
//
//        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
//
//        // authc：该过滤器下的页面必须登录后才能访问，它是Shiro内置的一个拦截器org.apache.shiro.web.filter.authc.FormAuthenticationFilter
//        // anon: 可以理解为不拦截
//        // user: 登录了就不拦截
//        // roles["admin"] 用户拥有admin角色
//        // perms["permission1"] 用户拥有permission1权限
//        // filter顺序按照定义顺序匹配，匹配到就验证，验证完毕结束。
//        // url匹配通配符支持：? * **,分别表示匹配1个，匹配0-n个（不含子路径），匹配下级所有路径
//
//        //1.shiro集成cas后，首先添加该规则
//        filterChainDefinitionMap.put("/cas", "casFilter");
//        //logut请求采用logout filter
//
//        //2.不拦截的请求
//        filterChainDefinitionMap.put("/css/**", "anon");
//        filterChainDefinitionMap.put("/js/**", "anon");
//        filterChainDefinitionMap.put("/login", "anon");
//        filterChainDefinitionMap.put("/admin/logout", "anon");
//        filterChainDefinitionMap.put("/error", "anon");
//        //3.拦截的请求（从本地数据库获取或者从casserver获取(webservice,http等远程方式)，看你的角色权限配置在哪里）
//        filterChainDefinitionMap.put("/user", "authc"); //需要登录
//        filterChainDefinitionMap.put("/user/add/**", "authc,roles[admin]"); //需要登录，且用户角色为admin
//        filterChainDefinitionMap.put("/user/delete/**", "authc,perms[\"user:delete\"]"); //需要登录，且用户有权限为user:delete
//
//        //4.登录过的不拦截
//        filterChainDefinitionMap.put("/**", "user");
//
//        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
//    }
//
//    /**
//     * 使用自定义redis缓存管理器
//     * 解决redis中key为非字符串乱码问题
//     * @return
//     */
//    @Bean(name = "myRedisCacheManager")
//    public MyRedisCacheManager myRedisCacheManager() {
//        MyRedisCacheManager myRedisCacheManager = new MyRedisCacheManager();
//        return myRedisCacheManager;
//    }
//
//    /**
//     * RedisSessionDAO shiro sessionDao层的实现 通过redis
//     * 使用的是shiro-redis开源插件
//     */
//    @Bean
//    public RedisSessionDAO redisSessionDAO() {
//        RedisSessionDAO redisSessionDAO = new RedisSessionDAO();
//        redisSessionDAO.setRedisManager(redisManager());
//        redisSessionDAO.setKeyPrefix(keyPrefix);
//        return redisSessionDAO;
//    }
//
//    /**
//     * 配置shiro redisManager
//     * 使用的是shiro-redis开源插件
//     * @return
//     */
//    @Bean(name="redisManager")
//    public RedisManager redisManager() {
//        RedisManager redisManager = new RedisManager();
//        RedisProperties redisProperties = SpringUtils.getBean(RedisProperties.class);
//        redisManager.setHost(redisProperties.getHostName());
//        redisManager.setPort(redisProperties.getPort());
//        // 配置缓存过期时间
//        redisManager.setExpire(Integer.parseInt(String.valueOf(redisProperties.getExpire())));
//        redisManager.setTimeout(redisProperties.getTimeout());
//        redisManager.setPassword(redisProperties.getPassword());
//        return redisManager;
//    }
//    /**
//     * shiro session的管理
//     */
//    @Bean(name = "redisSessionManager")
//    public DefaultWebSessionManager redisSessionManager() {
//        CasProperties casProperties = SpringUtils.getBean(CasProperties.class);
//        ShiroProperties shiroProperties = SpringUtils.getBean(ShiroProperties.class);
//        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
//        sessionManager.setSessionDAO(redisSessionDAO());
//        //会话超时时间，单位：毫秒
//        sessionManager.setGlobalSessionTimeout(casProperties.getSessionExpireTime() * 60 * 1000);
//        //当跳出SHIRO SERVLET时如ERROR-PAGE容器会为JSESSIONID重新分配值导致登录会话丢失
//        sessionManager.setSessionIdCookie(shrioCookie());
//        // 删除过期的session
//        sessionManager.setDeleteInvalidSessions(true);
//        // 去掉URL中的JSESSIONID
//        sessionManager.setSessionIdUrlRewritingEnabled(false);
//        // 是否定时检查session
//        sessionManager.setSessionValidationSchedulerEnabled(true);
//        //定时清理失效会话, 清理用户直接关闭浏览器造成的孤立会话,单位为毫秒
//        sessionManager.setSessionValidationInterval(shiroProperties.getSessionValidationInterval() * 60 * 1000);
//        return sessionManager;
//    }
//
//    /**
//     * cookie 属性设置
//     */
//    public SimpleCookie shrioCookie()
//    {
//        ShiroProperties shiroProperties = SpringUtils.getBean(ShiroProperties.class);
//        SimpleCookie cookie = new SimpleCookie("shiroCasCookie");
//        //如果是单点登录，各个系统要设置相同的父域名public.com,否则会出现每进入一个子系统都会生成一个session，
//        //也就是session没有实现共享，在退出后，子系统中用户还有残留！
//        cookie.setDomain("public.com");
//        //JSESSIONID的path为/用于多个系统共享JSESSIONID
//        cookie.setPath(shiroProperties.getPath());
//        //浏览器中通过document.cookie可以获取cookie属性，设置了HttpOnly=true,在脚本中就不能得到cookie，可以避免cookie被盗用
//        cookie.setHttpOnly(shiroProperties.isHttpOnly());
//        /*maxAge=-1表示浏览器关闭时失效此Cookie*/
//        cookie.setMaxAge(shiroProperties.getMaxAge() * 24 * 60 * 60);
//        return cookie;
//    }
//
//}