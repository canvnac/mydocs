对AuthorizingRealm的方法进行了重写，现在以角色做权限的区分。
欲要同时使用角色和权限来做限制，请参考官方文档。

# pom.xml

```bash
<!-- start: Apache Shiro所需的jar包-->
<dependency>
  <groupId>org.apache.shiro</groupId>
  <artifactId>shiro-core</artifactId>
  <version>1.2.2</version>
</dependency>
<dependency>
  <groupId>org.apache.shiro</groupId>
  <artifactId>shiro-web</artifactId>
  <version>1.2.2</version>
</dependency>
<dependency>
  <groupId>org.apache.shiro</groupId>
  <artifactId>shiro-spring</artifactId>
  <version>1.2.2</version>
</dependency>
<!-- start: Apache Shiro所需的jar包-->

```

# web.xml

```bash
<!-- Shiro配置 -->
<filter>
  <filter-name>shiroFilter</filter-name>
  <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>
<filter-mapping>
  <filter-name>shiroFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>

```

# applicationContext-shiro.xml

```bash
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:aop="http://www.springframework.org/schema/aop"
       xmlns:tx="http://www.springframework.org/schema/tx"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="
http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
http://www.springframework.org/schema/tx http://www.springframework.org/schema/tx/spring-tx.xsd
http://www.springframework.org/schema/aop http://www.springframework.org/schema/aop/spring-aop.xsd
http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd">

    <!-- 配置权限管理器 -->
    <bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
        <!-- ref对应我们写的realm  MyShiro -->
        <property name="realm" ref="myShiro"/>
        <!-- 使用下面配置的缓存管理器 -->
        <property name="cacheManager" ref="cacheManager"/>
    </bean>

    <bean id="myShiro" class="cn.canlnac.OnlineCourseFronten.service.MyShiro"/>

    <!-- 配置shiro的过滤器工厂类，id- shiroFilter要和我们在web.xml中配置的过滤器一致 -->
    <bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
        <!-- 调用我们配置的权限管理器 -->
        <property name="securityManager" ref="securityManager"/>
        <!-- 配置我们的登录请求地址 -->
        <property name="loginUrl" value="/login"/>
        <!-- 配置我们在登录页登录成功后的跳转地址，如果你访问的是非/login地址，则跳到您访问的地址 -->
        <property name="successUrl" value="/user"/>
        <!-- 如果您请求的资源不再您的权限范围，则跳转到/403请求地址 -->
        <property name="unauthorizedUrl" value="/403"/>
        <!-- 权限配置 -->
        <property name="filterChainDefinitions">
            <value>
                /login=anon
                /index/user=roles[student]
                /index/teach=roles[teacher]
                <!-- anon表示此地址不需要任何权限即可访问 -->
                <!--/static/**=anon-->
                <!--&lt;!&ndash; perms[user:query]表示访问此连接需要权限为user:query的用户 &ndash;&gt;-->
                <!--/user=perms[user:query]-->
                <!--&lt;!&ndash; roles[manager]表示访问此连接需要用户的角色为manager &ndash;&gt;-->
                <!--/user/add=roles[manager]-->
                <!--/user/del/**=roles[admin]-->
                <!--/user/edit/**=roles[manager]-->
                <!--&lt;!&ndash;所有的请求(除去配置的静态资源请求或请求地址为anon的请求)都要通过登录验证,如果未登录则跳到/login&ndash;&gt;-->
                <!--/** = authc-->
            </value>
        </property>
    </bean>

    <bean id="cacheManager" class="org.apache.shiro.cache.MemoryConstrainedCacheManager" />
    <bean id="lifecycleBeanPostProcessor" class="org.apache.shiro.spring.LifecycleBeanPostProcessor" />

</beans>

```

# MyShiro.java

```bash
package cn.canlnac.OnlineCourseFronten.service;

import cn.canlnac.OnlineCourseFronten.entity.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

/**
 * 登录认证 及 权限认证 类
 * Created by can on 2016/12/8.
 */
@Transactional
@Component(value = "MyShiro")
public class MyShiro extends AuthorizingRealm{
    @Autowired
    private UserService userService;

    /**
     * 权限认证
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //获取登录时的用户名
        String loginName=(String) principalCollection.fromRealm(getName()).iterator().next();
        //到数据库查是否有此对象
        User user=userService.findByUsername(loginName);
        if(user!=null){
            //权限信息对象info,用来存放查出的用户的所有的角色（role）及权限（permission）
            SimpleAuthorizationInfo info=new SimpleAuthorizationInfo();
            //用户的角色集合
            Set roles = new HashSet();
            roles.add(user.getUserStatus());
            info.setRoles(roles);
            return info;
        }
        return null;
    }

    /**
     * 登录认证
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //UsernamePasswordToken对象用来存放提交的登录信息
        UsernamePasswordToken token=(UsernamePasswordToken) authenticationToken;
        //查出是否有此用户
        User user=userService.findByUsername(token.getUsername());
        //判断用户是否存在，并且密码是否正确
        if (user!=null && new String(token.getPassword()).equals(user.getPassword())){
            Session session = SecurityUtils.getSubject().getSession();
            session.setAttribute("userName",user.getUsername());
            session.setAttribute("id",user.getId());
            session.setAttribute("userStatus",user.getUserStatus());
            //将此用户存放到登录认证info中
            return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
        }
        return null;
    }
}

```

# LoginController.java

```bash
package cn.canlnac.OnlineCourseFronten.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created by can on 2016/12/7.
 */
@Controller
@RequestMapping("/")
public class LoginController {

    /**
     * 登陆
     * @param userName
     * @param password
     * @return
     */
    @RequestMapping(value = "login")
    public String login(@RequestParam(value = "userName")String userName, @RequestParam(value = "password")String password){
        try {
            //输入判断
            if (!userName.equals("") && !password.equals("")) {
                //使用权限工具进行用户登陆，失败则抛异常
                SecurityUtils.getSubject().login(new UsernamePasswordToken(userName,password));
                //登录成功
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                System.out.println("用户:"+userName+"于"+sdf.format(new Date())+"登陆成功");
                Session session = SecurityUtils.getSubject().getSession();
                //userStatus:用户角色
                String userStatus = (String) session.getAttribute("userStatus");
                //不同角色跳转不同页面
                if(userStatus.equals("admin")){
                    return "success_admin";
                } else if (userStatus.equals("teacher")){
                    return "success_taacher";
                } else {
                    return "success_student";
                }
            }
        } catch (AuthenticationException e) {
            System.out.println(e);
            //抛出异常，登陆失败
            return "redirect:/index/user";
        } finally {
            return "redirect:/index/user";
        }
    }

    /**
     * 退出
     * @param
     * @return
     */
    @RequestMapping(value="/logout")
    public String logout(RedirectAttributes redirectAttributes){
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Session session = SecurityUtils.getSubject().getSession();
        System.out.println("用户:"+session.getAttribute("userName")+"于"+sdf.format(new Date())+"退出");
        //使用权限管理工具进行用户的退出，跳出登录，给出提示信息
        SecurityUtils.getSubject().logout();
        redirectAttributes.addFlashAttribute("message", "您已安全退出");
        return "redirect:/";
    }
}

```
