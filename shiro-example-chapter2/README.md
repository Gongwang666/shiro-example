# Shiro_身份验证       Junit测试
### 身份验证
> 在应用中谁能证明他就是他本人。一般提供如他们的身份ID一些标识信息来表明他就是他本人，如提供身份证，用户名/密码来证明。在shiro中，用户需要提供principals （身份）和credentials（证明）给shiro，从而应用能验证用户身份：

##### principals：
> 身份，即主体的标识属性，可以是任何东西，如用户名、邮箱等，唯一即可。一个主体可以有多个principals，但只有一个Primary principals，一般是用户名/密码/手机号。

##### credentials：
> 证明/凭证，即只有主体知道的安全值，如密码/数字证书等。

##### 最常见的principals和credentials组合就是用户名/密码了。接下来先进行一个基本的身份认证。

##### 另外两个相关的概念是之前提到的Subject及Realm，分别是主体及验证主体的数据源。


## 2.2  环境准备
### 本文使用Maven构建，因此需要一点Maven知识。首先准备环境依赖： 

# pom.xml文件    
```xml    
    <?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <artifactId>shiro-example</artifactId>
        <groupId>com.github.zhangkaitao</groupId>
        <version>1.0-SNAPSHOT</version>
    </parent>
    <modelVersion>4.0.0</modelVersion>

    <artifactId>shiro-example-chapter2</artifactId>
    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.9</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>1.7.25</version>
        </dependency>
        <dependency>
            <groupId>commons-logging</groupId>
            <artifactId>commons-logging</artifactId>
            <version>1.2</version>
        </dependency>
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-core</artifactId>
            <version>1.2.2</version>
        </dependency>

        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>5.1.25</version>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid</artifactId>
            <version>0.2.23</version>
        </dependency>


    </dependencies>


</project>
```

##  2.3  登录/退出

### 1、首先准备一些用户身份/凭据（shiro.ini）
```ini
   [users]  
    zhang=123  
    wang=123  
```

==此处使用ini配置文件，通过[users]指定了两个主体：zhang/123、wang/123。==

### 2、测试用例（com.github.zhangkaitao.shiro.chapter2.LoginLogoutTest）

```java
   @Test
   public void testHelloworld() {
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<org.apache.shiro.mgt.SecurityManager> factory =
                new IniSecurityManagerFactory("classpath:shiro.ini");

        //2、得到SecurityManager实例 并绑定给SecurityUtils
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");

        try {
            //4、登录，即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            //5、身份验证失败
        }

        Assert.assertEquals(true, subject.isAuthenticated()); //断言用户已经登录

        //6、退出
        subject.logout();
    }
```    

##### 2.1、首先通过==new IniSecurityManagerFactory==并指定一个ini配置文件来==创建一个SecurityManager工厂==；

##### 2.2、接着获取SecurityManager并绑定到SecurityUtils，==这是一个全局设置，设置一次即可；==

##### 2.3、通过SecurityUtils得到Subject，其会自动绑定到当前线程；==如果在web环境在请求结束时需要解除绑定；然后获取身份验证的Token，如用户名/密码；==

##### 2.4、调用subject.login方法进行登录，其会自动委托给SecurityManager.login方法进行登录；

##### 2.5、如果身份验证失败请捕获AuthenticationException或其子类，常见的如： DisabledAccountException（禁用的帐号）、LockedAccountException（锁定的帐号）、UnknownAccountException（错误的帐号）、ExcessiveAttemptsException（登录失败次数过多）、IncorrectCredentialsException （错误的凭证）、ExpiredCredentialsException（过期的凭证）等，具体请查看其继承关系；对于页面的错误消息展示，最好使用如“用户名/密码错误”而不是“用户名错误”/“密码错误”，防止一些恶意用户非法扫描帐号库；

##### 2.6、最后可以调用subject.logout退出，其会自动委托给SecurityManager.logout方法退出。

---

## 2.4  身份认证流程
![image](http://dl2.iteye.com/upload/attachment/0094/0173/8d639160-cd3e-3b9c-8dd6-c7f9221827a5.png)

### 流程如下：

> 1、首先调用Subject.login(token)进行登录，其会自动委托给Security Manager，调用之前必须通过SecurityUtils. setSecurityManager()设置；
> 
> 2、SecurityManager负责真正的身份验证逻辑；它会委托给Authenticator进行身份验证；
> 
> 3、Authenticator才是真正的身份验证者，Shiro API中核心的身份认证入口点，此处可以自定义插入自己的实现；
> 
> 4、Authenticator可能会委托给相应的AuthenticationStrategy进行多Realm身份验证，默认ModularRealmAuthenticator会调用AuthenticationStrategy进行多Realm身份验证；
> 
> 5、Authenticator会把相应的token传入Realm，从Realm获取身份验证信息，如果没有返回/抛出异常表示身份验证失败了。此处可以配置多个Realm，将按照相应的顺序及策略进行访问。

---

## 2.5  Realm

---

**Realm：域，Shiro从从Realm获取安全数据（==如用户、角色、权限==），就是说SecurityManager要验证用户身份，==那么它需要从Realm获取相应的用户进行比较以确定用户身份是否合法==；也需要==从Realm得到用户相应的角色/权限进行验证用户是否能进行操作；可以把Realm看成DataSource，即安全数据源==。如我们之前的ini配置方式将使用org.apache.shiro.realm.text.IniRealm。**

##### org.apache.shiro.realm.Realm接口如下： 

```
    String getName(); //返回一个唯一的Realm名字  
    boolean supports(AuthenticationToken token); //判断此Realm是否支持此Token  
    AuthenticationInfo getAuthenticationInfo(AuthenticationToken token)  
     throws AuthenticationException;  //根据Token获取认证信息  
```
### 单Realm配置
##### 1、自定义Realm实现（com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1）：  

```
    public class MyRealm1 implements Realm {  
        @Override  
        public String getName() {  
            return "myrealm1";  
        }  
        @Override  
        public boolean supports(AuthenticationToken token) {  
            //仅支持UsernamePasswordToken类型的Token  
            return token instanceof UsernamePasswordToken;   
        }  
        @Override  
        public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {  
            String username = (String)token.getPrincipal();  //得到用户名  
            String password = new String((char[])token.getCredentials()); //得到密码  
            if(!"zhang".equals(username)) {  
                throw new UnknownAccountException(); //如果用户名错误  
            }  
            if(!"123".equals(password)) {  
                throw new IncorrectCredentialsException(); //如果密码错误  
            }  
            //如果身份认证验证成功，返回一个AuthenticationInfo实现；  
            return new SimpleAuthenticationInfo(username, password, getName());  
        }  
    }   
```

### 2、ini配置文件指定自定义Realm实现(shiro-realm.ini)  

```
#声明一个realm  
myRealm1=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1  
#指定securityManager的realms实现  
securityManager.realms=$myRealm1 
```

### 3、测试用例请参考com.github.zhangkaitao.shiro.chapter2.LoginLogoutTest的testCustomRealm测试方法，只需要把之前的shiro.ini配置文件改成shiro-realm.ini即可。


---
## 多Realm配置
### 1、ini配置文件（shiro-multi-realm.ini）  

```
#声明一个realm  
myRealm1=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1  
myRealm2=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm2  
#指定securityManager的realms实现  
securityManager.realms=$myRealm1,$myRealm2 
```
**securityManager会按照==realms指定的顺序进行身份认证==。==此处我们使用显示指定顺序的方式指定了Realm的顺序，如果删除“securityManager.realms=$myRealm1,$myRealm2”，那么securityManager会按照realm声明的顺序进行使用（即无需设置realms属性，其会自动发现）==，当我们显示指定realm后，其他没有指定realm将被忽略，如“securityManager.realms=$myRealm1”，那么myRealm2不会被自动设置进去。**

### 2、测试用例请参考com.github.zhangkaitao.shiro.chapter2.LoginLogoutTest的testCustomMultiRealm测试方法。


---
## Shiro默认提供的Realm!

![image](http://dl2.iteye.com/upload/attachment/0094/0175/34062d4e-8ac5-378a-a9e2-4845f0828292.png)

> 以后一般继承AuthorizingRealm（授权）即可；其继承了AuthenticatingRealm（即身份验证），而且也间接继承了CachingRealm（带有缓存实现）。其中主要默认实现如下：
> 
> org.apache.shiro.realm.text.IniRealm：[users]部分指定用户名/密码及其角色；[roles]部分指定角色即权限信息；
> 
> org.apache.shiro.realm.text.PropertiesRealm： user.username=password,role1,role2指定用户名/密码及其角色；role.role1=permission1,permission2指定角色及权限信息；
> 
> org.apache.shiro.realm.jdbc.JdbcRealm：通过sql查询相应的信息，如“select password from users where username = ?”获取用户密码，“select password, password_salt from users where username = ?”获取用户密码及盐；“select role_name from user_roles where username = ?”获取用户角色；“select permission from roles_permissions where role_name = ?”获取角色对应的权限信息；也可以调用相应的api进行自定义sql；

---


## JDBC Realm使用

**1、数据库及依赖**
```
<dependency>  
    <groupId>mysql</groupId>  
    <artifactId>mysql-connector-java</artifactId>  
    <version>5.1.25</version>  
</dependency>  
<dependency>  
    <groupId>com.alibaba</groupId>  
    <artifactId>druid</artifactId>  
    <version>0.2.23</version>  
</dependency>
```
**2、到数据库shiro下建三张表：users（用户名/密码）、user_roles（用户/角色）、roles_permissions（角色/权限），具体请参照shiro-example-chapter2/sql/shiro.sql；并添加一个用户记录，用户名/密码为zhang/123；**



**3、ini配置（shiro-jdbc-realm.ini）**

```
jdbcRealm=org.apache.shiro.realm.jdbc.JdbcRealm  
dataSource=com.alibaba.druid.pool.DruidDataSource  
dataSource.driverClassName=com.mysql.jdbc.Driver  
dataSource.url=jdbc:mysql://localhost:3306/shiro  
dataSource.username=root  
#dataSource.password=  
jdbcRealm.dataSource=$dataSource  
securityManager.realms=$jdbcRealm  
```

> 1、变量名=全限定类名会自动创建一个类实例
> 
> 2、变量名.属性=值 自动调用相应的setter方法进行赋值
> 
> 3、$变量名 引用之前的一个对象实例 
> 
> 4、测试代码请参照com.github.zhangkaitao.shiro.chapter2.LoginLogoutTest的testJDBCRealm方法，和之前的没什么区别。
