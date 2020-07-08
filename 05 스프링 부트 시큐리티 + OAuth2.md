05 스프링 부트 시큐리티 + OAuth2
=======================
스프링 부트 프레임워크는 인증과 권한에 관련된 강력한 기능인 **스프링 부트 시큐리티**를 제공합니다.         
스프링 부트 시큐리티는 스프링 시큐리티의 번거로운 설정을 간소화 시켜주는 **래핑 프레임워크**입니다.         
        
스프링 (부트) 시큐리티는 십여 년간 보안 노하우를 쌓아 와서    
**기본적인 틀 안에서 원하는 대로 인증, 권한 처리를 편리하게 관리할 수 있습니다.**         
따라서 보안 문제는 스프링 부트 시큐리티에 맡겨두고 우리는 핵심 로직만 개발하면 됩니다.          
      
일반적인 인증은 ID 와 PW 로 이루어집니다.         
반면 회원 가입 과정을 생략하고 빠른 인증을 제공하는 인증방식인 OAuth2도 많이 사용합니다.       
우리는 이 2가지 방법을 배울 것입니다.     
    
우리는 특별히 스프링 부트 1.5 버전에서의 스프링 부트 시큐리티부터 알아보겠습니다.         
```1.5 버전```에서 지원하는 시큐리티와 OAuth2 API를 사용해 소셜 미디어 인증을 빠르고 쉽게 적용하겠습니다.     
```2.0 버전```부터는 스프링 시큐리티 내부에 OAuth2 API가 포함되는 등 구조가 많이 바뀌었습니다.   
```1.5 버전```을 통해 전체적인 적용방식을 익히고 2.0 버전으로 어떻게 업그레이드 되는지 알아봅시다.   

[1. 배경지식 소개](#1-배경지식-소개)    
[2. 스프링 부트 시큐리티 + OAuth2 설계하기](#2-스프링-부트-시큐리티--oauth2-설계하기)     
[3. 스프링 부트 시큐리티 + OAuth2 의존성 설정하기](#3-스프링-부트-시큐리티--OAuth2-의존성-설정하기)    

* 스프링 부트 시큐리티 + OAuth2 구현하기 
* 스프링 부트 2.0 기반의 OAuth2 설정하기 

# 1. 배경지식 소개
스프링 부트 시큐리티는 **스프링 시큐리티에 스타터를 제공해 더 빠른 설정을 지원**하는 프로젝트입니다.           
빠르게 설정하고 적용하는 것도 중요하지만    
기본적으로 **시큐리티와 OAuth2가 무엇이며 어떻게 인증이 수행되는지 확실하게 이해해보겠습니다.**      
     
## 1.1. 스프링 부트 시큐리티  
스프링 부트 시큐리티에서 가장 중요한 개념은 **인증** 과 **권한 부여**입니다.      
* **인증 :**  사용자(클라이언트)가 애플리케이션의 특정 동작에 관하여 허락(인증)된 사용자인지 확인하는 절차    
* **권한 부여 :** 데이터나 프로그램 등의 특정 자원이나 서비스에 접근할 수 있는 권한을 허용하는 것  
       
전통적인 인증 방식으로 사용자명과 비밀번호로 인증하는 ```크리덴셜 기반 인증 방식```이 있습니다.       
OTP와 같이 추가적인 인증 방식을 도입해 한번에 2가지 방법으로 인증하는 ```이중 인증 방식```도 있습니다.       
소셜미디어를 사용해 편리하게 인증하는 ```OAuth2 인증 방식```도 최근에는 필수적으로 쓰이고 있습니다.       
    
## 1.2. OAuth2   
OAuth는 **토큰을 사용한 범용적인 방법의 인증을 제공**하는 표준 인증 프로토콜입니다.         
이 프로토콜은 서드파티를 위한 범용적인 인증 표준입니다.  
```
서드파티 : 제 3자라는 뜻, 여기서는 프로토콜이나 관련된 사항이 아닌 다른 리소스를 말합니다.   
```      
   
OAuth2에서 제공하는 승인 타입은 총 4가지 입니다.    

1. **권한 부여 코드 승인 타입(Authorization Code Grant Type) :**    
클라이언트가 다른 사용자 대신 특정 리소스에 접근을 요청할 때 사용됩니다.       
리소스 접근을 위한 사용자명과 비밀번호, 권한 서버에 요청해서 받은 권한 코드를 함께 활용하여     
리소스에 대한 액세스 토큰을 받으면 이를 인증에 이용하는 방식입니다.     
2. **암시적 승인 타입 (Implicit Grant Type) :**         
권한 부여 코드 승인 타입과 권한 코드 교환 단계 없이 액세스 토큰을 즉시 반환받아 이를 인증에 이용하는 방식입니다.     
3. **리소스 소유자 암호 자격 증명 승인 타입(Resource Owner Password Credentials Grant Type) :**      
클라이언트가 암호를 사용하여 액세스 토큰에 대한 사용자의 자격 증명을 교환하는 방식입니다.       
4. **클라이언트 자격 증명 승인 타입(Client Credentials Grant Type) :**      
클라이언트가 컨텍스트 외부에서 액세스 토큰을 얻어 특정 리소스에 접근을 요청할 때 사용하는 방식입니다.   
   
눈여겨볼 방식은 ```1. 권한 부여 코드 승인 타입(Authorization Code Grant Type)``` 입니다.   
왜냐하면 페이스북, 구글, 카카오 등의 소셜 미디어들이 웹 서버 형태의 클라이언트를 지원하는 데 이 방식을 사용하기 때문입니다.   
이 방식은 장기 액세스 토큰을 사용하여 사용자 인증을 처리합니다.   
   
[사진]     
         
위 시퀀스 다이어그램에 표시된 각 주체에 대한 예입니다.          
           
* 리소스 주인 : 인증이 필요한 사용자                   
* 클라이언트 : 웹사이트                      
* 권한 서버 : 페이스북/구글/카카오 서버                 
* 리소스 서버 : 페이스북/구글/카카오 서버               
         
1. 클라이언트가 파라미터로 **클라이언트 ID**, **리다이렉트 URI**, **응답 타입**을 코드(code)로 지정하여 권한 서버에 전달합니다.       
정상적으로 인증이 되면 권한 부여 코드를 클라이언트에 보냅니다.   
(응답 타입은 code, token이 사용가능합니다. 응답 타입이 token 일 때가 암시적 승인 타입에 해당합니다.)    
   
2. 성공적으로 권한 부여 코드를 받은 클라이언트는 권한 부여 코드를 사용하여 액세스 토큰을 권한 서버에 추가로 요청합니다.    
이때 필요한 파라미터는 **클라이언트 ID**, **클라이언트 비밀번호**, **리다이렉트 URI**, **인증 타입**입니다.  
   
3. 마지막으로 응답받은 액세스 토큰을 사용하여 리소스 서버에 사용자의 데이터를 요청합니다.  

즉, ```클라이언트 ID로 SNS 응답``` -> ```ID/PW 로 인증``` -> ```인증 받은 후 필요한 데이터 요청```   
   
```사용자명 + 비밀번호``` 인증 방식은 저장된 사용자명과 비밀번호가 같은지 한 번만 요청하면 되지만 **OAuth2 방식은 최소 3번 요청합니다.**  
하지만 ```OAuth2```는 회원 가입 없이 이미 사용하는 소셜 미디어 계정으로 인증하기 때문에       
사용자 입장에서는 더욱 편리하게 로그인 처리할 수 있습니다.   
서비스 측면에서는 회원 가입 관련 기능을 축소키시고 소셜에서 제공하는 User 정보를 가져올 수 있어 편리합니다.   
     
여기서 ```권한 부여 코드 승인 타입```의 흐름을 이해하는 것은 굉장히 중요합니다.   
스프링이 아닌 다른 어떤 라이브러리도 이 흐름을 바탕으로 코드를 구현하기 때문에    
정확히 파악하는 것만으로도 소셜 인증 구현을 위한 준비 중 절반을 진행했다고 해도 과언이 아닙니다.   

***
# 2. 스프링 부트 시큐리티 + OAuth2 설계하기  
     
[사진]       
    
1. 사용자가 애플리케이션에 접속하면 해당 사용자에 대한 이전 로그인 정보(세션)의 유무를 체크합니다.     
2. 세션이 있으면 그대로 세션을 사용하고, 없으면 OAuth2 인증 과정을 거치게 됩니다.      
3. 이메일을 키값으로 사용하여 이미 가입된 사용자인지 체크합니다.         
이미 가입도니 사용자라면 등록된 정보를 반환하여 요청한 URL로 접근을 허용하고,       
아니라면 새롭게 User 정보를 저장하는 과정을 진행합니다.       
4. 각 소셜 미디어에서 제공하는 User 정보가 다르기 때문에 소셜 미디어에 따라 User 객체를 생성한 후 DB에 저장합니다.     
   
* 세션이 있거나 4번까지 성공한 사용자는 요청한 URL로의 접근을 허용합니다.    

[사진]   
    
먼저 각 소셜 미디어의 타입을 갖고 있는 ```SocialType``` 클래스 및 객체를 만들겠습니다.   

1. ```com.web.domain.enums``` 디렉토리에서 ```SocialType``` 클래스를 생성해줍니다.   
2. 아래와 같은 코드를 입력해줍니다.  

**SocialType**
```java
package com.web.domain.enums;

public enum SocialType {
    FACEBOOK("facebook"),
    GOOGLE("google"),
    KAKAO("kakao");

    private final String ROLE_PREFIX = "ROLE_";
    private String name;

    SocialType(String name){
        this.name = name;
    }

    public String getRoleType(){
        return ROLE_PREFIX + name.toUpperCase();
    }

    public String getValue(){return name;}

    public boolean isEquals(String authority){
        return this.getRoleType().equals(authority);
    }
}
```
각 소셜 미디어의 정보를 나타내는 ```SocialType``` enum을 생성했씁니다.      
```getRoleType()``` 메서드는 ```ROLE_*``` 형식으로 소셜 미디어의 권한명을 생성합니다.       
enum을 사용해 권한 생성로직을 공통 코드로 처리하여 중복 코드를 줄일 수 있습니다.       
   
로그인과 관련하여 인증 및 권한이 추가되므로 ```User``` 클래스의 User 테이블에 컬럼을 추가합니다.      
```OAuth2``` 인증으로 제공받는 키값인 ```principal```과 어떤 소셜 미디어로 인증 받았는지 여부를 구분해주는 ```socialType```컬럼도 추가합니다.     
   
**User**
```java
package com.web.domain;

import com.web.domain.enums.SocialType;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@Entity
@Table
public class User implements Serializable {

    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idx;

    @Column
    private String name;

    @Column
    private String password;

    @Column
    private String email;

    @Column
    private String principal;
    
    @Column
    @Enumerated(EnumType.STRING)
    private SocialType socialType;
    
    @Column
    private LocalDateTime createdDate;

    @Column
    private LocalDateTime updateDate;

    @Builder
    public User(String name, String password, String email, String principal, SocialType socialType, LocalDateTime createdDate, LocalDateTime updateDate) {
        this.name = name;
        this.password = password;
        this.email = email;
        this.principal = principal;
        this.socialType = socialType;
        this.createdDate = createdDate;
        this.updateDate = updateDate;
    }
}

```

***
# 3. 스프링 부트 시큐리티 + OAuth2 의존성 설정하기   
이제 커뮤니티 게시판 프로젝트에 의존성을 추가해서 진행하겠습니다.        
```build.gradle``` 에 ```spring security OAuth2```를 추가합니다.              
```OAuth2``` 의존성 안에 ```security```까지 포함되어 있어서 따로 ```security``` 의존성을 부여할 필요가 없습니다.              
     
처음에는 spring framework ```1.5 버전``` 으로 적용시켜보고 ```2.0```버전으로 마이그레이션을 진행해보겠습니다.     
```build.gradle```에 아래와 같은 코드로 수정해줍시다.     
   
**build.gradle**  
```gradle
buildscript {
	ext{
		springBootVersion = '1.5.14.RELEASE'
	}
	repositories {
		mavenCentral()
		jcenter()
	}
	dependencies {
		classpath("org.springframework.boot:spring-boot-gradle-plugin:${springBootVersion}")
	}
}

apply plugin: 'java'
apply plugin: 'eclipse'
apply plugin: 'org.springframework.boot'
apply plugin: 'io.spring.dependency-management'

group = 'com.web'
version = '0.0.1-SNAPSHOT'
sourceCompatibility = 1.8

repositories {
	mavenCentral()
	jcenter()
}

dependencies {
	compile('org.springframework.security.oauth:spring-security-oauth2')
	compile('org.springframework.boot:spring-boot-starter-web')
	compile('org.springframework.boot:spring-boot-starter-thymeleaf')
	compile('org.springframework.boot:spring-boot-starter-data-jpa')
	runtime('com.h2database:h2')
	runtime('org.springframework.boot:spring-boot-devtools')
	compileOnly('org.projectlombok:lombok')
	testCompile('org.springframework.boot:spring-boot-starter-test')
}

test {
	useJUnitPlatform()
}    
```


***
# 4. 스프링 부트 시큐리티 + OAuth2 구현하기    
이제까지 스프링 부트를 사용하여 설정을 빠르게 적용한 것처럼        
시큐리티, OAuth2도 적절한 프로퍼티 설정값만 지정하면 빠르고 편리하게 적용할 수 있습니다.      
   
프로젝트를 구현하기 전에 페이스북, 구글, 카카오의 개발자센터에서 ```클라이언트 ID``` 와 ```secret```을 발급 받아야 합니다.     
이 부분은 따로 링크를 걸어둘 터이니 해당 방법대로 발급받은 뒤 다음 내용을 계속 진행해주시기 바랍니다.       
  
[링크]  

1. SNS 프로퍼티 설정 및 바인딩  
2. 시큐리티 + OAuth2 설정하기  
3. 어노테이션 기반으로 User 정보 불러오기  
4. 인증 동작 확인하기  
5. 페이지 권한 분리하기  

페이스북 ID : 564162601158748
PW: dd56c82cf93b958f1d00e30b355df0c2
구글 ID : 531083614299-40lvfkln6kmihd62igmag5551ook21bo.apps.googleusercontent.com   
pw: Q0sFH7FeoZKfbx910iTIpNmm     
카카오 : 0a7ca146321bc1d63285c916ab12134c     

## 4.1. SNS 프로퍼티 설정 및 바인딩  
소셜 미디어 연동을 위해 필요한 기본적인 프로퍼티 정보는 다음과 같습니다.  

* **clientId :** OAuth 클라이언트 사용자명. OAuth 공급자가 클라이언트를 식별하는 데 사용합니다.  
* **clientSecret :** OAuth 클라이언트 시크릿 키값        
* **accessTokenUri :** 액세스 토큰을 제공하는 OAuth 의 URI   
* **scope :** 리소스에 대한 접근 범위를 지정하는 문자열. 쉼표로 구분하여 여러개 지정할 수 있다.   
* **userInfoUri :** 사용자의 개인정보 조회를 위한 URI     
    
모든 리소스 정보는 YAML 파일에 저장하겠습니다.       
YAML 파일에 저장하여 사용하면 정보를 매핑하기 훨씬 수월합니다.     
각 소셜 미디어로부터 발급받은 ```clientId``` 와 ```clientSecret```은 개인마다 고유한 값입니다.     

**형식**
```yml
facebook:
  client:
    clientId: <your-client-id>
    clientSecret: <your-secret>
    accessTokenUri: https://graph.facebook.com/oauth/access_token
    userAuthorizationUri: https://www.facebook.com/dialog/oauth?display=popup
    tokenName: oauth_token
    authenticationScheme: query
    clientAuthenticationScheme: form
    scope: email
  resource:
    userInfoUri: https://graph.facebook.com/me?fileds=id,name,email,link
    
google:
  client:
    clientId: <your-client>
    clientSecret: <your-secret>
    accessTokenUri: https://accounts.google.com/o/oauth2/token
    userAuthorizationUri: https://accounts.google.com/o/oauth2/auth
    scope: email, profile
  resource:
    userInfoUri: https://www.googleapis.com/oauth2/v2/userinfo

kakao:
  client:
    clientId: <your-client-id>
    accessTokenUri: https://kauth.kakao.com/oauth/token
    userAuthorizationUri: https://kauth.kakao.com/oauth/authorize
  resource:
      userInfoUri: https://kapi.kakao.com/v1/user/me
```
```
sns:
	client:
    		clientId:
    		clientSecret:
	resource:
```
선행 접두사를 소셜 미디어명으로 정했고 각 소셜 미디어마다 프로퍼티값을 ```client```와 ```resource```로 나누었습니다.      
```client``` 프로퍼티는 소셜 미디어에서 토큰 인증을 위해 필요한 키 값을 제공합니다. ```(clinetId 와 clientSecret)```     
```resource``` 프로퍼티는 사용자의 정보를 가져올 ```URL```을 제공합니다.      
    
```
    userInfoUri: https://graph.facebook.com/me?fileds=id,name,email,link
```
페이스북은 특이하게 ```scope``` 프로퍼티를 사용하지 않고 ```userInfoUri```의 파라미터로 원하는 정보를 요청합니다.      
원래 OAuth2 라이브러리는 ```client.scope``` 에 요청 정보를 담아서 가져갑니다.    
페이스북 API 규격은 파라미터 형식으로 되어 있어서 ```client.scope``` 로 정보를 요청하면 적용되지 않는 문제가 있으므로   
```fileds=id,name,email,link```와 같이 파라미터로 넣어서 처리했습니다.   
    
개인 마다의 ```clientId``` 와 ```clientSecret``` 이 따로 소유하고 있으므로 위 코드에서 알맞은 코드로 넣어줍시다.       
___
매핑 방식은 ```@ConfigurationProperties``` 어노테이션을 사용하며, 소셜 미디어에 따라 각각의 프로퍼티값을 바인딩할 수 있습니다.   
    
**ClientResources**    
```java
package com.web.oauth;

import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

public class ClientResources {

    @NestedConfigurationProperty
    private AuthorizationCodeResourceDetails client =
            new AuthorizationCodeResourceDetails();

    @NestedConfigurationProperty
    private ResourceServerProperties resource = new ResourceServerProperties();

    public AuthorizationCodeResourceDetails getClient() {
        return client;
    }

    public ResourceServerProperties getResource() {
        return resource;
    }

    // 위에 두개는 @Getter 를 사용해도 될 것 같다.

}
```
위 클래스는 각 소셜 미디어의 client 와 resource 프로퍼티 값을 매핑한다.    

```java
    @NestedConfigurationProperty
```
```@NestedConfigurationProperty``` 는 해당 필드가 단일값이 아닌 중복으로 바인딩된다고 표시하는 어노테이션입니다.   
소셜 미디어 3곳의 프로퍼티를 각각 바인딩하므로 ```@NestedConfigurationProperty``` 붙여줍시다.   
          
```java
    @NestedConfigurationProperty
    private AuthorizationCodeResourceDetails client =
            new AuthorizationCodeResourceDetails();
```
```
    clientId: 
    clientSecret: 
    accessTokenUri: 
    userAuthorizationUri: 
    tokenName:
    authenticationScheme:
    clientAuthenticationScheme:
    scope:
```   
```AuthorizationCodeResourceDetails``` 객체는 ```client:```프로퍼티를 기준으로 하위의 키/값을 매핑합니다.      
즉 해당 객체 안에는 위와 같은 값들을 저장할 수 있는 필드(변수) 들이 존재합니다.        
     
```java
    @NestedConfigurationProperty
    private ResourceServerProperties resource = new ResourceServerProperties();
```
```
resource:
      userInfoUri:
```    
```ResourceServerProperties``` 객체는 원래 OAuth2 리소스값을 매핑하는 데 사용하지만          
여기서는 ```userInfoUri:``` 밖에 없으니 회원 정보를 얻는 ```userInfoUri```값을 받는데 사용했습니다.      
    
___
     
```SecurityConfig.java``` 에 각 소셜 미디어의 프로퍼티값을 호출하는 빈을 등록하겠습니다.   

**SecurityConfig**
```java
package com.web.config;

import com.web.oauth.ClientResources;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {

    @Bean
    @ConfigurationProperties("facebook")
    public ClientResources facebook() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("google")
    public ClientResources google() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("kakao")
    public ClientResources kakao() {
        return new ClientResources();
    }

}
```
소셜 미디어 리소스 정보는 시큐리티 설정에서 사용하기 때문에 빈으로 등록했고    
3개의 소셜 미디어 프로퍼티를 ```@ConfigurationProperties``` 어노테이션에 접두사를 사용하여 바인딩 했습니다.   
만약 ```@ConfigurationProperties``` 어노테이션이 없었다면 일일이 프로퍼티값을 불러와야 했습니다.   

이해가 안되면 아래 url 을 통해 복습하자!!   
https://github.com/kwj1270/TIL_FIRST_SPRINGBOOT2/blob/master/02%20%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8%20%ED%99%98%EA%B2%BD%20%EC%84%A4%EC%A0%95.md#44-configurationproperties-%EC%82%B4%ED%8E%B4%EB%B3%B4%EA%B8%B0


## 4.2. 시큐리티 + OAuth2 설정하기    
시큐리티 OAuth2를 설정하겠습니다.   
시큐리티 부분을 먼저 설정하고 OAuth2를 적용시킬 **필터를 시큐리티 설정에 추가하겠습니다.**       
시큐리티 OAuth2 간의 연관된 설정에 유의해서 살펴보기 바랍니다.       
    
**SecurityConfig**    
```java

```








