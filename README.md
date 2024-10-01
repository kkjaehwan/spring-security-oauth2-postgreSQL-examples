# spring-security-oauth2-postgreSQL-examples

Spring OAuth2 Authorization Server with PostgresSQL Initialization Project.

## SecurityConfig

In this project, you are setting up the configuration of spring-boot-starter-oauth2-authorization-server in application.yml

In practice, when you configure a project with application.yml, it does not work normally.

All settings must be made through **SecurityConfig**.

The information in application.yml is used to set up **SecurityConfig** through **Oauth2Properties**.

## DB

I'm using PostgreSQL. Please set it up in application.yml.

## client-secret

spring.security.oauth2.authorizationserver.client.oidc-client.registration.client-secret is being encrypted through **EnvironmentVariableEncryptionConfig**.

If the client-secret is not encrypted, it is automatically encrypted when you start the project and the application.yml will be updated.

## Husky, Spotless

I'm forcing Code Conventions using Spotless through Husky.

Please run `npm install` after receiving the project.

If there is a problem with Spotless when committing, please run `mvn spotless:apply`.

The format will be changed after 'mvn spotless:apply', so please add the updates again(`git add .`).

# spring-security-oauth2-postgreSQL-examples

Spring OAuth2 Authorization Server with PostgresSQL 초기 설정 프로젝트입니다.

## SecurityConfig

이 프로젝트에서 application.yml에서 spring-boot-starter-oauth2-authorization-server를 설정하고 있지만

실제로는 application.yml로 프로젝트를 구성 할 시 정상 동작을 하지 않습니다.

모든 설정은 **SecurityConfig**을 통해 진행해야 합니다.

application.yml의 정보는 **OAuth2Properties**을 통해 **SecurityConfig**를 설정 할 때 사용됩니다.

## DB

PostgreSQL을 사용하고 있습니다. application.yml에서 설정을 해주세요.

## client-secret

**EnvironmentVariableEncryptionConfig**를 통해 spring.security.oauth2.authorizationserver.client.oidc-client.registration.client-secret를 암호화 하고 있습니다.

암호화가 안되어 있는 경우 자동으로 암호화 되고 application.yml이 업데이트 됩니다.

## Husky, Spotless

허스키를 통해 Spotless를 강제하고 있습니다.

`npm install`를 프로젝트를 받은 후 실행해 주세요.

commit시 Spotless가 문제가 있는 경우 `mvn spotless:apply`를 실행해주세요.

`mvn spotless:apply`후 포맷이 변경 되니 반드시 add(`git add .`)를 다시 해주세요.
