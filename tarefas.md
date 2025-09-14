# tarefas.md

> **Objetivo:** entregar a uma IA (ou equipe) um roteiro executável **sem ambiguidade** para gerar um microserviço fechado de Autenticação & Autorização usando **Java 21** e **Gradle**. O resultado esperado é um projeto completo (skeleton + código funcional mínimo) que implemente: JWT access tokens curtos + refresh tokens opacos em Redis, rotação de refresh tokens, blacklist (opcional) e endpoints `/login`, `/refresh`, `/logout`, `/me`.

---

## 0) Informação Inicial
Provavelmente você já vai estar em um projeto java 21 e gradle com uma estrutura inicial, basta seguir com as tarefas abaixo.

## 1) Precondições (ambiente do executor)
- Java 21 instalado e `JAVA_HOME` apontando para ele.
- Gradle 8.x ou superior (ou usar Gradle Wrapper gerado pelo projeto).
- Docker instalado (para testes locais com Postgres + Redis) — **opcional** mas recomendado.
- Acesso à linha de comando (bash/sh ou PowerShell) para executar comandos.

> Observação: todas as variáveis sensíveis (chave privada RSA, credenciais DB/Redis) devem ser passadas por variáveis de ambiente no ambiente de execução ou armazenadas em um Secret Manager. Nunca codificar segredos no repositório.

---

## 2) Estrutura de pacotes e arquivos (obrigatório seguir para evitar ambiguidade)
O projeto deve ter a seguinte estrutura de pacotes (namespace base: `com.example.auth` — a IA pode parametrizar, mas use este como padrão se não informado):

```
src/main/java/com/example/auth/
  ├─ config/
  │    └─ SecurityConfig.java
  ├─ controller/
  │    └─ AuthController.java
  ├─ dto/
  │    └─ LoginRequest.java
  │    └─ RefreshRequest.java
  │    └─ TokenResponse.java
  │    └─ UserResponse.java
  ├─ entity/
  │    └─ User.java
  │    └─ Role.java
  │    └─ Permission.java
  ├─ repository/
  │    └─ UserRepository.java
  │    └─ RoleRepository.java
  │    └─ PermissionRepository.java
  ├─ security/
  │    └─ JwtAuthenticationFilter.java
  │    └─ JwtUtil.java
  ├─ service/
  │    └─ AuthService.java
  │    └─ TokenService.java
  │    └─ UserService.java
  ├─ util/
  │    └─ RedisKeys.java
  └─ AuthServiceApplication.java

resources/
  └─ application.yml
```

> **Regra:** os arquivos devem ser Java e nomeados exatamente como acima (sufixos `Service`, `Controller` etc.). Use `UUID` como tipo para `id` das entidades.

---

## 3) Arquivo `application.yml` (esqueleto obrigatório)
Crie `src/main/resources/application.yml` com placeholders que usem variáveis de ambiente. **Não** codifique senhas reais.

```yaml
spring:
  datasource:
    url: ${DB_URL:jdbc:postgresql://localhost:5432/authdb}
    username: ${DB_USER:postgres}
    password: ${DB_PASS:postgres}
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: false
  redis:
    host: ${REDIS_HOST:localhost}
    port: ${REDIS_PORT:6379}

server:
  port: ${SERVER_PORT:8080}

security:
  jwt:
    // caminho para a chave privada em Base64 ou via env var
    private-key: ${JWT_PRIVATE_KEY:}
    public-key: ${JWT_PUBLIC_KEY:}
    access-token-ttl-seconds: ${JWT_ACCESS_TTL:600} # 10 minutos
    refresh-token-ttl-seconds: ${JWT_REFRESH_TTL:604800} # 7 dias

logging:
  level:
    root: INFO
```

---

## 4) Entidades JPA (código exemplo — a IA deve gerar classes completas com imports e anotações)
**Regras fixas:**
- `User` deve ter `@Entity(name = "users")` com campos: `id (UUID, @Id, @GeneratedValue)`, `username (unique)`, `passwordHash`, `enabled`, `createdAt` (timestamptz), `roles` (ManyToMany para Role). Use `Set<Role>`.
- `Role` deve ter `@Entity(name = "roles")` com `name` (ex.: ROLE_ADMIN) e relação ManyToMany com Permission.
- `Permission` deve ter `@Entity(name = "permissions")` com `name` (ex.: product:read).

**Fornecer SQL DDL** (arquivo `schema.sql` opcional) como referência:
```sql
CREATE TABLE users (
  id UUID PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  enabled BOOLEAN DEFAULT true,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE roles (
  id UUID PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE permissions (
  id UUID PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE user_roles (
  user_id UUID REFERENCES users(id),
  role_id UUID REFERENCES roles(id),
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_permissions (
  role_id UUID REFERENCES roles(id),
  permission_id UUID REFERENCES permissions(id),
  PRIMARY KEY (role_id, permission_id)
);
```

---

## 5) Repositórios JPA
- `UserRepository extends JpaRepository<User, UUID>` com método: `Optional<User> findByUsername(String username)`.
- `RoleRepository extends JpaRepository<Role, UUID>`.
- `PermissionRepository extends JpaRepository<Permission, UUID>`.

---

## 6) DTOs (definições obrigatórias)
- `LoginRequest { String username; String password; }` — adicionar `@NotBlank` nas propriedades.
- `RefreshRequest { String refreshToken; }`.
- `TokenResponse { String accessToken; String refreshToken; long expiresIn; }`.
- `UserResponse { UUID id; String username; Set<String> roles; }`.

---

## 7) Service layer — responsabilidades e assinaturas (métodos obrigatórios)
### 7.1) `UserService`
- `Optional<User> findByUsername(String username)`
- `User save(User user)`
- `void createDefaultAdmin()` — método para popular um admin de teste (usar senha `123456` com hash Argon2/bcrypt)

### 7.2) `TokenService` (detalhamento obrigatório)
**Assinatura e comportamento:**
- `String generateAccessToken(User user)`
  - Gera JWT assinado com **RSA/ECDSA** (prefira RSA 2048+ ou ECDSA P-256).
  - Claims obrigatórios:
    - `sub` = usuário.id (UUID string)
    - `iat` = issued at (epoch)
    - `exp` = expire (iat + access-token-ttl-seconds)
    - `roles` = array de strings ex: ["ROLE_USER"]
    - `permissions` = array de strings ex: ["product:read"]
    - `jti` = UUID do token (útil para blacklist)
- `String generateRefreshToken(User user)`
  - Gera token opaco: `UUID.randomUUID().toString()` (ou string com 32+ bytes aleatórios base64url).
  - Salva em Redis com key `refresh:{token}` e value JSON contendo `userId`, `issuedAt`, `expiresAt`, `clientIp` (opcional).
  - TTL no Redis = `refresh-token-ttl-seconds` (7 dias por padrão).
- `boolean validateAccessToken(String token)`
  - Valida assinatura e expiração. Retorna true/false. Se falso, lançar exceção adequada em camadas superiores.
- `Optional<UUID> parseUserIdFromAccessToken(String token)`
  - Retorna `sub` como UUID.
- `boolean validateRefreshToken(String token)`
  - Checa existência no Redis e se não foi revogado.
- `void revokeRefreshToken(String token)`
  - Remove do Redis.
- `TokenResponse rotateRefreshToken(String oldRefreshToken)`
  - Validar `oldRefreshToken` no Redis
  - Gerar novo refresh token
  - Salvar novo token em Redis
  - Deletar o antigo
  - Gerar access token novo e retornar `{accessToken, refreshToken, expiresIn}`

**Formato Redis** (obrigatório):
- Key: `refresh:{token}`
- Value (JSON):
  ```json
  {
    "userId": "<uuid>",
    "issuedAt": 1690000000,
    "expiresAt": 1690604800,
    "meta": { "ip": "1.2.3.4" }
  }
  ```

- **Blacklist opcional (recomendado para logout):**
  - Key: `blacklist:{jti}` value: boolean / timestamp. TTL = remaining lifetime do access token.


### 7.3) `AuthService` (orquestração)
- `TokenResponse login(String username, String password, String clientIp)`
  - Verifica credenciais com `UserService` / `PasswordEncoder`.
  - Se válido, chama `TokenService.generateAccessToken()` e `generateRefreshToken()` e retorna `TokenResponse`.
- `TokenResponse refresh(String refreshToken)`
  - Chama `TokenService.rotateRefreshToken(refreshToken)`.
- `void logout(String refreshToken, Optional<String> accessTokenJti)`
  - Chama `TokenService.revokeRefreshToken()` e adiciona access token `jti` na blacklist se fornecido.

---

## 8) Segurança (config `SecurityConfig.java`) — implementação obrigatória
- Classe `SecurityConfig` com:
  - Anotação `@Configuration` e `@EnableMethodSecurity`.
  - Um bean `PasswordEncoder passwordEncoder()` usando Argon2 (ou BCryptPasswordEncoder). Exemplo:
    ```java
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder();
    }
    ```
  - Um bean `SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtFilter)` configurado assim, em ordem:
    - CSRF disabled (apenas se API REST puro). Documente isso.
    - SessionManagement stateless.
    - Endpoints permitAll(): `/login`, `/refresh`, `/logout`, `/actuator/health`.
    - All other requests authenticated.
    - Adicionar `jwtFilter` antes de `UsernamePasswordAuthenticationFilter`.

> Observação: o filtro JWT deve extrair o token do header `Authorization: Bearer <token>` e, se válido, construir `UsernamePasswordAuthenticationToken` com authorities baseadas em `roles` e `permissions` do token.

---

## 9) `JwtAuthenticationFilter` (detalhes de implementação)
- Estender `OncePerRequestFilter`.
- Lógica:
  1. Ler header `Authorization`. Se ausente, continuar o chain.
  2. Extrair token (substring após "Bearer ").
  3. `tokenService.validateAccessToken(token)` → se inválido, limpar contexto e delegar (ou lançar `AuthenticationException` dependendo do design).
  4. `tokenService.parseUserIdFromAccessToken(token)` → buscar `User` via `UserService` para preencher detalhes se necessário (ou confiar nas claims do token).
  5. Criar `List<GrantedAuthority>` a partir das claims `roles` e `permissions`.
  6. Criar `UsernamePasswordAuthenticationToken(principal, null, authorities)` e setar no `SecurityContextHolder`.

---

## 10) `AuthController` (endpoints e contratos JSON)
- `@RestController @RequestMapping("/api/auth")` (ou simplesmente `/`) — padronizar para `/api/auth`.
- Endpoints:

1) `POST /api/auth/login`
```java
@PostMapping("/login")
public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest req, HttpServletRequest servletReq) {
  String clientIp = servletReq.getRemoteAddr();
  TokenResponse tokens = authService.login(req.getUsername(), req.getPassword(), clientIp);
  return ResponseEntity.ok(tokens);
}
```
- Status: 200 OK + body `{accessToken, refreshToken, expiresIn}`.
- Em erros (bad creds) retornar `401 Unauthorized` com mensagem padronizada.

2) `POST /api/auth/refresh`
- Request `{ "refreshToken": "..." }`.
- Response `{accessToken, refreshToken, expiresIn}`.
- Em refresh inválido -> `401 Unauthorized`.

3) `POST /api/auth/logout`
- Request `{ "refreshToken": "..." }`.
- Response `204 No Content`.
- Efetuar revoke do refresh token e, se header `Authorization` presente, extrair `jti` e incluir em blacklist.

4) `GET /api/auth/me`
- Header `Authorization: Bearer <accessToken>`.
- Response `UserResponse` com `id`, `username`, `roles`.

---

## 11) Rotação do refresh token (requisitos explícitos)
1. O endpoint `/refresh` deve **sempre** invalidar o refresh token usado (deletar do Redis) e **emitir um novo** refresh token armazenado com TTL completo. Isso previne replay attacks.
2. Em caso de tentativa de reuso de um refresh token já invalidado, registrar evento de segurança (possível ataque) e exigir re-login.
3. Implementar a rotação de forma atômica: inserir novo token e somente depois remover o antigo (use operações Redis multi/transaction ou lua script se necessário para garantir atomicidade).

---

## 12) Logout e blacklist de access tokens
- `logout` deve revogar o refresh token imediatamente.
- Se disponível `jti` do access token (extraído do header Authorization), adicionar chave `blacklist:{jti}` com TTL igual ao restante do tempo de vida do token. Assim, mesmo que o access token ainda seja válido, ele será considerado inválido se o `jti` existir na blacklist.
- A verificação da blacklist deve ocorrer no `JwtAuthenticationFilter` **após** validar assinatura/expiração: consultar `blacklist:{jti}` no Redis.

---

## 13) Geração/armazenamento das chaves RSA (instruções operacionais)
- **Local (desenvolvimento):** gerar par RSA com openssl:
  ```bash
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private_key.pem
  openssl rsa -pubout -in private_key.pem -out public_key.pem
  ```
- Converter para base64 (para injetar em env var) se necessário:
  ```bash
  cat private_key.pem | base64 -w0 > private_key_base64.txt
  cat public_key.pem | base64 -w0 > public_key_base64.txt
  ```
- **Produção:** armazenar chave privada em Secret Manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager) e não no sistema de arquivos.
- `application.yml` deve buscar chave via variável de ambiente `JWT_PRIVATE_KEY` (em base64) — se assim preferir, decodificar em tempo de inicialização.

---

## 14) Testes automatizados (tarefas para a IA criar)
- [ ] Criar `AuthControllerIntegrationTest` com `@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)` que execute os fluxos:
  - `login` com usuário válido → verificar 200 e tokens retornados.
  - `GET /api/auth/me` usando access token retornado → 200 e dados corretos.
  - Simular expiração do access token (método: gerar token com TTL curto em teste ou manipular clock) → assert 401.
  - `POST /api/auth/refresh` → obter novo access token + refresh rotation.
  - `POST /api/auth/logout` → tentar usar refresh token após logout -> 401.

- [ ] Criar `TokenServiceTest` com testes unitários de geração/validação de JWT e de armazenamento/remoção de refresh token no Redis (usar testcontainers ou mocks se preferir).

---

## 15) Docker e Docker Compose (para testes locais rápidos)
- **Dockerfile (obrigatório)** no root:
```dockerfile
FROM eclipse-temurin:21-jdk-jammy
ARG JAR_FILE=build/libs/auth-service.jar
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
```
- **docker-compose.yml** (opcional, para desenvolvimento local):
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: authdb
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - 5432:5432
  redis:
    image: redis:7
    ports:
      - 6379:6379
  auth-service:
    build: .
    environment:
      DB_URL: jdbc:postgresql://postgres:5432/authdb
      DB_USER: postgres
      DB_PASS: postgres
      REDIS_HOST: redis
      REDIS_PORT: 6379
      JWT_PRIVATE_KEY: ""
      JWT_PUBLIC_KEY: ""
    ports:
      - 8080:8080
    depends_on:
      - postgres
      - redis
```

---

## 16) Observability e métricas (tarefas opcionais mas recomendadas)
- Incluir Micrometer e configurar endpoint prometheus (se for necessário). Adicionar contadores:
  - `auth.login.success`, `auth.login.failure`, `auth.refresh.success`, `auth.refresh.failure`, `auth.logout`.
- Habilitar Actuator se necessário (`spring-boot-starter-actuator`).

---

## 17) Hardening (tarefas operacionais finais)
- [ ] Forçar HTTPS em produção (config de proxy/load-balancer) e definir `server.ssl` se expor diretamente.
- [ ] Implementar rate-limiting em `/api/auth/login` (recomendado usar `Bucket4j` com Redis backend). Tarefas:
  - Adicionar dependência `com.giffing.bucket4j:bucket4j-spring-boot-starter` ou configurar manualmente.
  - Bloquear IPs com muitas falhas e enviar alertas.
- [ ] Revisão de segurança: não logar tokens, não expor chaves.
- [ ] Rodar SCA (Software Composition Analysis) — Snyk/OWASP Dependency-Check.

---

## 18) Checklist final de aceitação (o que validar manualmente)
- [ ] `POST /api/auth/login` com credenciais válidas retorna `accessToken` (JWT) e `refreshToken` (opaco).
- [ ] Requisição GET a endpoint protegido com `Authorization: Bearer <accessToken>` retorna 200.
- [ ] Após expirar o access token, usando `/api/auth/refresh` com refresh token válido gera novos tokens e o refresh anterior não funciona mais.
- [ ] `POST /api/auth/logout` invalida refresh token e evita novos refreshes.
- [ ] Se usar logout com access token presente, o `jti` é salvo na blacklist e bloqueado até expirar.
- [ ] Senhas estão em hash Argon2/bcrypt no banco.
- [ ] Chave privada RSA não está no repositório, somente via variável de ambiente ou Secret Manager.

---

## 19) Comandos úteis a serem executados (incluir na entrega para a IA)
- Construir e rodar localmente com Gradle wrapper:
  ```bash
  ./gradlew build
  ./gradlew bootRun
  ```
- Executar testes:
  ```bash
  ./gradlew test
  ```
- Gerar chave RSA (desenvolvimento):
  ```bash
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private_key.pem
  openssl rsa -pubout -in private_key.pem -out public_key.pem
  ```
- Converter chave para base64:
  ```bash
  cat private_key.pem | base64 -w0 > private_key.base64
  ```

---

## 20) Observações finais (sem margem para dúvida)
1. **Nome do projeto:** `auth-service` (usar como base para pacotes `com.example.auth`).
2. **Java:** 21 (obrigatório). Gradle (build.gradle obrigatório.
3. **Todas as rotinas de refresh e blacklist devem usar Redis** (não use memória local para produção).
4. **A IA geradora deve criar classes Java completas** com imports, anotações, tratamento de exceções (custom exceptions como `InvalidCredentialsException`, `InvalidRefreshTokenException`) e testes básicos JUnit 5. Não deixe métodos sem implementação.
5. **Toda string que contenha `TODO` NÃO deve permanecer** no código final — a IA deve implementar a lógica ou documentar explicitamente o porquê se não puder implementar.
6. **Entregar um README.md** simples com instruções de como rodar localmente (usar docker-compose), como gerar chaves RSA e como passar variáveis de ambiente.

---

## 21) Entrega esperada (arquivos que devem existir no PR)
- `build.gradle`, `settings.gradle`, `gradlew`, `gradlew.bat`, `gradle/wrapper/*`.
- `src/main/java/...` com todos os pacotes e classes descritas.
- `src/main/resources/application.yml` com placeholders via env vars.
- `Dockerfile` e `docker-compose.yml` (opcional, mas recomendado).
- `README.md` com instruções.
- Testes unitários e integrados no `src/test/java/...`.

---

### FIM — Instrução para a IA executora
Siga este `tarefas.md` **na íntegra e na ordem**. Gere código Java 21, Gradle, e garanta que todas as rotinas estão completas, testadas (pelo menos com testes de integração básicos) e que a aplicação inicia com `./gradlew bootRun` contra Postgres + Redis. Não deixe placeholders nem `TODO` no código entregue.

Se qualquer passo não puder ser realizado (por exemplo, uma dependência específica está desatualizada), atualize a dependência para a versão mais recente compatível com Java 21 e documente a decisão no `README.md` do PR.



