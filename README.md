# Bài tập JWT: Spring Boot 3 + Spring Security 6 + Nimbus

Triển khai ví dụ trong `D:\ute\28-9\04_JWT.pdf` (trang 15–34).
Thay thư viện **JJWT (`io.jsonwebtoken`)** trong slide bằng **Nimbus JOSE + JWT**;
không thay định dạng JWT. Dự án dùng Java 17 trở lên, Spring Boot 3.4.5,
Security 6, JPA, MySQL và Nimbus 10.0.2. Không cần Lombok.

## 1. Chạy ứng dụng

Cần JDK 17+ và MySQL đang chạy. Maven Wrapper tải Maven/dependency trong lần chạy đầu.

Tạo database bằng MySQL client:

```sql
CREATE DATABASE IF NOT EXISTS jwt_springboot3
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Trong PowerShell, cấu hình và chạy:

```powershell
Set-Location 'D:\ute\28-9'
$env:DB_USERNAME = 'root'
$env:DB_PASSWORD = Read-Host 'Nhap mat khau MySQL'
# Sinh 32 byte ngẫu nhiên rồi mã hóa Base64, KHÔNG dùng khóa ví dụ cố định.
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$env:JWT_SECRET = [Convert]::ToBase64String($bytes)
& 'D:\ute\28-9\mvnw.cmd' spring-boot:run
```

Nếu database ở máy/cổng khác, đặt `DB_URL` (JDBC MySQL URL). Cấu hình nằm tại
`D:\ute\28-9\src\main\resources\application.properties`.
Không ghi khóa và mật khẩu thực vào Git. Đổi khóa sẽ làm token cũ mất hiệu lực.

Mở **http://localhost:8005/login.html**, đăng ký, đăng nhập và xem hồ sơ/danh sách người dùng.
Các trang HTML là tài nguyên công khai; dữ liệu hồ sơ chỉ lấy được khi JWT hợp lệ.

## 2. API theo bài giảng

| Method | Endpoint | Yêu cầu |
|---|---|---|
| POST | `/auth/signup` | JSON `fullName`, `email`, `password` |
| POST | `/auth/login` | JSON `email`, `password` |
| GET | `/users/me` | `Authorization: Bearer <token>` |
| GET | `/users` hoặc `/users/` | `Authorization: Bearer <token>` |

Đăng ký:

```json
{"fullName":"Nguyen Van A","email":"demo@example.com","password":"Password123!"}
```

Đăng nhập:

```json
{"email":"demo@example.com","password":"Password123!"}
```

Đăng nhập trả về `token` và `expiresIn` = **3600000 mili giây** (1 giờ, giống slide).
Trong Postman, chọn Authorization → Bearer Token và dán token từ phản hồi đăng nhập.
HTTP 400: dữ liệu không hợp lệ; 401: sai thông tin đăng nhập/token thiếu, sai hoặc hết hạn;
403: tài khoản không khả dụng khi đăng nhập hoặc không có quyền; 409: email trùng.
Mật khẩu tối thiểu 8 ký tự khi đăng ký, tối đa 72 byte UTF-8 theo giới hạn BCrypt.

Test API bằng PowerShell sau khi khởi động server:

```powershell
$base = 'http://localhost:8005'
$registration = @{ fullName='Nguyen Van A'; email='demo@example.com'; password='Password123!' } | ConvertTo-Json
Invoke-RestMethod "$base/auth/signup" -Method Post -ContentType 'application/json' -Body $registration
$credentials = @{ email='demo@example.com'; password='Password123!' } | ConvertTo-Json
$login = Invoke-RestMethod "$base/auth/login" -Method Post -ContentType 'application/json' -Body $credentials
$headers = @{ Authorization = "Bearer $($login.token)" }
Invoke-RestMethod "$base/users/me" -Headers $headers
Invoke-RestMethod "$base/users" -Headers $headers
```

## 3. Điểm thay đổi từ JJWT sang Nimbus

Mã chính: `D:\ute\28-9\src\main\java\vn\edu\hcmute\jwt\security\JwtService.java`.

| JJWT trong ví dụ | Nimbus trong bài làm |
|---|---|
| `Jwts.builder()` | `JWTClaimsSet.Builder` và `SignedJWT` |
| `signWith(...)` | `SignedJWT.sign(new MACSigner(secret))` |
| `compact()` | `SignedJWT.serialize()` |
| parse và xác thực JWT | `SignedJWT.parse()` rồi `verify(new MACVerifier(secret))` |
| lấy subject/expiration | `JWTClaimsSet.getSubject()` / `getExpirationTime()` |

**Parse không đồng nghĩa với xác thực.** Service kiểm tra HS256, kiểu JWT, chữ ký,
issuer, subject, `exp`, `iat` và `nbf` (nếu có) trước khi sử dụng email trong subject.
JWT chứa `sub`, `iss`, `iat`, `exp`, `jti`; không chứa mật khẩu.
HS256 là ký/xác thực, không mã hóa payload.

Luồng: Controller → AuthenticationService → BCrypt/AuthenticationManager → JwtService.
Request có Bearer token → JwtAuthenticationFilter → kiểm tra Nimbus → tải user từ DB
→ SecurityContext → UserController. Session là stateless.
API dùng UserResponse thay vì trả trực tiếp entity, tránh rò rỉ password hash.

Giao diện dùng Fetch API (AJAX thuần), không cần frontend framework hoặc CDN.
Token lưu trong sessionStorage để chuyển trang demo, dữ liệu render bằng textContent.

## 4. Kiểm thử và đóng gói

```powershell
& 'D:\ute\28-9\mvnw.cmd' -f 'D:\ute\28-9\pom.xml' clean verify
# Sau khi thiết lập các biến môi trường và database như trên:
java -jar 'D:\ute\28-9\target\jwt-nimbus-demo-1.0.0.jar'
```

12 tests: 8 kiểm thử Nimbus (token hợp lệ, hết hạn, thiếu exp, sai issuer,
sai thuật toán, sai chữ ký, malformed, khóa yếu) và 4 kiểm thử API Spring/MockMvc
(đăng ký/đăng nhập/API bảo vệ, thiếu/sai token, email trùng/sai mật khẩu, input/trang login).
Test sử dụng repository Mockito nên không cần MySQL và không xác minh persistence/schema
trên database thật. JavaScript có thể kiểm tra cú pháp bằng:

```powershell
node --check 'D:\ute\28-9\src\main\resources\static\mainjs.js'
```

## 5. Phạm vi và lưu ý bảo mật

- Giữ đúng ví dụ: mọi user đã đăng nhập đều xem được danh sách user; chưa phân vai admin.
- `images` được giữ trong entity với giá trị mặc định rỗng; chưa triển khai upload ảnh.
- Logout chỉ xóa token phía trình duyệt; token đã phát hành còn hiệu lực đến khi hết hạn.
- sessionStorage vẫn có rủi ro XSS; đây là demo, không phải thiết kế lưu token hoàn chỉnh cho production.
- CSRF tắt vì API chỉ xác thực qua Authorization header, không dùng cookie đăng nhập.
- Production cần HTTPS, DB TLS, quản lý secret, migration thay `ddl-auto=update`,
  giới hạn đăng nhập, phân quyền và cơ chế thu hồi token phù hợp.
- URL DB mặc định tắt TLS chỉ để chạy local, không sử dụng nguyên cấu hình đó cho production.