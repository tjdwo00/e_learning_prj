package kr.co.sist.e_learning.user.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthApiController {

    @Autowired
    private AuthService AuthService;

    @Autowired
    private JwtAuthUtils jwtAuthUtils;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    
  
   
    

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    /**
     * 이메일 인증 코드 전송
     */
    @PostMapping("/email/send")
    public ResponseEntity<?> sendEmailVerification(@RequestBody EmailRequestDTO dto) {
        String verificationSeq = AuthService.sendEmailVerification(dto.getEmail());
        return ResponseEntity.ok(
                new SimpleResponseDTO(true, "이메일 인증 코드 발송 완료", verificationSeq)
        );
    }

    /**
     * 이메일 인증 코드 검증
     */
    @PostMapping("/email/verify")
    public ResponseEntity<?> verifyEmailCode(@RequestBody EmailCodeVerifyRequestDTO dto) {
        boolean isValid = AuthService.verifyEmailCode(
                dto.getVerificationSeq(),
                dto.getCode()
        );
        return ResponseEntity.ok(
                new SimpleResponseDTO(isValid,
                        isValid ? "인증 성공" : "인증 실패",
                        null)
        );
    }

    /**
     * 이메일 중복 체크
     */
    @GetMapping("/email/check")
    public ResponseEntity<?> checkEmailDuplicate(@RequestParam String email) {
        boolean duplicated = AuthService.isEmailDuplicated(email);
        return ResponseEntity.ok(
                new SimpleResponseDTO(!duplicated,
                        duplicated ? "이미 가입된 이메일입니다." : "사용 가능한 이메일입니다.",
                        null)
        );
    }

    /**
     * 닉네임 중복 체크
     */
    @GetMapping("/nickname/check")
    public ResponseEntity<?> checkNicknameDuplicate(@RequestParam String nickname) {
        boolean duplicated = AuthService.isNicknameDuplicated(nickname);
        return ResponseEntity.ok(
                new SimpleResponseDTO(!duplicated,
                        duplicated ? "이미 사용 중인 닉네임입니다." : "사용 가능한 닉네임입니다.",
                        null)
        );
    }

    @PostMapping("/nickname/find")
    public ResponseEntity<?> findNicknameByEmail(@RequestBody EmailRequestDTO dto) {
        String nickname = AuthService.findNicknameByEmail(dto.getEmail());
        if (nickname != null) {
            return ResponseEntity.ok(new SimpleResponseDTO(true, "닉네임을 찾았습니다.", nickname));
        } else {
            return ResponseEntity.status(404).body(new SimpleResponseDTO(false, "해당 이메일로 가입된 닉네임이 없습니다.", null));
        }
    }

    
    /**
     * 회원가입
     */
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody LocalSignUpRequestDTO dto) {
        AuthService.signup(dto);
        return ResponseEntity.ok(
                new SimpleResponseDTO(true, "회원가입 완료", null)
        );
    }

    @PostMapping("/socialSignup")
    public ResponseEntity<?> socialSignup(@RequestBody SocialSignUpRequestDTO dto,
                                          HttpServletResponse response) {
        AuthService.socialSignup(dto, response);
        return ResponseEntity.ok(
                new SimpleResponseDTO(true, "소셜 회원가입 완료", null)
        );
    }

    /**
     * 로컬 로그인
     */
    @PostMapping("/login/local")
    public ResponseEntity<?> localLogin(@RequestBody LocalLoginRequestDTO dto,
                                        HttpServletResponse response) {
        AuthService.localLogin(dto, response);
        return ResponseEntity.ok(
                new SimpleResponseDTO(true, "로컬 로그인 성공", null)
        );
    }

    @PostMapping("/login/social")
    public ResponseEntity<?> socialLogin(@RequestBody SocialLoginDTO dto,
                                         HttpServletResponse response) {
        AuthService.socialLogin(dto, response);
        return ResponseEntity.ok(
                new SimpleResponseDTO(true, "소셜 로그인 성공", null)
        );
    }

    /**
     * Access Token 재발급
     */
    @PostMapping("/token/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        try {
            AuthService.reissueAccessToken(request, response);
            return ResponseEntity.ok(new SimpleResponseDTO(true, "Access Token 재발급 완료", null));
        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body(new SimpleResponseDTO(false, e.getMessage(), null));
        }
    }
}
    
    
