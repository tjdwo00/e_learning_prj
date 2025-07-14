package kr.co.sist.e_learning.user.auth;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
@Transactional
public class AuthServiceImpl implements AuthService {

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private EmailVerificationRepository emailVerificationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    
    @Autowired
    private JwtAuthUtils jwtAuthUtils;

    private String generateRandomCode() {
        SecureRandom rand = new SecureRandom();
        int code = 100000 + rand.nextInt(900000);
        return String.valueOf(code);
    }

    @Override
    public String sendEmailVerification(String email) {
        String code = generateRandomCode();
        String verificationSeq = UUID.randomUUID().toString();

        EmailVerificationEntity entity = new EmailVerificationEntity();
        entity.setVerificationSeq(verificationSeq);
        entity.setEmail(email);
        entity.setCode(code);
        entity.setStatus("SENT");
        entity.setCreatedAt(Timestamp.from(Instant.now()));
        entity.setExpiresAt(Timestamp.from(Instant.now().plusSeconds(300)));

        emailVerificationRepository.save(entity);

        System.out.println("임시 인증 코드: " + code);

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(email);
            helper.setSubject("[LangTrip] 이메일 인증 코드");
            helper.setText(
                    "<h2>인증 코드: " + code + "</h2>"
                            + "<p>5분 안에 입력하세요.</p>"
                    , true);

            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
            throw new IllegalStateException("이메일 발송에 실패했습니다.");
        }

        return verificationSeq;
    }

    @Override
    public boolean verifyEmailCode(String verificationSeq, String code) {
        EmailVerificationEntity entity =
                emailVerificationRepository.findByVerificationSeq(verificationSeq);

        if (entity == null) {
            return false;
        }

        boolean isValid = entity.getCode().equals(code)
                && entity.getExpiresAt().after(Timestamp.from(Instant.now()))
                && "SENT".equals(entity.getStatus());

        if (isValid) {
            entity.setStatus("VERIFIED");
            emailVerificationRepository.save(entity);
        }

        return isValid;
    }

    @Override
    public boolean isEmailDuplicated(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public boolean isNicknameDuplicated(String nickname) {
        return userRepository.existsByNickname(nickname);
    }

    @Override
    public String findNicknameByEmail(String email) {
        UserEntity user = userRepository.findByEmail(email);
        return user != null ? user.getNickname() : null;
    }

    @Override
    public void signup(LocalSignUpRequestDTO dto) {
        UserEntity user = new UserEntity();
        user.setEmail(dto.getEmail());
        user.setNickname(dto.getNickname());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setSocialProvider("LOCAL");
        user.setSignupPath(dto.getSignUp_path());
        this.createUser(user); 
    }

    @Override
    public void socialSignup(SocialSignUpRequestDTO sDTO, HttpServletResponse response) {
        UserEntity user = new UserEntity();
        user.setNickname(sDTO.getNickname());
        user.setSocialId(sDTO.getSocialId());
        user.setSocialProvider(sDTO.getSocialProvider());
        user.setSignupPath(sDTO.getSignUp_path());

        this.createUser(user); 
        
        

        String token = jwtTokenProvider.createAccessToken(user.getUserId());
        setTokenCookie(response, token);
    }

    @Override
    public UserEntity createUser(UserEntity user) {
        String userId;
        do {
            userId = UUID.randomUUID().toString()
                    .replace("-", "")
                    .substring(0, 10)
                    .toUpperCase();
        } while (userRepository.existsByUserId(userId));

        user.setUserId(userId);

        if (user.getProfile() == null) {
            user.setProfile("/images/default_profile.png");
        }
        if (user.getStatus() == null) {
            user.setStatus("ACTIVE");
        }
        if (user.getCreatedAt() == null) {
            user.setCreatedAt(LocalDateTime.now());
        }

        return userRepository.save(user);
    }

    @Override
    public void saveRefreshToken(String userId, String refreshToken, LocalDateTime expiresAt) {
        RefreshTokenEntity entity = new RefreshTokenEntity();
      
        entity.setUserId(userId); // userId 설정
        entity.setRefreshToken(refreshToken);
        entity.setExpiresAt(expiresAt);
        entity.setCreatedAt(LocalDateTime.now());

   
        refreshTokenRepository.save(entity);
    }

    @Override
    public void localLogin(LocalLoginRequestDTO dto, HttpServletResponse response) {
        UserEntity user = userRepository.findByNickname(dto.getNickname());
        if (user == null) {
            throw new RuntimeException("아이디가 존재하지 않습니다.");
        }

        if (!passwordEncoder.matches(dto.getPassword(), user.getPassword())) {
            throw new RuntimeException("비밀번호가 일치하지 않습니다.");
        }

        String accessToken = jwtTokenProvider.createAccessToken(user.getUserId());

        // Refresh Token 발급
        String refreshToken = jwtTokenProvider.createRefreshToken();
        LocalDateTime expiresAt = LocalDateTime.now().plusDays(7);
        saveRefreshToken(user.getUserId(), refreshToken, expiresAt);

        // 쿠키 저장
        setTokenCookie(response, accessToken);
        setRefreshTokenCookie(response, refreshToken);
    }

    private void setTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("accessToken", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(30 * 60);
        response.addCookie(cookie);
    }
    
    private void setRefreshTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("refreshToken", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(cookie);
    }

    
    @Override
    public void socialLogin(SocialLoginDTO dto, HttpServletResponse response) {
        // 소셜 로그인 로직 예시 (provider, socialId 기준으로 조회)
        UserEntity user = userRepository
                .findBySocialProviderAndSocialId(dto.getSocialProvider(), dto.getSocialId())
                .orElseThrow(() -> new RuntimeException("소셜 회원가입이 필요합니다."));

        String accessToken = jwtTokenProvider.createAccessToken(user.getUserId());

        // Refresh Token 발급
        String refreshToken = jwtTokenProvider.createRefreshToken();
        LocalDateTime expiresAt = LocalDateTime.now().plusDays(7);
        saveRefreshToken(user.getUserId(), refreshToken, expiresAt);

        // 쿠키 저장
        setTokenCookie(response, accessToken);
        setRefreshTokenCookie(response, refreshToken);
    }
    
    @Override
    public void logout(String refreshToken) {
        refreshTokenRepository.deleteByRefreshToken(refreshToken);
    }
    
    @Override
    public void reissueAccessToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = jwtAuthUtils.extractRefreshTokenFromCookies(request);

        if (refreshToken == null) {
            throw new RuntimeException("Refresh Token 없음");
        }

        RefreshTokenEntity token = refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh Token 만료 혹은 없음"));

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh Token 만료");
        }

        String userId = token.getUserId(); // refresh token entity에 포함됨

        String newAccessToken = jwtTokenProvider.createAccessToken(userId);
        jwtAuthUtils.setAccessTokenCookie(response, newAccessToken);
    }
}
    
    

 
    	
