package kr.co.sist.e_learning.config;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

import kr.co.sist.e_learning.user.auth.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomOAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    public CustomOAuth2AuthenticationSuccessHandler(UserRepository userRepository,
                                                    JwtTokenProvider jwtTokenProvider,
                                                    RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauthToken.getPrincipal();

        String provider = oauthToken.getAuthorizedClientRegistrationId();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String socialId = null;

        if ("kakao".equals(provider)) {
            socialId = String.valueOf(attributes.get("id"));
        } else if ("google".equals(provider)) {
            socialId = String.valueOf(attributes.get("sub"));
        } else {
            response.sendRedirect("/error");
            return;
        }

        Optional<UserEntity> userOpt = userRepository
                .findBySocialProviderAndSocialId(provider, socialId);

        if (userOpt.isEmpty()) {
            response.sendRedirect("/social_signup?socialProvider=" + provider + "&socialId=" + socialId);
        } else {
            UserEntity user = userOpt.get();

            // Access Token 발급
            String accessToken = jwtTokenProvider.createAccessToken(user.getUserId());

            // Refresh Token 발급
            String refreshToken = jwtTokenProvider.createRefreshToken();

            // DB 저장
            LocalDateTime expiresAt = LocalDateTime.now().plusDays(7);

            RefreshTokenEntity tokenEntity = new RefreshTokenEntity();
            tokenEntity.setUserId(user.getUserId());
            tokenEntity.setRefreshToken(refreshToken);
            tokenEntity.setExpiresAt(expiresAt);
            tokenEntity.setCreatedAt(LocalDateTime.now());

            refreshTokenRepository.save(tokenEntity);

            // Access Token 쿠키
            Cookie accessCookie = new Cookie("accessToken", accessToken);
            accessCookie.setHttpOnly(true);
            accessCookie.setSecure(true);
            accessCookie.setPath("/");
            accessCookie.setMaxAge(30 * 60);
            response.addCookie(accessCookie);

            // Refresh Token 쿠키
            Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
            refreshCookie.setHttpOnly(true);
            refreshCookie.setSecure(true);
            refreshCookie.setPath("/");
            refreshCookie.setMaxAge(7 * 24 * 60 * 60);
            response.addCookie(refreshCookie);

            response.sendRedirect("/");
        }
    }
}
