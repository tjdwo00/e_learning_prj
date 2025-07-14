package kr.co.sist.e_learning.user.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthPageController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtAuthUtils jwtAuthUtils;

    @GetMapping("/signup")
    public String showSignUpPage() {
        return "user/sign_up/sign_up";
    }

    @GetMapping("/user/login")
    public String showLoginPage() {
        return "user/login/login";
    }

    @GetMapping("/forgot-username")
    public String showForgotUsername() {
        return "user/login/forgot-username";
    }

    @GetMapping("/forgot-password")
    public String showForgotPassword() {
        return "user/login/forgot-password";
    }

    @GetMapping("user/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        // ① 쿠키에서 refreshToken 꺼내기
        String refreshToken = jwtAuthUtils.extractRefreshTokenFromCookies(request);

        if (refreshToken != null) {
            // ② DB에서 refresh token 삭제
            authService.logout(refreshToken);
        }

        // ③ 쿠키 삭제
        Cookie accessCookie = new Cookie("accessToken", null);
        accessCookie.setMaxAge(0);
        accessCookie.setPath("/");
        response.addCookie(accessCookie);

        Cookie refreshCookie = new Cookie("refreshToken", null);
        refreshCookie.setMaxAge(0);
        refreshCookie.setPath("/");
        response.addCookie(refreshCookie);

        return "redirect:/";
    }

    @GetMapping("/social_signup")
    public String showSocialSignUpPage(@RequestParam String socialProvider,
                                       @RequestParam String socialId,
                                       Model model) {
        model.addAttribute("socialProvider", socialProvider);
        model.addAttribute("socialId", socialId);
        return "user/sign_up/social_sign_up";
    }
}
