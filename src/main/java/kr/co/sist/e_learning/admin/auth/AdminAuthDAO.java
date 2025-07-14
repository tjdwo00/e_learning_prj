package kr.co.sist.e_learning.admin.auth;


import org.apache.ibatis.annotations.Mapper;
import kr.co.sist.e_learning.admin.signup.EmailVerificationDTO;

@Mapper
public interface AdminAuthDAO {
    AdminAuthDTO loginSelectAdminById(String id);
    void insertAuthVerificationCode(EmailVerificationDTO dto);
}
