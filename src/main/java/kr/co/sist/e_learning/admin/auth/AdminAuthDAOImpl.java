package kr.co.sist.e_learning.admin.auth;


import org.springframework.stereotype.Repository;

import kr.co.sist.e_learning.admin.signup.EmailVerificationDTO;

@Repository
public class AdminAuthDAOImpl implements AdminAuthDAO {



	@Override
	public AdminAuthDTO loginSelectAdminById(String id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void insertAuthVerificationCode(EmailVerificationDTO dto) {
		// TODO Auto-generated method stub
		
	}
}
