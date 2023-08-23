package com.CodeCrusades.GraalGatewayTest;

import com.CodeCrusades.GraalGatewayTest.controllers.AdminAPI;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.test.context.support.WithMockUser;
import reactor.core.publisher.Mono;

import java.nio.file.AccessDeniedException;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class GraalGatewayTestApplicationTests {

	@Autowired
	AdminAPI adminAPI;

	@WithMockUser(roles="admin")
	@Test
	void readAccountWithAdminRoleThenInvokes() {
//		Mono<ResponseEntity<Boolean>> responseEntityMono = this.adminAPI.isAdmin();
		// ... assertions
//		responseEntityMono.subscribe(booleanResponseEntity -> assertEquals(true, booleanResponseEntity));
	}

	@WithMockUser(roles="wrong")
	@Test
	void readAccountWithNonAdminRoleThenInvokes() {
		// ... assertions
//		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(
//				() -> this.adminAPI.isAdmin());
	}

}
