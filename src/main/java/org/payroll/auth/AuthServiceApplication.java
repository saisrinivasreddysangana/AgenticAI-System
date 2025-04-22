package org.payroll.auth;

import org.payroll.auth.entity.Role;
import org.payroll.auth.enums.RoleEnum;
import org.payroll.auth.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.Arrays;

@SpringBootApplication
public class AuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

	@Bean
	CommandLineRunner initRoles(RoleRepository roleRepository) {
		return args -> {
			Arrays.stream(RoleEnum.values()).forEach(roleEnum -> {
				if (!roleRepository.existsByName(roleEnum)) {
					Role role = new Role();
					role.setName(roleEnum);
					roleRepository.save(role);
				}
			});
		};
	}
}