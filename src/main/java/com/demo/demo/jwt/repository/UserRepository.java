package com.demo.demo.jwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.demo.demo.jwt.models.user.User;

public interface UserRepository extends JpaRepository<User, Integer> {

	// query-method personalizado que busca por username
	Optional<User> findByUsername(String username);
}
