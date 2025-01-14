package com.chatbotAuth.security.token;

import org.springframework.data.mongodb.repository.MongoRepository;
import java.util.List;
import java.util.Optional;

public interface TokenRepository extends MongoRepository<Token, String> {

    List<Token> findAllByUserIdAndExpiredIsFalseAndRevokedIsFalse(String userId);

    Optional<Token> findByToken(String token);
}