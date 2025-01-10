package com.chatbotAuth.security.token;

import com.chatbotAuth.security.user.User;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "token") // MongoDB collection name
public class Token {

    @Id
    private String id; // MongoDB's unique identifier

    private String token; // The token value

    private TokenType tokenType = TokenType.BEARER; // Default token type

    private boolean revoked; // Indicates if the token is revoked

    private boolean expired; // Indicates if the token is expired

    private User user; // The associated user
}
