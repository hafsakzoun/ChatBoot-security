package com.chatbotAuth.security.user;

import com.chatbotAuth.security.token.Token;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * User entity mapped to MongoDB collection "users".
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "users") // MongoDB collection name
public class User implements UserDetails {

    @Id
    private String id; // MongoDB ObjectId, represented as a String

    private String firstname;
    private String lastname;
    private String email; // Username field
    private String password; // Encrypted password

    // Embedded list of tokens for authentication/authorization
    private List<Token> tokens;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Return an empty list for now; roles and permissions can be added later
        return List.of();
    }

    @Override
    public String getUsername() {
        return email; // Use email as the username
    }

    @Override
    public String getPassword() {
        return password; // Use password field
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Account is always non-expired
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Account is never locked
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Credentials are always non-expired
    }

    @Override
    public boolean isEnabled() {
        return true; // Account is enabled
    }
}
