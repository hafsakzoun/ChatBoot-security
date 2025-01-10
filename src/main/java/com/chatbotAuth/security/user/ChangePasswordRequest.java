package com.chatbotAuth.security.user;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
@Data // Lombok annotation to generate getters, setters, toString, equals, and hashCode
public class ChangePasswordRequest {

    private String currentPassword;       // The user's current password
    private String newPassword;           // The new password the user wants to set
    private String confirmationPassword;  // Confirmation of the new password
}
