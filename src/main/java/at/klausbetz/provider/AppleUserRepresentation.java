package at.klausbetz.provider;

import com.fasterxml.jackson.databind.JsonNode;

public class AppleUserRepresentation {
    private String firstName;
    private String lastName;
    private String email;
    private JsonNode profile;

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public JsonNode getProfile() {
        return profile;
    }

    public void setProfile(JsonNode profile) {
        this.profile = profile;
    }
}
