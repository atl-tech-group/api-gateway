package com.apigateway.filter;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

@Component
public class RoleFilter {
    // Define access rules
    private static final Map<String, Predicate<List<String>>> accessRules = Map.of(
            // Only admin can POST to /product
            "/api/v1/attribute:POST", roles -> roles.contains("ROLE_ADMIN"),
            // Admin and User can GET /product-list
            "/api/v1/attribute:GET", roles -> roles.contains("ROLE_ADMIN") || roles.contains("ROLE_USER")
    );

    // Method to strip parameters from the URL
    private String getBaseUrl(String url) {
        // Strip everything after the last '/' if it's followed by a number (e.g., /api/v1/attribute/1 -> /api/v1/attribute)
        return url.replaceAll("/\\d+$", "");
    }

    // Method to check if the user has access
    public boolean hasAccess(String url, String method, List<String> userRoles) {
        String key = getBaseUrl(url) + ":" + method;  // Combine URL and HTTP method
        Predicate<List<String>> accessRule = accessRules.get(key);  // Retrieve the predicate based on the URL and method

        if (accessRule != null) {
            return accessRule.test(userRoles);  // Evaluate the predicate with the user's roles
        }

        // If there's no specific rule for this URL and method, deny access by default
        return false;
    }
}

