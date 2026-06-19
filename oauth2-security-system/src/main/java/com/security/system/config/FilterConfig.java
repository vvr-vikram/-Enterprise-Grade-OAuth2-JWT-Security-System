package com.security.system.config;

import com.security.system.filter.RateLimiterFilter;
import com.security.system.tenant.TenantFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    private final RateLimiterFilter rateLimiterFilter;
    private final TenantFilter tenantFilter;

    public FilterConfig(RateLimiterFilter rateLimiterFilter, TenantFilter tenantFilter) {
        this.rateLimiterFilter = rateLimiterFilter;
        this.tenantFilter = tenantFilter;
    }

    @Bean
    public FilterRegistrationBean<RateLimiterFilter> rateLimiterFilterRegistration() {
        FilterRegistrationBean<RateLimiterFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(rateLimiterFilter);
        registration.addUrlPatterns("/*");
        registration.setName("rateLimiterFilter");
        registration.setOrder(1); // Run first, before Spring Security
        return registration;
    }

    @Bean
    public FilterRegistrationBean<TenantFilter> tenantFilterRegistration() {
        FilterRegistrationBean<TenantFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(tenantFilter);
        registration.addUrlPatterns("/users/*", "/roles/*", "/admin/*");
        registration.setName("tenantFilter");
        registration.setOrder(101); // Run after Spring Security context is loaded
        return registration;
    }
}
