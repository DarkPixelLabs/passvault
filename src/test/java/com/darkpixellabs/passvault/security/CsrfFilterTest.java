package com.darkpixellabs.passvault.security;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class CsrfFilterTest {
    private final CsrfFilter filter = new CsrfFilter();
    private final FilterChain chain = mock(FilterChain.class);

    @Test
    void rejectsStateChangingRequestWithoutMatchingToken() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/vault");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        verifyNoInteractions(chain);
    }

    @Test
    void allowsLoginWithoutCsrfToken() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/login");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }
}
