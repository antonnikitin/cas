/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.jasig.cas;

import static org.mockito.Mockito.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationManager;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.BadCredentialsAuthenticationException;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.logout.LogoutManager;
import org.jasig.cas.services.RegisteredService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.services.UnauthorizedServiceException;
import org.jasig.cas.ticket.ExpirationPolicy;
import org.jasig.cas.ticket.InvalidTicketException;
import org.jasig.cas.ticket.ServiceTicket;
import org.jasig.cas.ticket.TicketCreationException;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.ticket.TicketGrantingTicket;
import org.jasig.cas.ticket.registry.TicketRegistry;
import org.jasig.cas.util.UniqueTicketIdGenerator;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests with the help of Mockito framework.
 * 
 * @author Dmitriy Kopylenko
 */
public class CentralAuthenticationServiceImplTests {

	private final String TICKET_GRANTING_ID = "ticketGrantingTicketId";

	private final String TICKET_ID = "ticketId";

	private ExpirationPolicy expirationPolicy;

	private Authentication auth1;

	private Authentication auth2;

	private TicketRegistry ticketRegMock;

	private LogoutManager logoutManager;

	private TicketGrantingTicket ticket;

	private Service service;

	private ServicesManager servicesManager;

	private RegisteredService registeredService;

	private Credentials credentials;

	private Map<String, Service> servicesMap;

	private CentralAuthenticationServiceImpl cas;

	private AuthenticationManager authenticationManager;

	private Principal principal1;

	private Principal principal2;
	
	private Map<String, Object> attributes;
	
	private Map<String, UniqueTicketIdGenerator> uniqueTicketIdGeneratorsForService;

	@SuppressWarnings("unchecked")
	@Before
	public void initTest() {

		expirationPolicy = mock(ExpirationPolicy.class);

		auth1 = mock(Authentication.class);

		auth2 = mock(Authentication.class);

		ticketRegMock = mock(TicketRegistry.class);

		logoutManager = mock(LogoutManager.class);

		ticket = mock(TicketGrantingTicket.class);

		service = mock(Service.class);

		servicesManager = mock(ServicesManager.class);

		registeredService = mock(RegisteredService.class);

		servicesMap = mock(Map.class);

		credentials = mock(Credentials.class);

		authenticationManager = mock(AuthenticationManager.class);

		principal1 = mock(Principal.class);

		principal2 = mock(Principal.class);
		
		attributes = new HashMap<String, Object>();
		
		uniqueTicketIdGeneratorsForService = new HashMap<String, UniqueTicketIdGenerator>();

		cas = new CentralAuthenticationServiceImpl(ticketRegMock, null,
				authenticationManager, mock(UniqueTicketIdGenerator.class),
				uniqueTicketIdGeneratorsForService, mock(ExpirationPolicy.class),
				expirationPolicy, servicesManager, logoutManager);
	}

    @Test
    public void testDestroyTicketGrantingTicket1() {
    	when(ticketRegMock.getTicket(eq(TICKET_GRANTING_ID), eq(TicketGrantingTicket.class))).thenReturn(null);
    	assertSame(Collections.emptyMap(), cas.destroyTicketGrantingTicket(TICKET_GRANTING_ID));
    }

    @Test
    public void testDestroyTicketGrantingTicket2() {
    	when(ticketRegMock.getTicket(eq(TICKET_GRANTING_ID), eq(TicketGrantingTicket.class))).thenReturn(ticket);
    	when(logoutManager.performLogout(eq(ticket))).thenReturn(servicesMap);
    	assertEquals(servicesMap, cas.destroyTicketGrantingTicket(TICKET_GRANTING_ID));
    	verify(ticketRegMock).deleteTicket(TICKET_GRANTING_ID);
    }

    @Test(expected=InvalidTicketException.class)
    public void testGrantServiceTicket1() throws TicketException {
    	cas.grantServiceTicket(null, null, null);
    }
    
    @Test(expected=InvalidTicketException.class)
    public void testGrantServiceTicket2() throws TicketException {
    	when(ticketRegMock.getTicket(eq(TICKET_GRANTING_ID), eq(TicketGrantingTicket.class))).thenReturn(null);
    	cas.grantServiceTicket(TICKET_GRANTING_ID, null, credentials);
    }
    
    @Test(expected=InvalidTicketException.class)
    public void testGrantServiceTicket3() throws TicketException {
        when(ticketRegMock.getTicket(eq(TICKET_GRANTING_ID), eq(TicketGrantingTicket.class))).thenReturn(ticket);
        when(ticket.isExpired()).thenReturn(true);
        cas.grantServiceTicket(TICKET_GRANTING_ID, null, credentials);
        
    }
    
    @Test(expected=UnauthorizedServiceException.class)
    public void testGrantServiceTicket4() throws TicketException {
    	when(ticketRegMock.getTicket(eq(TICKET_GRANTING_ID), eq(TicketGrantingTicket.class))).thenReturn(ticket);
        when(ticket.isExpired()).thenReturn(false);
        when(servicesManager.findServiceBy(eq(service))).thenReturn(null);
        cas.grantServiceTicket(TICKET_GRANTING_ID, service, credentials);
    }
    
    @Test(expected=UnauthorizedServiceException.class)
    public void testGrantServiceTicket5() throws TicketException {
    	when(ticketRegMock.getTicket(eq(TICKET_GRANTING_ID), eq(TicketGrantingTicket.class))).thenReturn(ticket);
        when(ticket.isExpired()).thenReturn(false);
        when(servicesManager.findServiceBy(eq(service))).thenReturn(registeredService);
        when(registeredService.isEnabled()).thenReturn(false);
        cas.grantServiceTicket(TICKET_GRANTING_ID, service, credentials);
    }

    @Test(expected=TicketCreationException.class)
    public void testGrantServiceTicket6() throws TicketException, AuthenticationException {
    	when(ticketRegMock.getTicket(eq(TICKET_GRANTING_ID), eq(TicketGrantingTicket.class))).thenReturn(ticket);
        when(ticket.isExpired()).thenReturn(false);
        when(servicesManager.findServiceBy(eq(service))).thenReturn(registeredService);
        when(registeredService.isEnabled()).thenReturn(true);
        when(authenticationManager.authenticate(eq(credentials))).thenThrow(new BadCredentialsAuthenticationException("oops"));
        cas.grantServiceTicket(TICKET_GRANTING_ID, service, credentials);
    }
    
    @Test(expected=TicketCreationException.class)
    public void testGrantServiceTicket7() throws TicketException, AuthenticationException {
    	when(ticketRegMock.getTicket(eq(TICKET_GRANTING_ID), eq(TicketGrantingTicket.class))).thenReturn(ticket);
        when(ticket.isExpired()).thenReturn(false);
        when(servicesManager.findServiceBy(eq(service))).thenReturn(registeredService);
        when(registeredService.isEnabled()).thenReturn(true);
        when(authenticationManager.authenticate(eq(credentials))).thenReturn(auth1);
        when(auth1.getPrincipal()).thenReturn(principal1);
        when(ticket.getAuthentication()).thenReturn(auth2);
        when(auth2.getPrincipal()).thenReturn(principal2);
        cas.grantServiceTicket(TICKET_GRANTING_ID, service, credentials);
    }
    
    @Test
    public void testGrantServiceTicket8() throws TicketException, AuthenticationException {
    	when(ticketRegMock.getTicket(eq(TICKET_GRANTING_ID), eq(TicketGrantingTicket.class))).thenReturn(ticket);
        when(ticket.isExpired()).thenReturn(false);
        when(servicesManager.findServiceBy(eq(service))).thenReturn(registeredService);
        when(registeredService.isEnabled()).thenReturn(true);
        when(authenticationManager.authenticate(eq(credentials))).thenReturn(auth1);
        when(auth1.getPrincipal()).thenReturn(principal1);
        when(auth1.getAttributes()).thenReturn(attributes);
        when(ticket.getAuthentication()).thenReturn(auth1);
        
        UniqueTicketIdGenerator serviceTicketUniqueTicketIdGenerator = mock(UniqueTicketIdGenerator.class);
        uniqueTicketIdGeneratorsForService.put(service.getClass().getName(), serviceTicketUniqueTicketIdGenerator);
        when(serviceTicketUniqueTicketIdGenerator.getNewTicketId(ServiceTicket.PREFIX)).thenReturn(TICKET_ID);
        ServiceTicket serviceTicket = mock(ServiceTicket.class);
        when(ticket.grantServiceTicket(TICKET_ID, service, expirationPolicy, true)).thenReturn(serviceTicket);
        when(serviceTicket.getId()).thenReturn(TICKET_ID);
        
        assertEquals(cas.grantServiceTicket(TICKET_GRANTING_ID, service, credentials), TICKET_ID);
    }
    
//    @Test(expected=InvalidTicketException.class)
//    public void testNonExistentServiceWhenDelegatingTicketGrantingTicket() throws TicketException {
//        this.cas.delegateTicketGrantingTicket("bad-st", TestUtils.getCredentialsWithSameUsernameAndPassword());
//    }
//
//    @Test(expected=UnauthorizedProxyingException.class)
//    public void testInvalidServiceWhenDelegatingTicketGrantingTicket() throws TicketException {
//        this.cas.delegateTicketGrantingTicket("st-id", TestUtils.getCredentialsWithSameUsernameAndPassword());
//    }
//
//    @Test(expected=UnauthorizedProxyingException.class)
//    public void disallowVendingServiceTicketsWhenServiceIsNotAllowedToProxyCAS1019() throws TicketException {
//        this.cas.grantServiceTicket("tgt-id", TestUtils.getService("test1"));
//    }
}
