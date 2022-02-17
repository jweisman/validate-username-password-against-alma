/*
* Copyright (C) 2017 Modern Language Association
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
* except in compliance with the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software distributed under
* the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/
package net.exldevnetwork.shibboleth.idp.authn.impl;

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.client.util.Key;

import net.shibboleth.idp.authn.AbstractUsernamePasswordValidationAction;
import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;

/**
 * An action that checks for a {@link UsernamePasswordContext} and directly produces an
 * {@link net.shibboleth.idp.authn.AuthenticationResult} based on that identity by authenticating 
 * against the REST API.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#AUTHN_EXCEPTION}
 * @event {@link AuthnEventIds#INVALID_CREDENTIALS}
 * @pre <pre>
 * ProfileRequestContext.getSubcontext(AuthenticationContext.class).getAttemptedFlow() != null
 * </pre>
 * @post If AuthenticationContext.getSubcontext(UsernamePasswordContext.class) != null, then an
 *       {@link net.shibboleth.idp.authn.AuthenticationResult} is saved to the {@link AuthenticationContext} on a
 *       successful login. On a failed login, the
 *       {@link AbstractValidationAction#handleError(ProfileRequestContext, AuthenticationContext, String, String)}
 *       method is called.
 */
public class ValidateUsernamePasswordAgainstAlma extends AbstractUsernamePasswordValidationAction {
    
    /** API key */
    private String apiKey = System.getenv("ALMA_APIKEY");
    
    /** API URL root */
    private String apiRoot = null;
    
    /** HTTP transport used to query the API endpoint */
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    
    /** JSON factory used for interpreting response from API */
    private static final JsonFactory JSON_FACTORY = new JacksonFactory();

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateUsernamePasswordAgainstAlma.class);
    
    /** Represents a user object as returned by the API */
    public static class AlmaUserObject extends GenericJson {
        @Key
        private String primary_id;
        
        @Key
        private String first_name;
        
        @Key
        private String last_name;
        
        @Key
        private NameValueObject user_group;

        @Key
        private NameValueObject status;
        
        public String getPrimaryId() {
            return this.primary_id;
        }

        public String getFirstName() {
            return this.first_name;
        }

        public String getLastName() {
            return this.last_name;
        }

        public NameValueObject getUserGroup() {
            return this.user_group;
        }

        public NameValueObject getStatus() {
            return this.status;
        }
    }

    /** Represents a user object as returned by the API */
    public static class NameValueObject extends GenericJson {
        @Key
        private String value;
        
        @Key
        private String desc;

        public String getValue() {
            return this.value;
        }

        public String getDesc() {
            return this.desc;
        }
    }

    /** {@inheritDoc} */
    @Override protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        log.debug("{} Attempting to authenticate user {}", getLogPrefix(), getUsernamePasswordContext() .getUsername());
        
        try {
            
            // Construct the URL composed of the API root, authenticate user method with id value equal
            //  to the username entered in the login form, the API key, and time stamp.
            StringBuilder urlBuilder = new StringBuilder().
                    append(this.apiRoot).
                    append("/users/").
                    append(getUsernamePasswordContext().getUsername()).
                    append("?format=json").
                    append("&op=auth").
                    append("&password=").
                    append(getUsernamePasswordContext().getPassword()).
                    append("&apikey=").
                    append(this.apiKey);

            log.debug("{} Alma query URL is {}", getLogPrefix(), urlBuilder.toString());
            
            // Query the Alma API
             HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(
                    new HttpRequestInitializer() {
                         @Override
                         public void initialize(HttpRequest request) {
                             /* Set default parser as a JSON parser to make casting to class instance easier */
                            request.setParser(new JsonObjectParser(JSON_FACTORY));
                         }
                    });
            HttpRequest request = requestFactory.buildPostRequest(new GenericUrl(urlBuilder.toString()), null);
            HttpResponse response = request.execute();

            log.debug("{} Alma returned status {}", getLogPrefix(), response.getStatusCode());

            // Retrieve the user
            urlBuilder = new StringBuilder().
                append(this.apiRoot).
                append("/users/").
                append(getUsernamePasswordContext().getUsername()).
                append("?format=json").
                append("&apikey=").
                append(this.apiKey);

            request = requestFactory.buildGetRequest(new GenericUrl(urlBuilder.toString()));
            response = request.execute();

            // Parse the response and create an instance of the user object.
            AlmaUserObject almaUser = response.parseAs(AlmaUserObject.class);

            // Parse out the id, name and user group.
            String primaryId = almaUser.getPrimaryId();
            String userName = almaUser.getFirstName() + " " + almaUser.getLastName();
            String userGroup = almaUser.getUserGroup().getValue() + " / " + almaUser.getUserGroup().getDesc();
            
            log.debug("{} Alma returned primary id {}", getLogPrefix(), primaryId);
            log.debug("{} Alma returned name {}", getLogPrefix(), userName);
            log.debug("{} Alma returned user group {}", getLogPrefix(), userGroup);
            
            // Non-active members cannot authenticate.
            if (!new String("ACTIVE").equals(almaUser.getStatus().getValue())) {
                log.info("{} User {} does not have active status", getLogPrefix(), getUsernamePasswordContext().getUsername());
                handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS, AuthnEventIds.NO_CREDENTIALS);
                return;
            }

            // Set the username in the context directly because the user may have typed the member number
            // into the form rather than the username. The member number will work for authentication,
            // but we always want to return the username as the principal.
            getUsernamePasswordContext().setUsername(primaryId);
            
            // Build the authentication result and proceed.
            log.info("{} Login by '{}' succeeded", getLogPrefix(), getUsernamePasswordContext().getUsername());
            buildAuthenticationResult(profileRequestContext, authenticationContext);
            ActionSupport.buildProceedEvent(profileRequestContext);
            
//        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | InterruptedException e) {
        } catch (IOException e) {
            log.warn("{} Login by {} produced exception", getLogPrefix(), getUsernamePasswordContext().getUsername(), e);
            handleError(profileRequestContext, authenticationContext, e.toString(), AuthnEventIds.AUTHN_EXCEPTION);
        } 
    }
    
    @Nonnull
    @Override
    protected Subject populateSubject(@Nonnull Subject subject) {
        subject.getPrincipals().add(new UsernamePrincipal(getUsernamePasswordContext().getUsername()));
        return subject;
    }
    
    /**
     * Set the API key
     * 
     *  @param key key to set
     */
    public void setApiKey(@Nullable final String key) {
        this.apiKey = key;
    }
    
    /**
     * Set the API root URL
     * 
     *  @param url API url to set
     */
    public void setApiRoot(@Nullable final String url) {
        this.apiRoot = url;
    }
}