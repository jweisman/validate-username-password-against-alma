# Shibboleth Validate Username Password Against Alma
This repository includes a prototype custom validator to validate users stored in the [Ex Libris Identity Service](https://developers.exlibrisgroup.com/alma/integrations/user-management/authentication/exl_identity_service/). It uses the [Alma Authenticate User REST API](https://developers.exlibrisgroup.com/alma/apis/docs/users/UE9TVCAvYWxtYXdzL3YxL3VzZXJzL3t1c2VyX2lkfQ==) to provide a custom [password authentication](https://shibboleth.atlassian.net/wiki/spaces/IDP30/pages/2494726322/PasswordAuthnConfiguration) flow.

## Build
To build the validator, run `mvn package`.

## Deploy
To deploy this validator to your Shibboleth environment, do the following:
1. In _conf/authn/password-authn-config.xml_, add the following:
```xml
    <import resource="alma-authn-config.xml" /> 
```
2. Add the _conf/authn/alma-authn-config.xml_ file from this repository
3. Add the built _validate-username-against-alma-VERSION-jar-with-dependencies.jar_ file to `webapp/WEB-INF/lib`

## Attributes
This example is necessarily incomplete as it does not handle attribute assertions. 

## Attribution
Thanks to the repository at https://github.com/MESH-Research/shibboleth-mla-auth for the [`AbstractUsernamePasswordValidationAction`](https://github.com/MESH-Research/shibboleth-mla-auth/blob/a61c366b432ba706c5134460c497cb43faa80aa2/shib-idp-mla-auth/src/main/java/org/mla/cbox/shibboleth/idp/authn/impl/ValidateUsernamePasswordAgainstMlaRest.java) example.