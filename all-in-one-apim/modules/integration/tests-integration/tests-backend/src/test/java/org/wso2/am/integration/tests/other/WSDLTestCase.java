// * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
// *
// * WSO2 Inc. licenses this file to you under the Apache License,
// * Version 2.0 (the "License"); you may not use this file except
// * in compliance with the License.
// * You may obtain a copy of the License at
// *
// *   http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing,
// * software distributed under the License is distributed on an
// * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// * KIND, either express or implied. See the License for the
// * specific language governing permissions and limitations
// * under the License.
// */

package org.wso2.am.integration.tests.other;

import com.google.gson.Gson;
import org.json.JSONObject;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Factory;
import org.testng.annotations.Test;
import org.wso2.am.integration.test.utils.base.APIMIntegrationBaseTest;
import org.wso2.am.integration.test.utils.bean.APILifeCycleAction;
import org.wso2.am.integration.test.utils.bean.APIRequest;
import org.wso2.carbon.automation.engine.annotations.ExecutionEnvironment;
import org.wso2.carbon.automation.engine.annotations.SetEnvironment;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.carbon.automation.test.utils.http.client.HttpResponse;
import org.wso2.am.integration.test.utils.base.APIMIntegrationConstants;
import org.wso2.am.integration.clients.store.api.ApiResponse;
import org.wso2.am.integration.clients.store.api.ApiException;


import java.net.URL;
import org.wso2.am.integration.clients.publisher.api.v1.dto.APIDTO;

@SetEnvironment(executionEnvironments = {ExecutionEnvironment.STANDALONE})
public class WSDLTestCase extends APIMIntegrationBaseTest {
    private String apiId;
    private String apiName = "SignedWSDLAPI";
    private String apiVersion = "1.0.0";
    private String apiContext = "signedwsdl";
    private String provider;
    private String generatedPrivateUrl;
    private String generatedPublicUrl;


    @Factory(dataProvider = "userModeDataProvider")
    public WSDLTestCase(TestUserMode userMode) {
        this.userMode = userMode;
    }

    @DataProvider
    public static Object[][] userModeDataProvider() {
        return new Object[][]{
                new Object[]{TestUserMode.SUPER_TENANT_ADMIN},
                new Object[]{TestUserMode.TENANT_ADMIN}
        };
    }

    @BeforeClass(alwaysRun = true)
    public void initTest() throws Exception {
        super.init(userMode);
        provider = user.getUserName();
    }

    /**
     * 1️⃣ Create and Publish SOAP API with WSDL
     */
    @Test
    public void createAndPublishSOAPAPI() throws Exception {

        String wsdlUrl = "https://www.dataaccess.com/webservicesserver/numberconversion.wso?WSDL";

        APIRequest apiRequest = new APIRequest(apiName, apiContext, new URL(wsdlUrl));
        apiRequest.setVersion(apiVersion);
        apiRequest.setProvider(provider);
        apiRequest.setType("SOAP");
        apiRequest.setVisibility("PRIVATE");
        apiRequest.setRoles("Internal/subscriber");

        HttpResponse response = restAPIPublisher.addAPI(apiRequest);
        apiId = response.getData();

        createAPIRevisionAndDeployUsingRest(apiId, restAPIPublisher);
        restAPIPublisher.changeAPILifeCycleStatus(apiId, APILifeCycleAction.PUBLISH.getAction(), null);

        waitForAPIDeploymentSync(provider, apiName, apiVersion,
                APIMIntegrationConstants.IS_API_EXISTS);
    }

    /**
     * 2️⃣ Generate Signed URL
     */
    @Test(dependsOnMethods = "createAndPublishSOAPAPI")
    public void testGenerateSignedUrl() throws Exception {

        ApiResponse<String> response = restAPIStore.generateWSDLUrlOfAPI(apiId, "Default");
        Assert.assertEquals(response.getStatusCode(), 200);
        generatedPrivateUrl = response.getData();
        // Validate the URL
        Assert.assertNotNull(generatedPrivateUrl, "Generated URL should not be null");
        Assert.assertTrue(generatedPrivateUrl.contains("exp="));
        Assert.assertTrue(generatedPrivateUrl.contains("sig="));
    }

    /**
     * 5️⃣ Valid Signature Should Succeed (200 OK)
     */
    @Test(dependsOnMethods = "testGenerateSignedUrl")
    public void testValidSignatureSuccess() throws Exception {
        // Extract the valid params from the URL generated in the previous test
        String validSigParam = getQueryParamValue(generatedPrivateUrl, "sig");
        String expString = getQueryParamValue(generatedPrivateUrl, "exp");
        String XWSO2TenantQ = getQueryParamValue(generatedPrivateUrl, "X-WSO2-Tenant-Q");
        Long validExpParam = Long.valueOf(expString);

        try {
            // Call the method with valid credentials
            ApiResponse<Void> response = restAPIStore.viewWSDLSchemaDefinitionOfAPI(apiId, "Default", validExpParam,
                    validSigParam, XWSO2TenantQ);

            // Validate response
            Assert.assertEquals(response.getStatusCode(), 200, "WSDL retrieval should succeed with valid URL");
        } catch (ApiException e) {
            System.out.println("Status code: " + e.getCode());
            System.out.println("Response body: " + e.getResponseBody());
            System.out.println("Response headers: " + e.getResponseHeaders());
            Assert.fail("WSDL retrieval failed with valid signature. Error: " + e.getCode() + " - " + e.getResponseBody());
        }
    }

    /**
     * 4️⃣ Tampered Signature Should Fail
     */
    @Test(dependsOnMethods = "testGenerateSignedUrl")
    public void testTamperedSignature() throws Exception {
        String originalSigParam = getQueryParamValue(generatedPrivateUrl, "sig");
        Long originalExpParam = Long.valueOf(getQueryParamValue(generatedPrivateUrl, "exp"));
        String XWSO2TenantQ = getQueryParamValue(generatedPrivateUrl, "X-WSO2-Tenant-Q");
        String tamperedSigParam = "abcd";

        boolean apiInvocationFailed = false;
        try {
            restAPIStore.viewWSDLSchemaDefinitionOfAPI(apiId, "Default", originalExpParam, tamperedSigParam, XWSO2TenantQ);
        } catch (ApiException e) {
            apiInvocationFailed = true;
            Assert.assertEquals(e.getCode(), 401, "Expected 401 status code for expired URL");
        } catch (Exception e) {
            //            log.error("Exception in connecting to server", e);
            Assert.fail("Client cannot connect to server");
        } finally {
            if (!apiInvocationFailed) {
                Assert.fail("API invocation should have failed with unauthorized URL");
            }
        }
    }

    /**
     * 5️⃣ Expired URL Should Fail
     */
//    @Test(dependsOnMethods = "testGenerateSignedUrl")
//    public void testExpiredUrl() throws Exception {
//        String originalSigParam = getQueryParamValue(generatedPrivateUrl, "sig");
//        long originalExpParam = Long.parseLong(getQueryParamValue(generatedPrivateUrl, "exp"));
//        Long tamperedExpParam;
//        if (String.valueOf(Math.abs(originalExpParam)).length() > 10) {
//            tamperedExpParam = originalExpParam - 60_000L;
//        } else {
//            tamperedExpParam = originalExpParam - 60L;
//        }
//        boolean apiInvocationFailed = false;
//        try {
//            restAPIStore.viewWSDLSchemaDefinitionOfAPI(apiId, "Default", tamperedExpParam, originalSigParam);
//        } catch (ApiException e) {
//            apiInvocationFailed = true;
//            Assert.assertTrue(true, "Exception in getting wsdl schema definition using expired URL");
//        } catch (Exception e) {
//            //            log.error("Exception in connecting to server", e);
//            Assert.fail("Client cannot connect to server");
//        } finally {
//            if (!apiInvocationFailed) {
//                Assert.fail("API invocation should have failed with expired URL");
//            }
//        }
//    }

    @Test(dependsOnMethods = "testGenerateSignedUrl")
    public void testExpiredUrl() throws Exception {
        String originalSigParam = getQueryParamValue(generatedPrivateUrl, "sig");
        long originalExpParam = Long.parseLong(getQueryParamValue(generatedPrivateUrl, "exp"));
        String XWSO2TenantQ = getQueryParamValue(generatedPrivateUrl, "X-WSO2-Tenant-Q");

        Long tamperedExpParam;
        if (String.valueOf(Math.abs(originalExpParam)).length() > 10) {
            tamperedExpParam = originalExpParam - 60_000L;
        } else {
            tamperedExpParam = originalExpParam - 60L;
        }
        boolean apiInvocationFailed = false;
        try {
            restAPIStore.viewWSDLSchemaDefinitionOfAPI(apiId, "Default", tamperedExpParam, originalSigParam, XWSO2TenantQ);
        } catch (ApiException e) {
            apiInvocationFailed = true;
            Assert.assertEquals(e.getCode(), 401, "Expected 401 status code for expired URL");
        } catch (Exception e) {
            //            log.error("Exception in connecting to server", e);
            Assert.fail("Client cannot connect to server");
        } finally {
            if (!apiInvocationFailed) {
                Assert.fail("API invocation should have failed with expired URL");
            }
        }
    }

    /**
     * 6️⃣ Public API Should Not Include exp/sig
     */
    @Test(dependsOnMethods = {"createAndPublishSOAPAPI", "testGenerateSignedUrl"})
    public void testPublicApiDoesNotGenerateSignature() throws Exception {

        // Make API public
        HttpResponse getAPIResponse = restAPIPublisher.getAPI(apiId);
        APIDTO apidto = new Gson().fromJson(getAPIResponse.getData(), APIDTO.class);
        apidto.setVisibility(APIDTO.VisibilityEnum.PUBLIC);
        HttpResponse updateResponse = restAPIPublisher.updateAPIWithHttpInfo(apidto);
        Assert.assertEquals(updateResponse.getResponseCode(), 200, "Updated API visibility to PUBLIC");
        ApiResponse<String> response = restAPIStore.generateWSDLUrlOfAPI(apiId, "Default");
        Assert.assertEquals(response.getStatusCode(), 200);

//        JSONObject json = new JSONObject(response.getData());
        generatedPublicUrl = response.getData();
        System.out.println("Generated URL for public API: " + generatedPublicUrl);

        // Validate that url does not contain exp and sig params
        Assert.assertFalse(generatedPublicUrl.contains("exp="), "Public API URL should not contain exp param");
        Assert.assertFalse(generatedPublicUrl.contains("sig="), "Public API URL should not contain sig param");

    }

    @AfterClass(alwaysRun = true)
    public void cleanUpArtifacts() throws Exception {
        restAPIPublisher.deleteAPI(apiId);
        super.cleanUp();
    }

    private static String getQueryParamValue(String url, String paramName) {
        if (url == null || paramName == null) {
            return null;
        }
        try {
            String query = new java.net.URI(url).getQuery();
            if (query == null) {
                return null;
            }
            for (String param : query.split("&")) {
                String[] kv = param.split("=", 2);
                if (paramName.equals(kv[0])) {
                    return kv.length > 1 ? java.net.URLDecoder.decode(kv[1],
                            java.nio.charset.StandardCharsets.UTF_8.name()) : "";
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }
}
