package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.testing.EnforcementFixtures;
import io.github.hectorvent.floci.testing.IamEnforcementProfile;
import io.github.hectorvent.floci.testing.PartitionCleanup;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.URI;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * IAM enforcement reads the groups a RunInstances launch template gives the instance before it
 * decides, so that read must leave nothing behind: a denied launch in a Region nobody has used
 * yet does not seed that Region's default VPC and security group.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2LaunchTemplateAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "000000000000";
    private static final String FRESH_REGION = "mx-central-1";

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @TestHTTPResource("/")
    URI baseUri;

    @Inject
    Ec2Service ec2Service;

    @Test
    void aDeniedLaunchFromATemplateSeedsNothingInAFreshRegion() {
        assertFalse(ec2Service.defaultResourcesSeeded(ACCOUNT_ID, FRESH_REGION),
                FRESH_REGION + " was already seeded by another test, so this one proves nothing");
        String adminAuth = EnforcementFixtures.auth(ACCOUNT_ID, "iam");
        String user = "lt-" + UUID.randomUUID().toString().substring(0, 8);
        String akid = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), adminAuth, user).accessKeyId();
        EnforcementFixtures.putUserPolicy(baseUri.getPort(), adminAuth, user, "p", """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"ec2:*","Resource":"*"},
                  {"Effect":"Deny","Action":"ec2:RunInstances","Resource":"*"}]}""");

        given().header("Authorization", EnforcementFixtures.auth(akid, FRESH_REGION, "ec2"))
                .formParam("Action", "RunInstances")
                .formParam("Version", "2016-11-15")
                .formParam("MinCount", "1")
                .formParam("MaxCount", "1")
                .formParam("LaunchTemplate.LaunchTemplateId", "lt-0123456789abcdef0")
            .when().post(baseUri)
            .then().statusCode(403).body(containsString("UnauthorizedOperation"));

        assertFalse(ec2Service.defaultResourcesSeeded(ACCOUNT_ID, FRESH_REGION),
                "authorizing the launch seeded " + FRESH_REGION + "'s default resources");
    }
}
