package io.github.hectorvent.floci.services.route53resolver;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
class Route53ResolverQueryLogIntegrationTest {

    private static final String AUTH_HEADER =
            "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/route53resolver/aws4_request";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void queryLogConfigLifecycleFollowsAwsStatuses() {
        String token = UUID.randomUUID().toString();
        String createBody = """
                {"Name":"dns-logs","DestinationArn":"arn:aws:s3:::query-logs/dns","CreatorRequestId":"%s"}
                """.formatted(token);
        String id = call("CreateResolverQueryLogConfig", createBody).statusCode(200)
                .body("ResolverQueryLogConfig.Status", equalTo("CREATING"))
                .body("ResolverQueryLogConfig.Id", startsWith("rqlc-"))
                .body("ResolverQueryLogConfig.Arn", startsWith("arn:aws:route53resolver:us-east-1:"))
                .body("ResolverQueryLogConfig.ShareStatus", equalTo("NOT_SHARED"))
                .extract().path("ResolverQueryLogConfig.Id");
        call("CreateResolverQueryLogConfig", createBody).statusCode(200)
                .body("ResolverQueryLogConfig.Id", equalTo(id));
        call("GetResolverQueryLogConfig", "{\"ResolverQueryLogConfigId\":\"" + id + "\"}").statusCode(200)
                .body("ResolverQueryLogConfig.Status", equalTo("CREATED"))
                .body("ResolverQueryLogConfig.AssociationCount", equalTo(0));

        String associate = "{\"ResolverQueryLogConfigId\":\"" + id + "\",\"ResourceId\":\"vpc-0ql0000\"}";
        String associationId = call("AssociateResolverQueryLogConfig", associate).statusCode(200)
                .body("ResolverQueryLogConfigAssociation.Status", equalTo("CREATING"))
                .body("ResolverQueryLogConfigAssociation.Error", equalTo("NONE"))
                .extract().path("ResolverQueryLogConfigAssociation.Id");
        call("AssociateResolverQueryLogConfig", associate).statusCode(400)
                .body("__type", equalTo("ResourceExistsException"));
        String getAssociation = "{\"ResolverQueryLogConfigAssociationId\":\"" + associationId + "\"}";
        call("GetResolverQueryLogConfigAssociation", getAssociation).statusCode(200)
                .body("ResolverQueryLogConfigAssociation.Status", equalTo("ACTIVE"))
                .body("ResolverQueryLogConfigAssociation.ResourceId", equalTo("vpc-0ql0000"));
        call("ListResolverQueryLogConfigAssociations", "{}").statusCode(200)
                .body("ResolverQueryLogConfigAssociations.Id", hasItem(associationId));
        call("ListResolverQueryLogConfigs", "{}").statusCode(200)
                .body("ResolverQueryLogConfigs.find { it.Id == '" + id + "' }.AssociationCount", equalTo(1));
        call("DeleteResolverQueryLogConfig", "{\"ResolverQueryLogConfigId\":\"" + id + "\"}").statusCode(400)
                .body("__type", equalTo("InvalidRequestException"));

        call("DisassociateResolverQueryLogConfig", associate).statusCode(200)
                .body("ResolverQueryLogConfigAssociation.Status", equalTo("DELETING"));
        call("GetResolverQueryLogConfigAssociation", getAssociation).statusCode(400)
                .body("__type", equalTo("ResourceNotFoundException"));
        call("DeleteResolverQueryLogConfig", "{\"ResolverQueryLogConfigId\":\"" + id + "\"}").statusCode(200)
                .body("ResolverQueryLogConfig.Status", equalTo("DELETING"));
        call("GetResolverQueryLogConfig", "{\"ResolverQueryLogConfigId\":\"" + id + "\"}").statusCode(400)
                .body("__type", equalTo("ResourceNotFoundException"));
    }

    @Test
    void firehoseDestinationIsRejected() {
        call("CreateResolverQueryLogConfig", """
                {"Name":"fh","DestinationArn":"arn:aws:firehose:us-east-1:000000000000:deliverystream/x",
                 "CreatorRequestId":"%s"}
                """.formatted(UUID.randomUUID())).statusCode(400)
                .body("__type", equalTo("InvalidParameterException"));
    }

    private static ValidatableResponse call(String action, String body) {
        return given()
                .contentType("application/x-amz-json-1.1")
                .header("X-Amz-Target", "Route53Resolver." + action)
                .header("Authorization", AUTH_HEADER)
                .body(body)
                .when().post("/")
                .then();
    }
}
