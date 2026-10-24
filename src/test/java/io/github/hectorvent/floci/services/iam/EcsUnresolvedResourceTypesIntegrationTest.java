package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Holds {@link ResourceArnBuilder#ECS_UNRESOLVED_TYPES} to its claim, as
 * {@code UnresolvedResourceTypesIntegrationTest} does for IAM: each type belongs only to actions
 * {@code EcsJsonHandler} does not dispatch, besides the tagging actions, which pass their ARN
 * through. Dispatching one of them without resolving its type would leave it evaluated against
 * {@code *}, so a deny naming the resource would never apply.
 */
@QuarkusTest
class EcsUnresolvedResourceTypesIntegrationTest {

    private static final String TARGET = "AmazonEC2ContainerServiceV20141113.";

    @BeforeAll
    static void configure() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void everyEcsTypeDeclaredUnresolvedIsCarriedOnlyByActionsNobodyDispatches() {
        assertFalse(ResourceArnBuilder.ECS_UNRESOLVED_TYPES.isEmpty(),
                "nothing is declared unresolved any more, so this test has nothing to hold");
        for (Map.Entry<String, String> declared : ResourceArnBuilder.ECS_UNRESOLVED_TYPES.entrySet()) {
            Set<String> actions = actionsCarrying(declared.getKey());
            assertFalse(actions.isEmpty(), declared.getKey()
                    + " is declared unresolved but AWS no longer gives it to any action besides "
                    + "tagging, so the entry is dead and should go");
            for (String action : actions) {
                Response response = given().contentType("application/x-amz-json-1.1")
                        .header("X-Amz-Target", TARGET + action)
                        .body("{}")
                    .when().post("/");
                assertEquals(400, response.statusCode(), reason(declared, action));
                assertEquals("UnsupportedOperation", response.jsonPath().getString("__type"),
                        reason(declared, action));
            }
        }
    }

    private static String reason(Map.Entry<String, String> declared, String action) {
        return "ecs:" + action + " is dispatched now, so '" + declared.getKey() + "' is no longer a "
                + "type only undispatched actions carry (" + declared.getValue() + "). Resolve it in "
                + "ResourceArnBuilder, or the action is evaluated against * and a policy naming the "
                + "resource never applies";
    }

    private static Set<String> actionsCarrying(String resourceType) {
        Set<String> actions = new TreeSet<>();
        for (Map.Entry<String, List<String>> entry
                : IamActionResources.forService("ecs").actionResources().entrySet()) {
            if (entry.getValue().contains(resourceType)
                    && !ResourceArnBuilder.ECS_ARN_PARAMETERS.containsKey(entry.getKey())) {
                actions.add(entry.getKey());
            }
        }
        return actions;
    }
}
