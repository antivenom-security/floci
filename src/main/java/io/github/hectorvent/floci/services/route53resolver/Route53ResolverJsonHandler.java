package io.github.hectorvent.floci.services.route53resolver;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsErrorResponse;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * JSON 1.1 handler for Route 53 Resolver operations.
 * Dispatches {@code X-Amz-Target: Route53Resolver.*} actions to {@link Route53ResolverService}.
 *
 * @see <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53_Resolver.html">Route 53 Resolver API</a>
 */
@ApplicationScoped
public class Route53ResolverJsonHandler {

    private static final Logger LOG = Logger.getLogger(Route53ResolverJsonHandler.class);

    private final Route53ResolverService service;
    private final ObjectMapper objectMapper;
    private final Ec2Service ec2Service;

    @Inject
    public Route53ResolverJsonHandler(Route53ResolverService service, ObjectMapper objectMapper,
                                      Ec2Service ec2Service) {
        this.service = service;
        this.objectMapper = objectMapper;
        this.ec2Service = ec2Service;
    }

    public Response handle(String action, JsonNode request, String region, String accountId) {
        LOG.debugv("Route53Resolver action: {0}", action);
        try {
            return switch (action) {
                case "ListFirewallDomainLists" -> handleListFirewallDomainLists(region);
                case "GetFirewallDomainList" -> handleGetFirewallDomainList(request, region);
                case "CreateFirewallDomainList" -> firewallDomainListResponse(
                        service.createFirewallDomainList(request, region, accountId));
                case "DeleteFirewallDomainList" -> firewallDomainListResponse(
                        service.deleteFirewallDomainList(text(request, "FirewallDomainListId")));

                case "CreateResolverEndpoint" -> resolverEndpointResponse(
                        service.createResolverEndpoint(request, region, accountId));
                case "DeleteResolverEndpoint" -> resolverEndpointResponse(
                        service.deleteResolverEndpoint(text(request, "ResolverEndpointId")));
                case "GetResolverEndpoint" -> resolverEndpointResponse(
                        service.getResolverEndpoint(text(request, "ResolverEndpointId")));
                case "ListResolverEndpoints" -> handleListResolverEndpoints();
                case "ListResolverEndpointIpAddresses" -> handleListResolverEndpointIpAddresses(
                        text(request, "ResolverEndpointId"));
                case "UpdateResolverEndpoint" -> resolverEndpointResponse(
                        service.updateResolverEndpoint(text(request, "ResolverEndpointId"), request));

                case "CreateResolverRule" -> resolverRuleResponse(
                        service.createResolverRule(request, region, accountId));
                case "DeleteResolverRule" -> resolverRuleResponse(
                        service.deleteResolverRule(text(request, "ResolverRuleId")));
                case "GetResolverRule" -> resolverRuleResponse(
                        service.getResolverRule(text(request, "ResolverRuleId")));
                case "ListResolverRules" -> handleListResolverRules();
                case "UpdateResolverRule" -> resolverRuleResponse(
                        service.updateResolverRule(text(request, "ResolverRuleId"), request.path("Config")));

                case "AssociateResolverRule" -> resolverRuleAssociationResponse(
                        service.associateResolverRule(request));
                case "DisassociateResolverRule" -> resolverRuleAssociationResponse(
                        service.disassociateResolverRule(request));
                case "GetResolverRuleAssociation" -> resolverRuleAssociationResponse(
                        service.getResolverRuleAssociation(text(request, "ResolverRuleAssociationId")));
                case "ListResolverRuleAssociations" -> handleListResolverRuleAssociations();

                case "CreateResolverQueryLogConfig" -> queryLogConfigResponse(
                        service.createResolverQueryLogConfig(request, region, accountId));
                case "GetResolverQueryLogConfig" -> queryLogConfigResponse(
                        service.getResolverQueryLogConfig(text(request, "ResolverQueryLogConfigId")));
                case "ListResolverQueryLogConfigs" -> listResponse("ResolverQueryLogConfigs",
                        service.listResolverQueryLogConfigs());
                case "DeleteResolverQueryLogConfig" -> queryLogConfigResponse(
                        service.deleteResolverQueryLogConfig(text(request, "ResolverQueryLogConfigId")));
                case "AssociateResolverQueryLogConfig" -> {
                    String vpcId = text(request, "ResourceId");
                    if (vpcId != null && ec2Service.describeVpcs(region, List.of(vpcId), Map.of()).isEmpty()) {
                        throw new AwsException("ResourceNotFoundException", "VPC not found: " + vpcId, 400);
                    }
                    yield queryLogAssociationResponse(service.associateResolverQueryLogConfig(request));
                }
                case "DisassociateResolverQueryLogConfig" -> queryLogAssociationResponse(
                        service.disassociateResolverQueryLogConfig(request));
                case "GetResolverQueryLogConfigAssociation" -> queryLogAssociationResponse(
                        service.getResolverQueryLogConfigAssociation(
                                text(request, "ResolverQueryLogConfigAssociationId")));
                case "ListResolverQueryLogConfigAssociations" -> listResponse(
                        "ResolverQueryLogConfigAssociations", service.listResolverQueryLogConfigAssociations());

                case "TagResource" -> {
                    service.tagResource(text(request, "ResourceArn"), request.get("Tags"), region, accountId);
                    yield Response.ok(objectMapper.createObjectNode()).build();
                }
                case "UntagResource" -> {
                    service.untagResource(text(request, "ResourceArn"), request.get("TagKeys"), region, accountId);
                    yield Response.ok(objectMapper.createObjectNode()).build();
                }
                case "ListTagsForResource" -> Response.ok(service.listTagsForResource(
                        text(request, "ResourceArn"), request.get("MaxResults"),
                        text(request, "NextToken"), region, accountId)).build();

                default -> Response.status(400)
                        .entity(new AwsErrorResponse("UnknownOperationException",
                                "Unknown operation: Route53Resolver." + action))
                        .build();
            };
        } catch (AwsException e) {
            return Response.status(e.getHttpStatus())
                    .entity(new AwsErrorResponse(e.jsonType(), e.getMessage())).build();
        }
    }

    private String text(JsonNode request, String field) {
        JsonNode value = request == null ? null : request.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    // ---------- Firewall domain lists ----------

    private Response handleListFirewallDomainLists(String region) {
        ObjectNode result = objectMapper.createObjectNode();
        ArrayNode lists = result.putArray("FirewallDomainLists");
        for (Route53ResolverService.FirewallDomainList list : service.listFirewallDomainLists(region)) {
            ObjectNode node = lists.addObject();
            node.put("Arn", list.arn());
            node.put("CreatorRequestId", "AWSManaged");
            node.put("Id", list.id());
            node.put("ManagedOwnerName", list.managedOwnerName());
            node.put("Name", list.name());
        }
        for (ObjectNode custom : service.listCustomFirewallDomainLists()) {
            lists.add(custom);
        }
        return Response.ok(result).build();
    }

    private Response handleGetFirewallDomainList(JsonNode request, String region) {
        String id = text(request, "FirewallDomainListId");
        Optional<ObjectNode> custom = service.getCustomFirewallDomainList(id);
        if (custom.isPresent()) {
            return firewallDomainListResponse(custom.get());
        }
        Route53ResolverService.FirewallDomainList list = service.getFirewallDomainList(region, id);

        ObjectNode result = objectMapper.createObjectNode();
        ObjectNode node = result.putObject("FirewallDomainList");
        node.put("Arn", list.arn());
        node.put("CreatorRequestId", "AWSManaged");
        node.put("Id", list.id());
        node.put("ManagedOwnerName", list.managedOwnerName());
        node.put("Name", list.name());

        return Response.ok(result).build();
    }

    private Response firewallDomainListResponse(ObjectNode list) {
        return Response.ok(objectMapper.createObjectNode().set("FirewallDomainList", list)).build();
    }

    // ---------- Resolver endpoints ----------

    private Response resolverEndpointResponse(ObjectNode endpoint) {
        return Response.ok(objectMapper.createObjectNode().set("ResolverEndpoint", endpoint)).build();
    }

    private Response handleListResolverEndpoints() {
        ObjectNode result = objectMapper.createObjectNode();
        ArrayNode endpoints = result.putArray("ResolverEndpoints");
        for (ObjectNode endpoint : service.listResolverEndpoints()) {
            endpoints.add(endpoint);
        }
        return Response.ok(result).build();
    }

    private Response handleListResolverEndpointIpAddresses(String endpointId) {
        ObjectNode result = objectMapper.createObjectNode();
        result.putArray("IpAddresses").addAll(service.listResolverEndpointIpAddresses(endpointId));
        return Response.ok(result).build();
    }

    // ---------- Resolver rules ----------

    private Response resolverRuleResponse(ObjectNode rule) {
        return Response.ok(objectMapper.createObjectNode().set("ResolverRule", rule)).build();
    }

    private Response handleListResolverRules() {
        ObjectNode result = objectMapper.createObjectNode();
        ArrayNode rules = result.putArray("ResolverRules");
        for (ObjectNode rule : service.listResolverRules()) {
            rules.add(rule);
        }
        return Response.ok(result).build();
    }

    // ---------- Resolver rule associations ----------

    private Response resolverRuleAssociationResponse(ObjectNode association) {
        return Response.ok(objectMapper.createObjectNode()
                .set("ResolverRuleAssociation", association)).build();
    }

    private Response handleListResolverRuleAssociations() {
        ObjectNode result = objectMapper.createObjectNode();
        ArrayNode associations = result.putArray("ResolverRuleAssociations");
        for (ObjectNode association : service.listResolverRuleAssociations()) {
            associations.add(association);
        }
        return Response.ok(result).build();
    }

    // ---------- Query logging ----------

    private Response queryLogConfigResponse(ObjectNode config) {
        return Response.ok(objectMapper.createObjectNode().set("ResolverQueryLogConfig", config)).build();
    }

    private Response queryLogAssociationResponse(ObjectNode association) {
        return Response.ok(objectMapper.createObjectNode()
                .set("ResolverQueryLogConfigAssociation", association)).build();
    }

    private Response listResponse(String member, List<ObjectNode> items) {
        ObjectNode result = objectMapper.createObjectNode();
        result.put("TotalCount", items.size());
        result.put("TotalFilteredCount", items.size());
        result.putArray(member).addAll(items);
        return Response.ok(result).build();
    }
}
