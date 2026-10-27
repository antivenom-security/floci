# WAF v2

**Protocol:** JSON 1.1
**Endpoint:** `http://localhost:4566/`
**Target prefix:** `X-Amz-Target: AWSWAF_20190729.*`

Floci emulates the AWS WAF v2 management API. Web ACLs, IP sets, regex pattern sets, rule groups, logging configurations, permission policies, tags, and resource associations are persisted in Floci's storage backend. A web ACL associated with an Application Load Balancer inspects the requests the load balancer receives, and its logging configuration delivers AWS WAF logs; see [Inspecting Application Load Balancer traffic](#inspecting-application-load-balancer-traffic). Other resource types (API Gateway, AppSync, CloudFront, Cognito) are associated but not inspected.

## Supported Actions

<!-- floci:actions:start -->
| Action | Description |
| --- | --- |
| `CreateWebACL` | Creates a web ACL |
| `GetWebACL` | Returns a web ACL by name/id/scope |
| `UpdateWebACL` | Updates a web ACL (requires the current `LockToken`) |
| `DeleteWebACL` | Deletes a web ACL |
| `ListWebACLs` | Lists web ACLs for a scope |
| `CreateIPSet` | Creates an IP set |
| `GetIPSet` | Returns an IP set |
| `UpdateIPSet` | Updates an IP set |
| `DeleteIPSet` | Deletes an IP set |
| `ListIPSets` | Lists IP sets for a scope |
| `CreateRegexPatternSet` | Creates a regex pattern set |
| `GetRegexPatternSet` | Returns a regex pattern set |
| `UpdateRegexPatternSet` | Updates a regex pattern set |
| `DeleteRegexPatternSet` | Deletes a regex pattern set |
| `ListRegexPatternSets` | Lists regex pattern sets for a scope |
| `CreateRuleGroup` | Creates a rule group |
| `GetRuleGroup` | Returns a rule group |
| `UpdateRuleGroup` | Updates a rule group |
| `DeleteRuleGroup` | Deletes a rule group |
| `ListRuleGroups` | Lists rule groups for a scope |
| `CheckCapacity` | Returns the WCU capacity required for a set of rules |
| `AssociateWebACL` | Associates a web ACL with a resource |
| `DisassociateWebACL` | Removes a web ACL association from a resource |
| `GetWebACLForResource` | Returns the web ACL associated with a resource |
| `ListResourcesForWebACL` | Lists resources associated with a web ACL |
| `PutLoggingConfiguration` | Sets the logging configuration for a web ACL |
| `GetLoggingConfiguration` | Returns the logging configuration for a web ACL |
| `DeleteLoggingConfiguration` | Removes a logging configuration |
| `ListLoggingConfigurations` | Lists logging configurations for a scope |
| `PutPermissionPolicy` | Attaches an IAM-style policy to a rule group |
| `GetPermissionPolicy` | Returns the policy attached to a rule group |
| `DeletePermissionPolicy` | Removes the policy from a rule group |
| `TagResource` | Adds tags to a WAF resource |
| `UntagResource` | Removes tags from a WAF resource |
| `ListTagsForResource` | Lists tags for a WAF resource |
<!-- floci:actions:end -->

## Scope

WAF v2 resources are partitioned by `Scope`: `REGIONAL` (ALB, API Gateway, AppSync) or `CLOUDFRONT`. Pass `--scope` on every call; `CLOUDFRONT`-scoped requests target the partition's CloudFront region (`us-east-1`, or `cn-northwest-1` in China) as on real AWS. The `CLOUDFRONT` scope exists only where CloudFront does, the commercial and China partitions; elsewhere it is a `WAFInvalidParameterException`. See [AWS Partitions](../configuration/partitions.md).

## IP set addresses

`CreateIPSet` and `UpdateIPSet` require every entry in `Addresses` to be in CIDR notation matching the set's `IPAddressVersion`: an IPv4 address with a `/1`-`/32` prefix, or an IPv6 address with a `/1`-`/128` prefix (a `/0` prefix is rejected, matching AWS). A bare address with no prefix, a prefix outside that range, or an address that does not match the declared `IPAddressVersion` is rejected with `WAFInvalidParameterException`.

## Tags

Every WAF v2 resource accepts at most 50 tags. `TagResource`, `CreateWebACL`, `CreateIPSet`, `CreateRegexPatternSet` and `CreateRuleGroup` reject a request that would leave the resource with more than 50 tags with `WAFLimitsExceededException`; overwriting an existing key does not count toward the limit. Tag keys must be 1-128 characters and values 0-256 characters, both limited to letters, numbers, spaces and `_ . : / = + - @`. An invalid key or value is rejected with `WAFInvalidParameterException` (`Field: TAGS`, or `TAG_KEYS` for `UntagResource`).

## Inspecting Application Load Balancer traffic

Each request an Application Load Balancer listener accepts is evaluated against the associated web ACL before the listener's rules, in rule priority order:

- **Statements:** `IPSetReferenceStatement` (the client's source address), `ByteMatchStatement` (every `PositionalConstraint`), `RegexMatchStatement` and `SizeConstraintStatement` on `UriPath`, `QueryString`, `SingleHeader` or `Method`, `RateBasedStatement` with `AggregateKeyType` `IP` and an optional `ScopeDownStatement` (counted over `EvaluationWindowSec`, 300 by default), and `AndStatement`, `OrStatement` and `NotStatement`.
- **Text transformations:** `NONE`, `LOWERCASE`, `UPPERCASE`, `URL_DECODE`, `HTML_ENTITY_DECODE`, `COMPRESS_WHITE_SPACE`, `REMOVE_WHITESPACE`, `TRIM`, `TRIM_LEFT`, `TRIM_RIGHT`, `REMOVE_NULLS`, `REPLACE_NULLS`, `REMOVE_COMMENTS_CHAR`, `REPLACE_COMMENTS`, `CMD_LINE`, `CMD_LINE_UNIX`, `NORMALIZE_PATH`, `NORMALIZE_PATH_WIN`, `BASE64_DECODE`, `HEX_DECODE`, `MD5` and `SHA256`, applied in `Priority` order to the component's bytes.
- **Actions:** `Allow` and `Count`, and `Block`, which answers AWS's `403 Forbidden` page, or the `CustomResponse` status, headers and `CustomResponseBodies` body. Matching rules add their `RuleLabels` under the web ACL's label namespace. The default action applies when no rule terminates.
- **Not evaluated:** a rule that uses any other statement, field, transformation or action (`ManagedRuleGroupStatement`, `RuleGroupReferenceStatement`, `GeoMatchStatement`, body inspection, `Captcha`, `Challenge`, forwarded-IP configuration, and so on) never matches. Floci logs one warning per web ACL. `CustomRequestHandling` is not applied.

### Logs

`PutLoggingConfiguration` with an S3 bucket (`arn:aws:s3:::aws-waf-logs-<suffix>[/<prefix>]`) or a CloudWatch Logs group (`arn:aws:logs:<region>:<account>:log-group:aws-waf-logs-<suffix>`) delivers one JSON record per inspected request in AWS's "Log fields for protection pack (web ACL) traffic" format, with the keys in the order of AWS's examples: `timestamp`, `formatVersion`, `webaclId`, `terminatingRuleId`, `terminatingRuleType`, `action`, `terminatingRuleMatchDetails`, `httpSourceName` (`ALB`), `httpSourceId` (`<account>-app/<name>/<id>`), `ruleGroupList`, `rateBasedRuleList`, `nonTerminatingMatchingRules`, `requestHeadersInserted`, `responseCodeSent`, `httpRequest` (client IP, `country` `-`, headers, URI, query string, HTTP version, method, and the trace ID as `requestId`) and `labels`. Destinations not named `aws-waf-logs-*`, and Firehose streams, receive nothing.

- S3 files are gzipped at `[prefix/]AWSLogs/<account>/WAFLogs/<region>/<web-acl-name>/YYYY/MM/dd/HH/mm/<account>_waflogs_<region>_<web-acl-name>_<YYYYMMddTHHmmZ>_<hash>.log.gz`, one per interval (`FLOCI_SERVICES_WAFV2_LOGS_INTERVAL`, 300 seconds as on AWS), dated by the interval's start and written when it ends.
- CloudWatch Logs events go to the existing log group's `<region>_<web-acl-name>_0` stream, on the same tick.
- `LoggingFilter` keeps or drops records by `ActionCondition` (the terminating action or a `COUNT` match) and `LabelNameCondition`; the first filter whose conditions are met decides. `RedactedFields` `UriPath`, `QueryString`, `Method` and `SingleHeader` are logged as `REDACTED`.
- Floci delivers without checking or adding the bucket policy or log group resource policy that AWS creates for `delivery.logs.amazonaws.com`.

## Example

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

# Create an IP set
aws wafv2 create-ip-set \
  --name blocklist --scope REGIONAL \
  --ip-address-version IPV4 \
  --addresses 192.0.2.0/24

# Create a web ACL that allows by default
aws wafv2 create-web-acl \
  --name demo-acl --scope REGIONAL \
  --default-action Allow={} \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=demo

aws wafv2 list-web-acls --scope REGIONAL

# Inspect an Application Load Balancer's traffic and log it to S3
aws wafv2 associate-web-acl --web-acl-arn "$ACL_ARN" --resource-arn "$ALB_ARN"
aws wafv2 put-logging-configuration --logging-configuration \
  "ResourceArn=$ACL_ARN,LogDestinationConfigs=arn:aws:s3:::aws-waf-logs-demo"
```

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_WAFV2_LOGS_INTERVAL` | `300` | Seconds each WAF traffic-log file covers, as AWS's 5 minutes |
