# CloudTrail

**Protocol:** JSON 1.1 (`X-Amz-Target: com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.*`)
**Endpoint:** `POST http://localhost:4566/`

Floci emulates a CloudTrail trail's full life cycle, records every
management event in event history, and emits management events and S3
data events to the trail's destination bucket as gzipped JSON log files at
the AWS-shaped key path:

```
${prefix}AWSLogs/${accountId}/CloudTrail/${region}/yyyy/MM/dd/${accountId}_CloudTrail_${region}_${YYYYMMDDTHHMMZ}_${rand12}.json.gz
```

## Supported Actions

<!-- floci:actions:start -->
| Action | Description |
| --- | --- |
| `CreateTrail` | Creates a trail, optionally tagged via `TagsList`, and returns its ARN |
| `DescribeTrails` | Returns the settings for one or more trails |
| `DeleteTrail` | Deletes a trail |
| `UpdateTrail` | Updates the settings of an existing trail |
| `PutEventSelectors` | Configures the event selectors for a trail |
| `GetEventSelectors` | - |
| `StartLogging` | Starts logging for a trail |
| `StopLogging` | Stops logging for a trail |
| `GetTrailStatus` | Returns the logging status of a trail |
| `LookupEvents` | Returns event history newest first, filtered by one lookup attribute and a time range, with or without a trail |
| `ListTrails` | - |
| `AddTags` | Adds or overwrites tags on a trail, identified by ARN |
| `RemoveTags` | Removes the given tag keys from a trail, identified by ARN |
| `ListTags` | Returns the tags for one or more trails, identified by ARN |
<!-- floci:actions:end -->

Selector matching honors `ReadWriteType` (`All`, `ReadOnly`, `WriteOnly`)
and `AWS::S3::Object` data resource ARNs in any of these forms:

- `arn:aws:s3:::` — every bucket
- `arn:aws:s3:::bucket/` — every key in the bucket
- `arn:aws:s3:::bucket/prefix` — keys with the given prefix
- `arn:aws:s3:::bucket/prefix/key` — exact key match

## Management Events and Event History

Every signed AWS API call that CloudTrail logs as a management event is
recorded as an `eventVersion` 1.11 record:

- `eventName` is the model operation, `requestParameters` the parsed input
  and `responseElements` the parsed output, in CloudTrail's casing. Members
  the model marks sensitive, and STS `credentials.sessionToken`, read
  `HIDDEN_DUE_TO_SECURITY_REASONS`.
- `responseElements` is `null` for read-only calls and errors, except STS
  `AssumeRole*`, `GetSessionToken` and `GetFederationToken`, which are
  read-only and keep it. A refused call,
  an IAM denial included, carries `errorCode` and `errorMessage`.
- `userIdentity` is `Root` for the `test` key and a 12-digit account key,
  `IAMUser`, `AssumedRole` with its `sessionContext`, `FederatedUser`, or
  `Unknown`. Global services (IAM, CloudFront, Route 53) record in their
  partition's signing region, `us-east-1` in `aws`.
- `sourceIPAddress` is the TCP peer, or the first `X-Forwarded-For` address
  with `trust-forwarded-for` on.

Data events (S3 object operations, DynamoDB items, Lambda `Invoke`, SNS
`Publish`, SQS messages, Kinesis records) and CloudWatch Logs `PutLogEvents` are not
management events and are not recorded here.

AWS services' own role assumptions are recorded as `AssumeRole` with an
`AWSService` identity: ECS task roles (`ecs-tasks.amazonaws.com`), Lambda
execution roles (`lambda.amazonaws.com`) and EC2 instance profile roles
(`ec2.amazonaws.com`), each with an `AWS::IAM::Role` resource.

Each record goes to event history, which `LookupEvents` serves per account
and region whether or not a trail exists, and to every logging trail whose
selectors cover it. A trail with no selectors logs every management event,
and one with `IncludeGlobalServiceEvents` off skips global services' events.
`PutEventSelectors` rejects an empty selector list.
Basic selectors honor `IncludeManagementEvents`, `ReadWriteType` and
`ExcludeManagementEventSources`; advanced selectors `eventCategory`,
`readOnly` and `eventSource`.

`LookupEvents` takes one lookup attribute (`EventId`, `EventName`,
`ReadOnly`, `Username`, `ResourceType`, `ResourceName`, `EventSource`,
`AccessKeyId`), `StartTime`, `EndTime`, `MaxResults` up to 50 and
`NextToken`, and answers `ThrottlingException` past
`lookup-rate-limit-per-second` calls per second per account and region.

### EventBridge

A management or S3 data event that a logging trail covers also goes to the
default event bus of its record's region (`us-east-1` for global services),
as `AWS API Call via CloudTrail` (or `AWS Service Event via CloudTrail`) with
`source` `aws.<service>`, `resources` `[]` and the record as `detail`. Write
management events and data events match `ENABLED` rules. Read-only management
events match only rules in state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`.
Records over 256 KB are not sent. `eventbridge-delay-seconds` holds events back
before they are sent; AWS documents no delay, so the default is 0.

Known gaps:

- Unsigned calls (for example `AssumeRoleWithWebIdentity`) are not recorded.
- Scalars read from Query forms, REST paths and XML responses are strings.
- REST request headers and rest-xml bodies are not read into
  `requestParameters`, and rest-xml responses give no `responseElements`.
  S3 management events name the bucket `bucket`, not `bucketName`.
- A Query form `POST` without a `Content-Length` or over 256 KB is not
  recorded, since naming its operation would buffer the body.
- Lambda URL and Lambda Web execution roles are not recorded.

## S3 Hook Coverage

Floci emits a CloudTrail data event whenever any of these S3 ops runs
against a bucket matched by an active trail's selectors:

- `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, `ListObjects`,
  `GetObjectAcl`

Both success and `AwsException` paths emit; the latter populates
`errorCode` / `errorMessage` (`NoSuchKey`, `NoSuchBucketPolicy`, etc.).

If `floci.services.iam.enforcement-enabled` is set, IAM-deny responses also
emit records with `errorCode: "AccessDenied"`, named after the operation that
was refused. Besides the ops above, that covers the object ACL and tagging
operations, `PutObjectRetention`, `GetObjectAttributes`, and the `POST`
operations `CreateMultipartUpload`, `CompleteMultipartUpload`, `RestoreObject`
and `SelectObjectContent`. A `POST` is named from the request's
sub-resource, since `CreateMultipartUpload` and `CompleteMultipartUpload` are
both checked as `s3:PutObject` and `SelectObjectContent` as `s3:GetObject`. A request
refused for a permission it needs besides its own, such as
`s3:PutObjectTagging` for an upload that sets tags, is recorded as the
operation. A browser `POST` upload, whose credential is in its form fields, is
recorded as `PostObject` when IAM refuses it.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_CLOUDTRAIL_ENABLED` | `true` | Enable or disable the service |
| `FLOCI_SERVICES_CLOUDTRAIL_FLUSH_INTERVAL_SECONDS` | `60` | How often the writer flushes buffered records into the destination bucket. Real CloudTrail delivers with ~5 minute latency; the local default is shorter for fast feedback loops. |
| `FLOCI_SERVICES_CLOUDTRAIL_MANAGEMENT_EVENTS_ENABLED` | `true` | Record management events into event history and trails |
| `FLOCI_SERVICES_CLOUDTRAIL_EVENT_HISTORY_RETENTION_DAYS` | `90` | How long event history keeps an event |
| `FLOCI_SERVICES_CLOUDTRAIL_EVENT_HISTORY_MAX_EVENTS` | `20000` | Event history size, across accounts and regions; the oldest events are evicted past it |
| `FLOCI_SERVICES_CLOUDTRAIL_LOOKUP_RATE_LIMIT_PER_SECOND` | `2` | `LookupEvents` calls allowed per second per account and region |
| `FLOCI_SERVICES_CLOUDTRAIL_TRUST_FORWARDED_FOR` | `false` | Record the first `X-Forwarded-For` address as `sourceIPAddress` instead of the TCP peer |
| `FLOCI_SERVICES_CLOUDTRAIL_EVENTBRIDGE_DELAY_SECONDS` | `0` | Seconds before a covered event reaches EventBridge |

## Example

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test

aws s3 mb s3://my-source
aws s3 mb s3://my-trail-logs

aws cloudtrail create-trail \
    --name my-trail \
    --s3-bucket-name my-trail-logs

aws cloudtrail put-event-selectors \
    --trail-name my-trail \
    --event-selectors '[{
        "ReadWriteType": "All",
        "IncludeManagementEvents": false,
        "DataResources": [{
            "Type": "AWS::S3::Object",
            "Values": ["arn:aws:s3:::my-source/"]
        }]
    }]'

aws cloudtrail start-logging --name my-trail

# Drive some traffic
echo hello | aws s3 cp - s3://my-source/greeting.txt
aws s3 cp s3://my-source/greeting.txt -

# After ~60s, log files appear
aws s3 ls s3://my-trail-logs/AWSLogs/ --recursive

# Event history, newest first, with or without a trail
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateTrail
```
