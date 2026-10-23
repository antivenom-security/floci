"""Tests for regen_cloudtrail_operations.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import json

import regen_cloudtrail_operations as r

CATALOG = """
        descriptor("s3", "s3", config.services().s3().enabled(), true,
                "s3", null, 5000L, AwsNamespaces.S3, ServiceProtocol.REST_XML,
                protocols(ServiceProtocol.REST_XML),
                // s3express: directory-bucket clients sign with it
                Set.of(), Set.of("s3", "s3express"), Set.of(), Set.of(S3Controller.class)),
        descriptor("ssm", "ssm", config.services().ssm().enabled(), true,
                "ssm", null, 5000L, null, ServiceProtocol.JSON,
                protocols(ServiceProtocol.JSON),
                Set.of("AmazonSSM."), Set.of("ssm"), Set.of(), Set.of()),
"""


def s3_model() -> dict:
    return {
        "metadata": {"protocol": "rest-xml", "apiVersion": "2006-03-01", "endpointPrefix": "s3"},
        "operations": {
            "CreateMultipartUpload": {"http": {"method": "POST", "requestUri": "/{Bucket}/{Key+}?uploads"},
                                      "input": {"shape": "CreateMultipartUploadRequest"}},
            "GetObject": {"http": {"method": "GET", "requestUri": "/{Bucket}/{Key+}?x-id=GetObject"},
                          "input": {"shape": "GetObjectRequest"}},
            "CopyObject": {"http": {"method": "PUT", "requestUri": "/{Bucket}/{Key+}?x-id=CopyObject"},
                           "input": {"shape": "CopyObjectRequest"}},
            "UploadPart": {"http": {"method": "PUT", "requestUri": "/{Bucket}/{Key+}?x-id=UploadPart"},
                           "input": {"shape": "UploadPartRequest"}},
        },
        "shapes": {
            "CreateMultipartUploadRequest": {"type": "structure", "members": {
                "Bucket": {"shape": "BucketName", "locationName": "Bucket"},
                "SSEKMSKeyId": {"shape": "SSEKMSKeyId"},
                "Expires": {"shape": "Expires"},
                "Body": {"shape": "Body"}}},
            "GetObjectRequest": {"type": "structure", "members": {"Bucket": {"shape": "BucketName"},
                                                                  "Tags": {"shape": "TagMap"}}},
            "CopyObjectRequest": {"type": "structure", "required": ["Bucket", "CopySource"], "members": {
                "Bucket": {"shape": "BucketName", "location": "uri", "locationName": "Bucket"},
                "CopySource": {"shape": "BucketName", "location": "header", "locationName": "x-amz-copy-source"}}},
            "UploadPartRequest": {"type": "structure", "required": ["UploadId", "PartNumber"], "members": {
                "UploadId": {"shape": "BucketName", "location": "querystring", "locationName": "uploadId"},
                "PartNumber": {"shape": "BucketName", "location": "querystring", "locationName": "partNumber"}}},
            "BucketName": {"type": "string"},
            "SSEKMSKeyId": {"type": "string", "sensitive": True},
            "Expires": {"type": "timestamp"},
            "Body": {"type": "blob", "streaming": True},
            "TagMap": {"type": "map", "key": {"shape": "BucketName"}, "value": {"shape": "BucketName"}},
        },
    }


def ec2_model() -> dict:
    return {
        "metadata": {"protocol": "ec2", "apiVersion": "2016-11-15", "endpointPrefix": "ec2"},
        "operations": {"StartInstances": {"http": {"method": "POST", "requestUri": "/"},
                                          "input": {"shape": "StartInstancesRequest"}}},
        "shapes": {
            "StartInstancesRequest": {"type": "structure", "members": {
                "InstanceIds": {"shape": "InstanceIdList", "locationName": "InstanceId"},
                "DryRun": {"shape": "Boolean", "locationName": "dryRun"},
                "Password": {"shape": "String", "sensitive": True}}},
            "InstanceIdList": {"type": "list", "member": {"shape": "String", "locationName": "InstanceId"}},
            "String": {"type": "string"},
            "Boolean": {"type": "boolean"},
        },
    }


def test_catalog_scopes_reads_every_credential_scope_past_comments():
    assert r.catalog_scopes(CATALOG) == {"s3", "s3express", "ssm"}


def test_a_rest_operation_keeps_its_route_and_required_query_literals():
    doc = r.build_model(s3_model())

    assert doc["signingName"] == "s3"
    assert doc["eventSource"] == "s3.amazonaws.com"
    assert doc["protocol"] == "rest-xml"
    assert "targetPrefix" not in doc
    assert doc["operations"]["GetObject"] == {"method": "GET", "uri": "/{Bucket}/{Key+}",
                                             "query": {"x-id": "GetObject"}, "input": "GetObjectRequest"}
    assert doc["operations"]["CreateMultipartUpload"]["query"] == {"uploads": ""}
    assert doc["operations"]["CopyObject"]["headers"] == ["x-amz-copy-source"]
    assert doc["operations"]["UploadPart"]["queryParameters"] == ["partNumber", "uploadId"]


def test_shapes_keep_structure_lists_maps_and_sensitive_members_only():
    shapes = r.build_model(s3_model())["shapes"]

    assert set(shapes) == {"CopyObjectRequest", "CreateMultipartUploadRequest", "GetObjectRequest", "TagMap",
                           "UploadPartRequest"}
    assert shapes["CreateMultipartUploadRequest"] == {
        "members": {"Bucket": "", "SSEKMSKeyId": "", "Expires": "", "Body": ""},
        "sensitive": ["SSEKMSKeyId"], "blobs": ["Body"], "timestamps": ["Expires"]}
    assert shapes["GetObjectRequest"]["members"]["Tags"] == "TagMap"
    assert shapes["TagMap"] == {"map": True}


def test_ec2_members_keep_their_location_names():
    doc = r.build_model(ec2_model())

    assert "method" not in doc["operations"]["StartInstances"]
    assert doc["shapes"]["StartInstancesRequest"] == {
        "members": {"InstanceIds": "InstanceIdList", "DryRun": "", "Password": ""},
        "locationNames": {"InstanceIds": "InstanceId", "DryRun": "dryRun"},
        "sensitive": ["Password"],
    }
    assert doc["shapes"]["InstanceIdList"] == {"list": "", "locationName": "InstanceId"}


def test_event_source_is_the_signing_name_unless_overridden():
    def source(endpoint_prefix: str, signing: str | None = None) -> str:
        metadata = {"protocol": "json", "apiVersion": "2020-01-01", "endpointPrefix": endpoint_prefix}
        if signing:
            metadata["signingName"] = signing
        return r.build_model({"metadata": metadata, "operations": {}, "shapes": {}})["eventSource"]

    assert source("api.ecr", "ecr") == "ecr.amazonaws.com"
    assert source("api.sagemaker", "sagemaker") == "sagemaker.amazonaws.com"
    assert source("email", "ses") == "ses.amazonaws.com"
    assert source("s3-control", "s3") == "s3.amazonaws.com"
    assert source("streams.dynamodb", "dynamodb") == "dynamodb.amazonaws.com"
    assert source("memory-db", "memorydb") == "memorydb.amazonaws.com"
    assert source("api.pricing", "pricing") == "pricing.amazonaws.com"
    assert source("kms") == "kms.amazonaws.com"
    assert source("portal.sso", "awsssoportal") == "sso.amazonaws.com"
    assert source("participant.connect", "execute-api") == "participant.connect.amazonaws.com"


def test_render_is_one_model_per_line_and_round_trips():
    doc = r.build({"s3": s3_model(), "ec2": ec2_model()}, "botocore test")
    text = r.render(doc)

    assert json.loads(text) == doc
    assert text.splitlines()[3].startswith('"ec2":{')


def test_check_passes_on_a_fresh_generation_and_fails_on_a_stale_one(tmp_path):
    for name, model in (("s3", s3_model()), ("ssm", {
            "metadata": {"protocol": "json", "apiVersion": "2014-11-06", "endpointPrefix": "ssm",
                         "targetPrefix": "AmazonSSM"}, "operations": {}, "shapes": {}}),
                        ("sqs", {"metadata": {"protocol": "query", "apiVersion": "2012-11-05",
                                              "endpointPrefix": "sqs"}, "operations": {}, "shapes": {}})):
        directory = tmp_path / "data" / name / "2020-01-01"
        directory.mkdir(parents=True)
        (directory / "service-2.json").write_text(json.dumps(model), encoding="utf-8")
    catalog = tmp_path / "Catalog.java"
    catalog.write_text(CATALOG, encoding="utf-8")
    output = tmp_path / "out.json"
    args = ["--botocore-data", str(tmp_path / "data"), "--catalog", str(catalog), "--output", str(output)]

    assert r.main(args) == 0
    document = json.loads(output.read_text(encoding="utf-8"))
    assert sorted(document["models"]) == ["s3", "ssm"]
    assert document["models"]["ssm"]["targetPrefix"] == "AmazonSSM"
    assert r.main(args + ["--check"]) == 0

    output.write_text(output.read_text(encoding="utf-8").replace("2006-03-01", "1999-01-01"), encoding="utf-8")
    assert r.main(args + ["--check"]) == 1
