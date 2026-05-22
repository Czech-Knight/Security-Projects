"""
Optional AWS boto3 collector starter.

The demo project uses CSV data by default. For real AWS data:
1. Create an IAM user/role with read-only EC2 permissions.
2. Configure AWS CLI profile locally.
3. Use this collector to read authorised EC2 security group data.
"""

from typing import Any, Dict, List
import boto3


class AwsBoto3Collector:
    def __init__(self, region_name: str = "ap-southeast-2", profile_name: str | None = None) -> None:
        if profile_name:
            session = boto3.Session(profile_name=profile_name, region_name=region_name)
        else:
            session = boto3.Session(region_name=region_name)
        self.ec2 = session.client("ec2")

    def describe_security_groups(self) -> List[Dict[str, Any]]:
        paginator = self.ec2.get_paginator("describe_security_groups")
        groups: List[Dict[str, Any]] = []
        for page in paginator.paginate():
            groups.extend(page.get("SecurityGroups", []))
        return groups
