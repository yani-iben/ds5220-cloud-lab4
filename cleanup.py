import boto3
import logging
import yaml


def load_config(path="labs/lab04/config.yaml"):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

CONFIG = load_config()
ec2 = boto3.client('ec2', region_name=CONFIG['region'])
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def cleanup_infrastructure():
    # 1. Find and Terminate the Instance
    instances = ec2.describe_instances(
        Filters=[{'Name': 'tag:Name', 'Values': ['boto3-lab-instance']}]
    )
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            if instance['State']['Name'] != 'terminated':
                instance_id = instance['InstanceId']
                ec2.terminate_instances(InstanceIds=[instance_id])
                logger.info(f"Terminating instance: {instance_id}")
                
    # 2. Release Elastic IPs
    addresses = ec2.describe_addresses()
    for addr in addresses['Addresses']:
        if 'InstanceId' not in addr:  # Only release if not attached to anything
            ec2.release_address(AllocationId=addr['AllocationId'])
            logger.info(f"Released unassociated Elastic IP: {addr['PublicIp']}")

if __name__ == "__main__":
    cleanup_infrastructure()