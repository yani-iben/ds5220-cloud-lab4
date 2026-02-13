import logging
# Configure logging (console + local file)
import yaml
import boto3
import json

# Create clients for different services
ec2 = boto3.client('ec2', region_name='us-east-1')
s3 = boto3.client('s3', region_name='us-east-1')
iam = boto3.client('iam')  # IAM is global

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("provision.log", mode="a", encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)
def load_config(path="labs/lab04/config.yaml"):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

CONFIG = load_config("labs/lab04/config.yaml")

def create_s3_bucket(bucket_name, region):
    s3 = boto3.client('s3', region_name=region)
    try:
        if region == 'us-east-1':
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        
        logger.info(f"Successfully created bucket: {bucket_name}")
        return bucket_name
    except Exception as e:
        logger.error(f"Failed to create bucket {bucket_name}: {e}")
        return None
    
import json

def create_iam_role(role_name):
    """
    Create an IAM role for EC2 with a trust policy.
    
    Args:
        role_name (str): Name of the IAM role
        
    Returns:
        str: Role ARN if successful, None otherwise
    """
    iam = boto3.client('iam')
    
    # Trust policy allowing EC2 to assume this role
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='Role for EC2 to access S3'
        )
        logger.info(f"Created IAM role: {role_name}")
        return response['Role']['Arn']
    except iam.exceptions.EntityAlreadyExistsException:
        logger.warning(f"Role {role_name} already exists")
        response = iam.get_role(RoleName=role_name)

        return response['Role']['Arn']
        pass
    except Exception as e:
        logger.error(f"Error creating IAM role: {e}")
        return None

def create_instance_profile(profile_name, role_name):
    iam = boto3.client('iam')
    
    try:
        # 1. Create the instance profile container
        response = iam.create_instance_profile(InstanceProfileName=profile_name)
        
        # 2. Add the role to the profile
        iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name,
            RoleName=role_name
        )
        
        logger.info(f"Created instance profile {profile_name} and added role {role_name}")
        return response['InstanceProfile']['Arn']

    except iam.exceptions.EntityAlreadyExistsException:
        logger.warning(f"Instance profile {profile_name} already exists. Verifying role...")
        
        # 1. Get the existing profile details
        response = iam.get_instance_profile(InstanceProfileName=profile_name)
        
        # 2. Check if the role is already attached to avoid LimitExceeded errors
        existing_roles = [r['RoleName'] for r in response['InstanceProfile']['Roles']]
        if role_name not in existing_roles:
            iam.add_role_to_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=role_name
            )
            
        return response['InstanceProfile']['Arn']

    except Exception as e:
        logger.error(f"Error creating instance profile: {e}")
        return None



def attach_s3_policy(role_name, bucket_name):
    iam = boto3.client('iam')
    
    # Define the policy document
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:DeleteObject"
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",      # Permission for the bucket itself
                    f"arn:aws:s3:::{bucket_name}/*"    # Permission for all files inside
                ]
            }
        ]
    }
    
    try:
       
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName='S3AccessPolicy',
            PolicyDocument=json.dumps(policy_document)
        )
        
        logger.info(f"Attached S3 policy to role {role_name} for bucket {bucket_name}")
        return True
    except Exception as e:
        logger.error(f"Error attaching policy: {e}")
        return False
    
def allocate_elastic_ip():
    """
    Allocate an Elastic IP address.
    
    Returns:
        dict: Dictionary with 'AllocationId' and 'PublicIp', or None
    """
    ec2 = boto3.client('ec2', region_name=CONFIG['region'])
    
    try:
        response=ec2.allocate_address(Domain="vpc")

        allocation_id= response["AllocationId"]
        public_ip=response["PublicIp"]

        return{
            "AllocationId" : allocation_id,
            "PublicIp" : public_ip
        }
    except Exception as e:
        logger.error(f"Error allocating Elastic IP: {e}")
        return None
def associate_elastic_ip(instance_id, allocation_id):
    """
    Associate an Elastic IP with an EC2 instance.
    
    Args:
        instance_id (str): ID of the EC2 instance
        allocation_id (str): Allocation ID of the Elastic IP
        
    Returns:
        str: Association ID if successful, None otherwise
    """
    ec2 = boto3.client('ec2', region_name=CONFIG['region'])
    
    try:
        response= ec2.associate_address(
            InstanceId= instance_id,
            AllocationId=allocation_id
        )
        association_id = response["AssociationId"]
        logger.info(f"Associated Elastic IP with AllocationId: {allocation_id} and InstanceId: {instance_id}")
        
        return association_id
    except Exception as e:
        logger.error(f"Error associating Elastic IP: {e}")
        return None
    
def launch_ec2_instance(instance_type, ami_id, key_name, security_group, instance_profile_name, bucket_name):
    """
    Launch an EC2 instance with user data and instance profile.
    
    Args:
        instance_type (str): EC2 instance type (e.g., m7i.large)
        ami_id (str): AMI ID to use (e.g., Ubuntu 24.04)
        key_name (str): SSH key pair name
        security_group (str): Security Group ID (sg-xxxx)
        instance_profile_name (str): Instance profile name
        bucket_name (str): S3 bucket name
        
    Returns:
        str: Instance ID if successful, None otherwise
    """
    ec2 = boto3.client('ec2', region_name=CONFIG['region'])
    
    # User data script - bootstraps the instance automatically on startup
    user_data_script = f"""#!/bin/bash
    apt update
    apt upgrade -y

    snap install docker
    sleep 10
    docker run -d --restart=always -p 8888:8888 quay.io/jupyter/base-notebook start-notebook.py --NotebookApp.token='my-token'
    
    # Test S3 access by copying a file to your lab bucket
    aws s3 cp /var/log/apt/history.log s3://{bucket_name}/
    """
    
    try:
        # 1. Trigger the instance launch
        response = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            KeyName=key_name,
            MinCount=1,
            MaxCount=1,
            UserData=user_data_script,
            SecurityGroupIds=[security_group],
            IamInstanceProfile={'Name': instance_profile_name},
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': 'boto3-lab-instance'},
                        {'Key': 'Lab', 'Value': 'IaC-Python'}
                    ]
                }
            ]
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        logger.info(f"Launch command sent. Instance ID: {instance_id}")
        
    
        logger.info(f"Waiting for instance {instance_id} to reach 'running' state...")
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        
        logger.info(f"Instance {instance_id} is now running and ready for EIP association.")
        return instance_id
        
    except Exception as e:
        logger.error(f"Error launching instance: {e}")
        return None
    
def main():
    logger.info("Starting infrastructure provisioning..")
    bucket_success=create_s3_bucket(CONFIG["bucket_name"],CONFIG["region"])

    if not bucket_success:
        logger.error("Failed to setup S3 bucket. Exiting.")
        return
    role_name=CONFIG["instance"]["role_name"]
    role_arn=create_iam_role(role_name)

    if not role_arn:
        logger.error("Failed to create IAM role. Exiting.")
        return
    
    policy_attached=attach_s3_policy(role_name,CONFIG["bucket_name"])

    if not policy_attached:
        logger.error("Failed to attach S3 policy. Aborting")
        return
    profile_arn= create_instance_profile(role_name,role_name)

    if not profile_arn:
        logger.error("Failed to create instance profile. Exiting.")
        return
    logger.info("Waiting 10 seconds for IAM resources to propogate..")
    import time 
    time.sleep(10)

    instance_id= launch_ec2_instance(
        instance_type=CONFIG["instance"]["instance_type"],
        ami_id=CONFIG["instance"]["ami_id"],
        key_name=CONFIG["instance"]["key_name"],
        security_group=CONFIG["instance"]["security_group_id"],
        instance_profile_name=role_name,
        bucket_name=CONFIG["bucket_name"]
    )
    if not instance_id:
        logger.error("Failed to launch EC2 instance. Exiting.")
        return
    elastic_ip_info=allocate_elastic_ip()
    if not elastic_ip_info:
        logger.error("Failed to allocate Elastic IP.")
        return
    association_id=associate_elastic_ip(instance_id,elastic_ip_info["AllocationId"])

    if not association_id:
        logger.error("Failed to associate Elastic IP.")
        return

    logger.info("Infrastructure provisioning complete!")
    logger.info(f"Your instance is accessible at: http://{elastic_ip_info['PublicIp']}:8888")
    logger.info(f"S3 bucket created: {CONFIG['bucket_name']}")

    return{
        "instance_id": instance_id,
        "public_ip": elastic_ip_info["PublicIp"],
        "bucket_name": CONFIG["bucket_name"]
    }

if __name__ == "__main__": 
        main()