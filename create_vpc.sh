
#!/bin/bash

# create-aws-vpc
echo "Runnning create VPC, subnet and routetables script"
read -p "Enter region(us-east-2,us-east-1,eu-west-1,us-west-2,us-west-1,ap-southeast-1,ap-northeast-1,ap-southeast-2) > : " region
read -p "Enter AWS Profile Role for creating VPC and Infra > : " cliprofile
read -p  "Enter LAB/POC Name > : " laborpocname

echo ${region}
echo ${cliprofile}
echo ${laborpocname}
#variables used in script:
vpcTagName="vpc-myss-${laborpocname}"
mainSubnetName="vpc-myss-main-subnet-${laborpocname}"
workLoadSubnetName="vpc-myss-workload-subnet-${laborpocname}"
routeTableName="vpc-myss-rt-${laborpocname}"
vpcCidrBlock=$(echo $ALIASES | jq '.vpccidr' -r cli-config.json)
privateSubNetClusterCidrBlock=$(echo $ALIASES | jq '.subnetscidrs.clustermaintainence' -r cli-config.json) # 
privateSubNetWorkLoadCidrBlock=$(echo $ALIASES | jq '.subnetscidrs.workload' -r cli-config.json) # 
#destinationCidrBlock="0.0.0.0/0"

#create vpc with cidr block /16

echo "creating vpc for lab ${vpcTagName}"
export AWS_PROFILE=${AWSPROFILE}
read -r VPC_ID VPC_CIDR VPC_NAME < <(aws ec2 create-vpc \
 --cidr-block "${vpcCidrBlock}" \
 --tag-specifications ResourceType=vpc,Tags="[{Key=Name,Value='${vpcTagName}'}, {Key=Environment,Value='lab'},{Key=Owner,Value='Myss'}]" \
 --profile "${cliprofile}" \
 --region "${region}" \
 --query "Vpcs[0].[VpcId,CidrBlock,Tags[?Key == 'Name']|[0].Value]" \
 --output text)

read -r VPC_ID VPC_CIDR VPC_NAME < <(aws ec2 describe-vpcs \
  --profile "${cliprofile}" \
  --filters "Name=tag:Name,Values=${vpcTagName}"  \
  --query "Vpcs[*].[VpcId,CidrBlock,Tags[?Key == 'Name']|[0].Value]" \
  --output text)

echo "project name :${VPC_ID} ::: ${VPC_CIDR} :::: ${VPC_NAME}"
#add dns support
echo "updating dns support...."
modify_response=$(aws ec2 modify-vpc-attribute \
 --vpc-id "${VPC_ID}" \
 --profile "${cliprofile}" \
 --region "${region}" \
 --enable-dns-support "{\"Value\":true}")
#add dns hostnames
echo "updating dns hostnames...."
modify_response=$(aws ec2 modify-vpc-attribute \
  --vpc-id "${VPC_ID}" \
  --profile "${cliprofile}" \
  --region "${region}" \
  --enable-dns-hostnames "{\"Value\":true}")

# reading availability zones from region
availability_zones=$(aws ec2 describe-availability-zones \
 --profile "${cliprofile}" \
 --region "${region}")

#loop availability zones and subnet ids is needs to be changed
availability_zone_one=$(echo -e "$availability_zones" |  jq '.AvailabilityZones[0].ZoneName'| tr -d '"' )
echo " :::  :: $availability_zone_one"
availability_zone_two=$(echo -e "$availability_zones" |  jq '.AvailabilityZones[1].ZoneName'| tr -d '"')
echo " @@@@@@@ $availability_zone_two"
#creating main subnet for vpc with cidr block
echo "creating main subnet for vpc ...."
subnet_response=$(aws ec2 create-subnet \
 --cidr-block "${privateSubNetClusterCidrBlock}" \
 --availability-zone "${availability_zone_one}" \
 --tag-specifications ResourceType=subnet,Tags="[{Key=Name,Value='${mainSubnetName}'}, {Key=Environment,Value='lab'},{Key=Owner,Value='Myss'}]" \
 --vpc-id "${VPC_ID}" \
 --profile "${cliprofile}" \
 --region "${region}" \
 --output json)

clusterSubnetID=$(echo -e "$subnet_response" |  jq '.Subnet.SubnetId' | tr -d '"')
echo "clusterSubnetID :::::::::   ${clusterSubnetID}"
#creating  workload subnet for vpc with cidr block
echo "creating workload subnet for vpc ...."
subnet_response=$(aws ec2 create-subnet \
 --cidr-block "${privateSubNetWorkLoadCidrBlock}" \
 --availability-zone "${availability_zone_two}" \
 --tag-specifications ResourceType=subnet,Tags="[{Key=Name,Value='${workLoadSubnetName}'}, {Key=Environment,Value='lab'},{Key=Owner,Value='Myss'}]" \
 --vpc-id "${VPC_ID}" \
 --profile "${cliprofile}" \
 --region "${region}" \
 --output json)

workLoadSubnetID=$(echo -e "$subnet_response" |  jq '.Subnet.SubnetId' | tr -d '"')
echo "workLoadSubnetID ::::::::    ${workLoadSubnetID}"
#create route table for vpc
route_table_response=$(aws ec2 create-route-table \
 --vpc-id "$VPC_ID" \
 --tag-specifications ResourceType=route-table,Tags="[{Key=Name,Value='${routeTableName}'}, {Key=Environment,Value='lab'},{Key=Owner,Value='Myss'}]" \
 --profile "${cliprofile}" \
 --region "${region}" \
 --output json)
routeTableId=$(echo -e "$route_table_response" |  jq '.RouteTable.RouteTableId' | tr -d '"')
echo "routeTableId ::::::::    ${routeTableId}"
#name the route table

#add route to both Main and workload subnet
echo "associating route table to both main and workload subnet"
associate_response=$(aws ec2 associate-route-table \
 --subnet-id "${clusterSubnetID}" \
 --route-table-id "${routeTableId}" \
 --profile "${cliprofile}" \
 --region "${region}" \
 --output json)
#add route to both Main and workload subnet
associate_response=$(aws ec2 associate-route-table \
 --subnet-id "${workLoadSubnetID}" \
 --route-table-id "${routeTableId}" \
 --profile "${cliprofile}" \
 --region "${region}" \
 --output json)

./update_cli_json.sh region ${region}
./update_cli_json.sh cliprofile ${cliprofile}
./update_cli_json.sh laborpocname ${laborpocname}
./update_cli_json.sh vpc_id ${VPC_ID}
./update_cli_json.sh subnets "${clusterSubnetID},${workLoadSubnetID}" 

echo "VPC created: ${VPC_NAME} ::: ${VPC_ID} "
echo "Subnet Id's created are ::::   ${clusterSubnetID} :::: ${workLoadSubnetID}"
echo "routeTableId created ::::::::    ${routeTableId}"
echo "finshed creating VPC, subnet and routetables"
# end of create-aws-vpc

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

CLUSTER_NAME=$(echo $ALIASES | jq '.cluster.Name' -r cli-config.json)
CliProfile=$(echo $ALIASES | jq '.CliProfile' -r cli-config.json)
CLUSTER_NAME=$(echo $ALIASES | jq '.cluster' -r cli-config.json)
PocName=$(echo $ALIASES | jq '.PocName' -r cli-config.json)
OIDC_ENDPOINT=$(echo $ALIASES | jq '.OIDC_ENDPOINT' -r cli-config.json)
AWS_ACCOUNT_ID=$(echo $ALIASES | jq '.AWS_ACCOUNT_ID' -r cli-config.json)
AWS_REGION=$(echo $ALIASES | jq '.AWS_REGION' -r cli-config.json)
AWS_PARTITION="aws"
echo " CLUSTER_NAME :::: ${CLUSTER_NAME} ::: ${OIDC_ENDPOINT} :::: ${AWS_ACCOUNT_ID}"
echo " AWS_ACCOUNT_ID :::: ${AWS_ACCOUNT_ID} ::: ${AWS_REGION} :::: ${CliProfile}"

suffix="eks_cluster_poc"
instance_profile_suffix="ekspoc"
karpenter_role_name="KarpenterNodeRole${instance_profile_suffix}"
karpenter_instance_profile_name="KarpenterNodeInstanceProfile${instance_profile_suffix}"
karpenterNodeRoleArn=$(aws iam create-role \
    --role-name "${karpenter_role_name}" \
    --assume-role-policy-document file://eksNodeRole.json \
    --profile "${CliProfile}" \
    --max-session-duration 7200 |  jq '.Role.Arn' | tr -d '"')

echo "Karpenter node role :::::  $karpenterNodeRoleArn"

aws iam attach-role-policy --role-name "${karpenter_role_name}" \
    --policy-arn arn:${AWS_PARTITION}:iam::aws:policy/AmazonEKSWorkerNodePolicy \
    --profile "${CliProfile}"
aws iam attach-role-policy --role-name "${karpenter_role_name}" \
    --policy-arn arn:${AWS_PARTITION}:iam::aws:policy/AmazonEKS_CNI_Policy \
    --profile "${CliProfile}" 

aws iam attach-role-policy --role-name "${karpenter_role_name}" \
    --policy-arn arn:${AWS_PARTITION}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly \
    --profile "${CliProfile}" 

aws iam attach-role-policy --role-name "${karpenter_role_name}" \
    --policy-arn arn:${AWS_PARTITION}:iam::aws:policy/AmazonSSMManagedInstanceCore \
    --profile "${CliProfile}" 

echo "creating instance profile"


karpenterInstanceProfileArn=$(aws iam create-instance-profile \
    --profile "${CliProfile}" \
    --instance-profile-name $karpenter_instance_profile_name |  jq '.InstanceProfile.Arn' | tr -d '"')

aws iam add-role-to-instance-profile \
    --instance-profile-name $karpenter_instance_profile_name \
    --role-name $karpenter_role_name \
    --profile "${CliProfile}"

karpenterControllerRoleArn=$(aws iam create-role --role-name KarpenterControllerRole${suffix} \
    --assume-role-policy-document file://karpenter-controller-trust-policy.json \
    --profile "${CliProfile}" |  jq '.Role.Arn' | tr -d '"')

aws iam put-role-policy --role-name KarpenterControllerRole-${suffix} \
    --policy-name KarpenterControllerPolicy-${suffix} \
    --policy-document file://karpenter-controller-policy.json \
    --profile "${CliProfile}"

#./update_cli_json.sh "karpenterControllerRoleArn" ${karpenterControllerRoleArn}
#./update_cli_json.sh "karpenterInstanceProfileArn" ${karpenterInstanceProfileArn}
#./update_cli_json.sh "karpenterNodeRoleArn" ${karpenterNodeRoleArn}

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
AWSTemplateFormatVersion: 2010-09-09
Description: Amazon EKS - Node Group
Parameters:
  KeyName:
    Description: The EC2 Key Pair to allow SSH access to the instances
    Type: String
  NodeImageId:
    Description: AMI id for the node instances.
    Type: 'AWS::EC2::Image::Id'
  NodeInstanceType:
    Description: EC2 instance type for the node instances
    Type: String
    Default: t2.small
    ConstraintDescription: Must be a valid EC2 instance type
    AllowedValues:
      - t2.small
      - t2.medium
      - t2.large
      - t2.xlarge
      - t2.2xlarge
      - t3.nano
      - t3.micro
      - t3.small
      - t3.medium
      - t3.large
      - t3.xlarge
      - t3.2xlarge
      - m3.medium
      - m3.large
      - m3.xlarge
      - m3.2xlarge
      - m4.large
      - m4.xlarge
      - m4.2xlarge
      - m4.4xlarge
      - m4.10xlarge
      - m5.large
      - m5.xlarge
      - m5.2xlarge
      - m5.4xlarge
      - m5.12xlarge
      - m5.24xlarge
      - c4.large
      - c4.xlarge
      - c4.2xlarge
      - c4.4xlarge
      - c4.8xlarge
      - c5.large
      - c5.xlarge
      - c5.2xlarge
      - c5.4xlarge
      - c5.9xlarge
      - c5.18xlarge
      - i3.large
      - i3.xlarge
      - i3.2xlarge
      - i3.4xlarge
      - i3.8xlarge
      - i3.16xlarge
      - r3.xlarge
      - r3.2xlarge
      - r3.4xlarge
      - r3.8xlarge
      - r4.large
      - r4.xlarge
      - r4.2xlarge
      - r4.4xlarge
      - r4.8xlarge
      - r4.16xlarge
      - x1.16xlarge
      - x1.32xlarge
      - p2.xlarge
      - p2.8xlarge
      - p2.16xlarge
      - p3.2xlarge
      - p3.8xlarge
      - p3.16xlarge
      - p3dn.24xlarge
      - r5.large
      - r5.xlarge
      - r5.2xlarge
      - r5.4xlarge
      - r5.12xlarge
      - r5.24xlarge
      - r5d.large
      - r5d.xlarge
      - r5d.2xlarge
      - r5d.4xlarge
      - r5d.12xlarge
      - r5d.24xlarge
      - z1d.large
      - z1d.xlarge
      - z1d.2xlarge
      - z1d.3xlarge
      - z1d.6xlarge
      - z1d.12xlarge
  NodeAutoScalingGroupMinSize:
    Description: Minimum size of Node Group ASG.
    Type: Number
    Default: 1
  NodeAutoScalingGroupMaxSize:
    Description: >-
      Maximum size of Node Group ASG. Set to at least 1 greater than
      NodeAutoScalingGroupDesiredCapacity.
    Type: Number
    Default: 2
  NodeAutoScalingGroupDesiredCapacity:
    Description: Desired capacity of Node Group ASG.
    Type: Number
    Default: 1
  NodeVolumeSize:
    Description: Node volume size
    Type: Number
    Default: 20
  ClusterName:
    Description: >-
      The cluster name provided when the cluster was created. If it is
      incorrect, nodes will not be able to join the cluster.
    Type: String
  BootstrapArguments:
    Description: >-
      Arguments to pass to the bootstrap script. See files/bootstrap.sh in
      https://github.com/awslabs/amazon-eks-ami
    Type: String
    Default: ''
  NodeGroupName:
    Description: Unique identifier for the Node Group.
    Type: String
  NodeInstanceRole:
    Description: Unique identifier for the Node Instance Role.
    Type: String
  NodeInstanceRoleArn:
    Description: Unique identifier for the Node Role Arn.
    Type: String  
  EndpointSecurityGroup:
    Description: Additional VPC endpoint security group to grant to worker nodes.
    Type: 'AWS::EC2::SecurityGroup::Id'
  NodeSecurityGroup:
    Description: NodeGroup security group to grant to worker nodes.
    Type: 'AWS::EC2::SecurityGroup::Id'
  VpcId:
    Description: The VPC of the worker instances
    Type: 'AWS::EC2::VPC::Id'
  VpcCidr:
    Description: The CIDR of the VPC for the worker instances
    Type: String
  Subnets:
    Description: The subnets where workers can be created.
    Type: 'List<AWS::EC2::Subnet::Id>'
  ClusterAPIEndpoint:
    Description: Private API endpoint for EKS cluster
    Type: String
  HttpsProxy:
    Description: HTTPS proxy for access to external resources such as ECR 
    Type: String
  ClusterCA:
    Description: Certificate for EKS cluster
    Type: String
  UserToken:
    Description: Temporary Kubernetes user credentials token
    Type: String
  KubectlS3Location:
    Description: Where in S3 can the Kubectl binary be found
    Type: String
Metadata:
  'AWS::CloudFormation::Interface':
    ParameterGroups:
      - Label:
          default: EKS Cluster
        Parameters:
          - ClusterName
          - EndpointSecurityGroup
      - Label:
          default: Worker Node Configuration
        Parameters:
          - NodeInstanceRole
          - NodeInstanceRoleArn
          - NodeGroupName
          - NodeSecurityGroup
          - NodeAutoScalingGroupMinSize
          - NodeAutoScalingGroupDesiredCapacity
          - NodeAutoScalingGroupMaxSize
          - NodeInstanceType
          - NodeImageId
          - NodeVolumeSize
          - KeyName
          - BootstrapArguments
      - Label:
          default: Worker Network Configuration
        Parameters:
          - VpcId
          - Subnets

Conditions:
  UseEC2KeyPair: !Not [!Equals [!Ref KeyName, ""]]

## RESOURCES
Resources:
  NodeInstanceProfile:
    Type: 'AWS::IAM::InstanceProfile'
    Properties:
      InstanceProfileName: NodeInstanceProfile
      Path: /
      Roles:
        - !Ref NodeInstanceRole
  NodeGroup:
    Type: 'AWS::AutoScaling::AutoScalingGroup'
    Properties:
      DesiredCapacity: !Ref NodeAutoScalingGroupDesiredCapacity
      LaunchTemplate:
        LaunchTemplateId: !Ref NodeLaunchTemplate
        Version: !GetAtt NodeLaunchTemplate.LatestVersionNumber
      MinSize: !Ref NodeAutoScalingGroupMinSize
      MaxSize: !Ref NodeAutoScalingGroupMaxSize
      VPCZoneIdentifier: !Ref Subnets
      Tags:
        - Key: Name
          Value: !Sub '${ClusterName}-${NodeGroupName}-Node'
          PropagateAtLaunch: true
        - Key: !Sub 'kubernetes.io/cluster/${ClusterName}'
          Value: owned
          PropagateAtLaunch: true
    UpdatePolicy:
      AutoScalingRollingUpdate:
        MaxBatchSize: 1
        MinInstancesInService: !Ref NodeAutoScalingGroupDesiredCapacity
        PauseTime: PT5M
  NodeLaunchTemplate:
    Type: 'AWS::EC2::LaunchTemplate'
    Properties:
      LaunchTemplateName: !Sub ${AWS::StackName}-launch-template
      LaunchTemplateData:
        NetworkInterfaces:
          - DeviceIndex: 0
            AssociatePublicIpAddress: false
            Groups:
              - !Ref NodeSecurityGroup
              - !Ref EndpointSecurityGroup
        IamInstanceProfile: 
          Arn: !GetAtt
            - NodeInstanceProfile
            - Arn
        ImageId: !Ref NodeImageId
        InstanceType: !Ref NodeInstanceType
        KeyName: !If [UseEC2KeyPair, !Ref KeyName, !Ref "AWS::NoValue"]
        BlockDeviceMappings:
          - DeviceName: /dev/xvda
            Ebs:
              VolumeSize: !Ref NodeVolumeSize
              VolumeType: gp2
              DeleteOnTermination: true
        UserData:
          'Fn::Base64': !Sub |
            #!/bin/bash

            set -o xtrace
            echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ inside user data @@@@@@@@@@@@@@@@@"
            echo "installing SSM agent$$$$$$$$$$$$$$$$$$$$$$$$"
            # Install the SSM Agent so we can remotely access the worker node if necessary
            yum install -y amazon-ssm-agent 
            systemctl enable amazon-ssm-agent
            systemctl start amazon-ssm-agent
            systemctl status amazon-ssm-agent

            CLUSTER_API_HOSTNAME=`basename ${ClusterAPIEndpoint}`
            echo " cluster api hostname :::: $CLUSTER_API_HOSTNAME"
            echo "downloading from s3 ....."
            aws s3 cp ${KubectlS3Location} /tmp/kubectl --region ${AWS::Region}
            chmod 755 /tmp/kubectl

            /tmp/kubectl config set-cluster cfc --server=${ClusterAPIEndpoint}
            /tmp/kubectl config set clusters.cfc.certificate-authority-data ${ClusterCA}
            /tmp/kubectl config set-credentials user --token=${UserToken}
            /tmp/kubectl config set-context cfc --cluster=cfc --user=user
            /tmp/kubectl config use-context cfc
            
            echo "applying kubectl on aws auth "
            cat <<EOF >/tmp/aws-auth-cm.yaml
            apiVersion: v1
            kind: ConfigMap
            metadata:
              name: aws-auth
              namespace: kube-system
            data:
              mapRoles: |
                - rolearn: '${NodeInstanceRoleArn}'
                  username: system:node:{{EC2PrivateDNSName}}
                  groups:
                    - system:bootstrappers
                    - system:nodes
            EOF

            /tmp/kubectl get cm -n kube-system aws-auth
            if [ $? -ne 0 ]; 
            then
              echo "applying kubectl aws auth"
              /tmp/kubectl apply -f /tmp/aws-auth-cm.yaml
            fi

            if [ "${HttpsProxy}" != "" ];
            then
            cat <<EOF >/tmp/http-proxy.conf
            [Service]
            Environment="https_proxy=${HttpsProxy}"
            Environment="HTTPS_PROXY=${HttpsProxy}"
            Environment="http_proxy=${HttpsProxy}"
            Environment="HTTP_PROXY=${HttpsProxy}"
            Environment="NO_PROXY=169.254.169.254,${VpcCidr},$CLUSTER_API_HOSTNAME,s3.amazonaws.com,s3.${AWS::Region}.amazonaws.com,ec2.${AWS::Region}.amazonaws.com,ecr.${AWS::Region}.amazonaws.com,dkr.ecr.${AWS::Region}.amazonaws.com"
            EOF
            
            mkdir -p /usr/lib/systemd/system/docker.service.d
            cp /tmp/http-proxy.conf /etc/systemd/system/kubelet.service.d/
            cp /tmp/http-proxy.conf /usr/lib/systemd/system/docker.service.d/
            fi

            /etc/eks/bootstrap.sh ${ClusterName} --b64-cluster-ca ${ClusterCA} --apiserver-endpoint ${ClusterAPIEndpoint} --kubelet-extra-args "--node-labels=workergroup=${NodeGroupName}" ${BootstrapArguments}

            systemctl daemon-reload
            systemctl restart docker

            yum install -y iptables-services
            iptables --insert FORWARD 1 --in-interface eni+ --destination 169.254.169.254/32 --jump DROP
            iptables-save | tee /etc/sysconfig/iptables 
            systemctl enable --now iptables

            /opt/aws/bin/cfn-signal --exit-code $? \
                    --stack  ${AWS::StackName} \
                    --resource NodeGroup  \
                    --region ${AWS::Region}
