
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

Region=$(echo $ALIASES | jq '.Region' -r cli-config.json)
CliProfile=$(echo $ALIASES | jq '.CliProfile' -r cli-config.json)
PocName=$(echo $ALIASES | jq '.PocName' -r cli-config.json)
clusterName=$(echo $ALIASES | jq '.EksClusterName' -r cli-config.json)
VpcId=$(echo $ALIASES | jq '.VpcId' -r cli-config.json)
vpc_default_sg_id=$(echo $ALIASES | jq '.VpcDefaultSG' -r cli-config.json)
cluster_sharednode_sg_id=$(echo $ALIASES | jq '.EksClusterSharedNodeSG' -r cli-config.json)

if [ -z "${cluster_sharednode_sg_id}" ]; then
    echo "creating cluster shared node security group....."
    cluster_sharednode_sg_id=$(aws ec2 create-security-group \
        --group-name "${clusterName}-ClusterSharedNodeSecurityGroup" \
        --description "Communication between all nodes in the cluster" \
        --vpc-id ${VpcId} \
        --tag-specifications ResourceType=security-group,Tags="[{Key=Name,Value='${clusterName}-ClusterSharedNodeSecurityGroup'}, {Key=Environment,Value='lab'},{Key=Owner,Value='Myss'}]" \
        --profile ${CliProfile} \
        --region ${Region} \
        --output json | jq '.GroupId' | tr -d '"' )

    echo "created cluster shared node security group :::: ${cluster_sharednode_sg_id}"
    ./update_cli_json.sh "EksClusterSharedNodeSG" ${cluster_sharednode_sg_id}
fi

#start worker node security groups rules
aws ec2 authorize-security-group-ingress \
    --group-id ${cluster_sharednode_sg_id} \
    --ip-permissions  --ip-permissions IpProtocol=tcp,FromPort=443,ToPort=443,UserIdGroupPairs="[{GroupId=$vpc_default_sg_id}]" \
    --profile ${CliProfile} \
    --region ${Region}

aws ec2 authorize-security-group-ingress \
    --group-id ${cluster_sharednode_sg_id} \
    --ip-permissions  --ip-permissions IpProtocol=tcp,FromPort=1025,ToPort=65535,UserIdGroupPairs="[{GroupId=$vpc_default_sg_id}]" \
    --profile ${CliProfile} \
    --region ${Region}

aws ec2 authorize-security-group-ingress \
    --group-id ${cluster_sharednode_sg_id} \
    --ip-permissions IpProtocol=all,FromPort=-1,ToPort=1,UserIdGroupPairs="[{GroupId=${cluster_sharednode_sg_id},Description='all traffic from worker nodes'}]" \
    --profile ${CliProfile} \
    --region ${Region}
echo "completed worker node security group rules :: ${cluster_sharednode_sg_id}"
#end worker node security group rules

#start default security groups rules
aws ec2 authorize-security-group-ingress \
    --group-id ${vpc_default_sg_id} \
    --ip-permissions  --ip-permissions IpProtocol=tcp,FromPort=443,ToPort=443,UserIdGroupPairs="[{GroupId=$cluster_sharednode_sg_id}]" \
    --profile ${CliProfile} \
    --region ${Region}

aws ec2 revoke-security-group-egress \
    --group-id ${vpc_default_sg_id} \
    --ip-permissions  --ip-permissions IpProtocol=all,FromPort=-1,ToPort=1,IpRanges="[{CidrIp=0.0.0.0/0}]" \
    --profile ${CliProfile} \
    --region ${Region}

aws ec2 authorize-security-group-egress \
    --group-id ${vpc_default_sg_id} \
    --ip-permissions  --ip-permissions IpProtocol=tcp,FromPort=1025,ToPort=65535,UserIdGroupPairs="[{GroupId=$cluster_sharednode_sg_id}]" \
    --profile ${CliProfile} \
    --region ${Region}
aws ec2 authorize-security-group-egress \
    --group-id ${vpc_default_sg_id} \
    --ip-permissions  --ip-permissions IpProtocol=tcp,FromPort=443,ToPort=443,UserIdGroupPairs="[{GroupId=$cluster_sharednode_sg_id}]" \
    --profile ${CliProfile} \
    --region ${Region}

echo "completed default security group rules :: ${vpc_default_sg_id}"

#start default security groups rules
