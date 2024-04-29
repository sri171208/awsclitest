
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

#&&&&&&&&&&&&&&&&
set -e
folder="./"
files=()
echo "start to find json under folder: "$folder
find $folder -name  "*-config.json" -print0 >tmpfile
while IFS=  read -r -d $'\0'; do
    files+=("$REPLY")
done < tmpfile
echo ${files[@]} #print all

echo "input file: " ${files[$i]}
jq -r '."'${key}'" = "'${value}'"' "${files[$i]}" > "${files[$i]}.new"
echo "${files[$i]}.new""===>""${files[$i]}"
mv "${files[$i]}.new" "${files[$i]}"
