# Cloud-DDOS_NACL_Lambda

The Lambda function verifies if there is a change in the IP address of the customer FQDN due to DNS diversion while under attack and creates a NACL on demand which allows the protected assets to be accessible only from SD IP addresses range. 


Lambda permissions:

{ 

    "Version": "2012-10-17", 

    "Statement": [ 

        { 

            "Sid": "VisualEditor0", 

            "Effect": "Allow", 

            "Action": [ 

                "ec2:DeleteTags", 

                "logs:DeleteLogGroup", 

                "logs:PutDestinationPolicy", 

                "lambda:GetFunction", 

                "ec2:CreateTags", 

                "lambda:UpdateFunctionConfiguration", 

                "iam:CreateRole", 

                "iam:DeleteRole", 

                "lambda:GetFunctionConfiguration", 

                "logs:CreateLogGroup", 

                "logs:DeleteLogStream", 

                "logs:PutLogEvents", 

                "ec2:ReplaceNetworkAclAssociation", 

   "ec2:CreateNetworkInterface", 

                "logs:CreateLogStream", 

                "ec2:CreateNetworkAcl", 

                "logs:DeleteLogDelivery", 

                "ec2:DescribeSubnets", 

                "ec2:DescribeNetworkAcls", 

                "ec2:CreateNetworkAclEntry", 

                "ec2:DeleteNetworkAcl", 

                "ec2:DeleteNetworkAclEntry" 

            ], 

            "Resource": "*" 

        } 

    ] 

} 
