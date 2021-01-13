import boto3
import socket
import os
NACL_rule_number = 125
 
def lambda_handler(event, context):
    
    # GetCurrentAssetIP:
        # Get the current Asset IP adress 
        # Returen list of IP's
    def GetCurrentAssetIP(fqdn):
        list_of_ips = socket.gethostbyname_ex(fqdn)
        return list_of_ips[2]
    
    # CheckIpChange:
        # Checks if the the list of the current IP's are matach to the
        # Peacetime (real ips) of the customer
        # all this IP's are SD IP which will be used as SNAT to reach this VPC 
        # Adding all this IP's of SD to the NACL that will be created on demand.
    def CheckIpChange(ip_list):
        status = 0
        new_changed_ip_list = []
        for i in range(len(ip_list)):
            if ip_list[i] not in customer_peace_ip:
                new_changed_ip_list.append(ip_list[i])
                status = 1  # 1 - Under Attack
        return status
    
    def UpdateAclEntry_Outbound(nacl_obj):
         nacl_obj.create_entry(
                CidrBlock= "0.0.0.0/0",
                DryRun=False,
                Egress=True,
                Protocol="-1",
                RuleAction='allow',
                RuleNumber=11
            )
    # UpdateAclEntry:
        # Recieve: NACL object, IP to add (as source), rule number of the NACL, port,protocol
        # Update the SD NACL with new IP's to allowed while under attack
    def UpdateAclEntry(nacl_obj,ip_to_add,rule_number_start,port,Protocol):
        global NACL_rule_number
        code = 123
        if Protocol == 1:
            code = -1
        for sub_add in range(len(ip_to_add)):
            nacl_obj.create_entry(
                CidrBlock= ip_to_add[sub_add],
                DryRun=False,
                Egress=False,
                IcmpTypeCode={
                    'Code': code,
                    'Type': code
                },
                PortRange={
                    'From': port,
                    'To': port
                },
                Protocol=Protocol,
                RuleAction='allow',
                RuleNumber=NACL_rule_number
            )
            NACL_rule_number += 1
    
    #AddPrefixToip:
        #Add prefiex /32 to the ip list provided from the customer
    def AddPrefixToip(ip_list):
        new_ip_list = [s + "/32" for s in ip_list]
        return new_ip_list
    
    
    def CreateNacl(acl_name,vpc):
        ncl = vpc.create_network_acl(
            DryRun=False,
            TagSpecifications=[
                {
                    'ResourceType': 'network-acl',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': acl_name
                        },
                    ]
                },
            ])
        return ncl
    
    def DeleteNacl(acl_obj):
        acl_obj.delete(
            DryRun=False,
        )
    
    # GetAclAsscociateBySubnetId:
        # Recieve: Source NACL object which the subnet is located in 
        # Retrun the ACL assoicate id for this subnet
    def GetAclAsscociateBySubnetId(source_acl_asscociate,subnet_id):
        acl_asscociate = source_acl_asscociate.associations
        for index in range(len(acl_asscociate)):
            if acl_asscociate[index]["SubnetId"] == subnet_id:
                return acl_asscociate[index]["NetworkAclAssociationId"]
        return None
    
    # UpdateAclForSubnet:
        # Recieve: Source NACL object which the subnet is located in,subnet id we want to add 
        # Function will update the subnet assoicate id in the new ACL object (nacl_obj)
    def UpdateAclForSubnet(source_acl_asscociate,nacl_obj,subnet_id_list):
        
        #print(Acl_associantionId)
        #Checks if the subnet is located in the current NACL assoicate list
        for i in range(len(subnet_id_list)):
            Acl_associantionId = GetAclAsscociateBySubnetId(source_acl_asscociate,subnet_id_list[i])
            if Acl_associantionId != None:
                print(Acl_associantionId)
                nacl_obj.replace_association(
                AssociationId=Acl_associantionId,
                DryRun=False,
                )
            else:
                print("Subnet Doesnt Exist in Default ACL")
    
    # GetIdOfNacl:
        # Recieve: Vpc object ,get all the NACL in the current VPC(vpc_obj.network_acls.all())
        # Function checks 
        # Retrun the ACL assoicate id for this subnet
    def GetIdOfNacl(vpc_obj):
        network_acl_iterator = vpc_obj.network_acls.all()
        for i in network_acl_iterator:
            if len(i.tags) != 0:
                for index in range(len(i.tags)):
                    if i.tags[index]["Value"] == "Under_attack":
                        print(i.tags[index]["Value"])
                        return i
    
    
    def UpdateAttack_state(region,Lambda_name,state,nacl_state):
        client = boto3.client('lambda', region_name=region)
        client.update_function_configuration(
        FunctionName=Lambda_name,
        Environment={
            'Variables': {
                'Attack_state': state,
                'NACL_status': nacl_state,
                'customer_ip': os.environ['customer_ip'],
                'customer_url': os.environ['customer_url'],
                'prod_nacl_id': os.environ['prod_nacl_id'],
                'subnet_id': ",".join(os.environ['subnet_id'].split(",")),
                'vpc_id': os.environ.get('vpc_id'),
                'sd_ip_subnet':os.environ['sd_ip_subnet'],
                'port_list':os.environ['port_list'],
                
            }
        }
        )
    # UpdateMultipleAclEntries:
        # Recieve: list of ports to open in NACL
        # Function create NACL entry with specified port  
    def UpdateMultipleAclEntries(ports_to_add_list):
        plist = ports_to_add_list.split(",")
        for port in range(len(plist)):
            if plist[port] == "0":
                UpdateAclEntry(nac_id,ip_to_add, NACL_rule_number,int(plist[port]),'1')
            UpdateAclEntry(nac_id,ip_to_add, NACL_rule_number,int(plist[port]),'6')    

        
    ## Main ##
    
    Region = context.invoked_function_arn.split(":")[3]
    FunctionName= context.function_name
    
    ec2 = boto3.resource('ec2', region_name=Region)
    prod_nacl = ec2.NetworkAcl(os.environ['prod_nacl_id'])
    subnet_prod_id = os.environ['subnet_id'].split(",")	
    vpc = ec2.Vpc(os.environ.get('vpc_id'))
    customer_url = os.environ['customer_url']
    peacetimeIPList = os.environ['customer_ip'].split()	
    customer_peace_ip = AddPrefixToip(peacetimeIPList)
    current_customer_ip = AddPrefixToip(GetCurrentAssetIP(customer_url))
    print("Asset ip in Pacetime: {}".format(customer_peace_ip))
    print("Currnet Asset ip: {}".format(current_customer_ip))
    print("Attacks State: {}".format(os.environ['Attack_state']))

    ip_to_add =  os.environ['sd_ip_subnet'].split()
    attack_status = CheckIpChange(current_customer_ip)
    
    if attack_status == 1 and os.environ['Attack_state'] == "0":
        print("The Asset is curently Under Attack")
        UpdateAttack_state(Region,FunctionName,"1","1")
        print("NACL is associate with {} subnet".format(os.environ['subnet_id']))
        nac_id = CreateNacl("Under_attack", vpc)
        UpdateAclEntry_Outbound(nac_id)
        UpdateMultipleAclEntries(os.environ['port_list'])
        UpdateAclForSubnet(prod_nacl, nac_id, subnet_prod_id)
        
    
    if attack_status == 0:
        UpdateAttack_state(Region,FunctionName,"0","0")
        print("Peactime")
        if os.environ['NACL_status'] == "1":
            SD_Acl_obj = GetIdOfNacl(vpc)
            UpdateAclForSubnet(SD_Acl_obj,prod_nacl, subnet_prod_id)
            SD_Acl_obj.delete(DryRun=False)
