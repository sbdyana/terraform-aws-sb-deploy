################################################################################
# Policy Module - Load configurations from YAML
################################################################################

module "policy" {
  #source = "../terraform-mirae-policy"
  source  = "app.terraform.io/sb-github/policy/mirae"
  version = "1.0.0"

  region      = var.region
  project     = var.project
  environment = var.environment
  policy_file = var.policy_file
}

################################################################################
# AWS Account ID (for IAM ARN generation in locals)
################################################################################

data "aws_caller_identity" "current" {}

################################################################################
# VPC Module
################################################################################

module "vpc" {
  #source = "../terraform-aws-vpc"
  source  = "app.terraform.io/sb-github/vpc/aws"
  version = "1.0.0"
  # VPC
  vpc_name = local.resolved_vpc_name
  vpc_cidr = local.resolved_vpc_cidr

  # Subnets
  subnet_names              = local.resolved_subnet_names
  subnet_cidr_blocks        = local.resolved_subnet_cidrs
  subnet_availability_zones = local.resolved_subnet_zones

  # Route Tables
  route_table_names        = local.resolved_route_table_names
  route_table_associations = local.resolved_route_table_associations

  # Routes
  route_names                   = local.resolved_route_names
  route_route_table_names       = local.resolved_route_route_table_names
  route_destination_cidr_blocks = local.resolved_route_destination_cidrs

  # Tags
  tags = local.default_tags
}

################################################################################
# Security Group Module
################################################################################

module "security_group" {
  source   = "../terraform-aws-security-group"
  for_each = local.security_groups

  name        = each.value.name
  description = each.value.description
  vpc_id      = module.vpc.vpc_id

  # Rules
  rule_names        = local.sg_rules[each.key].names
  rule_types        = local.sg_rules[each.key].types
  rule_descriptions = local.sg_rules[each.key].descriptions
  rule_cidr_ipv4    = local.sg_rules[each.key].cidrs_ipv4
  rule_cidr_ipv6    = local.sg_rules[each.key].cidrs_ipv6
  rule_ip_protocols = local.sg_rules[each.key].protocols
  rule_from_ports   = local.sg_rules[each.key].from_ports
  rule_to_ports     = local.sg_rules[each.key].to_ports

  tags = local.default_tags
}

# ################################################################################
# # VPC Endpoint Module
# ################################################################################

# module "vpc_endpoint" {
#   source = "../terraform-aws-endpoint"

#   name   = local.base_name
#   vpc_id = module.vpc.vpc_id

#   # Endpoints
#   vpc_endpoint_names               = local.vpce_names
#   vpc_endpoint_service_names       = local.vpce_service_names
#   vpc_endpoint_types               = local.vpce_types
#   vpc_endpoint_private_dns_enabled = local.vpce_private_dns_enabled

#   # Gateway 타입: Route Table 연결
#   vpc_endpoint_route_table_ids = {
#     for name, rt_names in local.vpce_route_table_ids : name => [
#       for rt_name in rt_names : module.vpc.route_table_ids[rt_name]
#     ]
#   }

#   # Interface 타입: Subnet 연결
#   vpc_endpoint_subnet_ids = {
#     for name, sbn_names in local.vpce_subnet_ids : name => [
#       for sbn_name in sbn_names : module.vpc.subnet_ids[sbn_name]
#     ]
#   }

#   # Interface 타입: Security Group 연결
#   vpc_endpoint_security_group_ids = {
#     for name, sg_names in local.vpce_security_group_ids : name => [
#       for sg_name in sg_names : module.security_group[
#         [for k, v in local.security_groups : k if v.name == sg_name][0]
#       ].security_group_id
#     ]
#   }

#   tags = local.default_tags
# }

# ################################################################################
# # ElastiCache Module (Simplified - Object Map)
# ################################################################################

# module "elasticache" {
#   source = "../terraform-aws-elasticache"

#   # Subnet Groups (객체 맵)
#   subnet_groups = {
#     for sg_name, sg in local.elasticache_subnet_groups : sg_name => {
#       description = sg.description
#       subnet_ids = [
#         for sbn_name in local.elasticache_subnet_group_subnet_names[sg_name] :
#         module.vpc.subnet_ids[sbn_name]
#       ]
#     }
#   }

#   # Parameter Groups (객체 맵)
#   parameter_groups = local.elasticache_parameter_groups

#   # Replication Groups (객체 맵)
#   replication_groups = {
#     for rg_name, rg in local.elasticache_replication_groups_base : rg_name => {
#       engine                     = rg.engine
#       engine_version             = rg.engine_version
#       description                = rg.description
#       node_type                  = rg.node_type
#       port                       = rg.port
#       num_cache_clusters         = rg.num_cache_clusters
#       num_node_groups            = rg.num_node_groups
#       replicas_per_node_group    = rg.replicas_per_node_group
#       automatic_failover_enabled = rg.automatic_failover_enabled
#       multi_az_enabled           = rg.multi_az_enabled
#       at_rest_encryption_enabled = rg.at_rest_encryption_enabled
#       transit_encryption_enabled = rg.transit_encryption_enabled
#       transit_encryption_mode    = rg.transit_encryption_mode
#       auth_token                 = rg.auth_token
#       kms_key_id                 = rg.kms_key_id
#       snapshot_retention_limit   = rg.snapshot_retention_limit
#       snapshot_window            = rg.snapshot_window
#       maintenance_window         = rg.maintenance_window
#       auto_minor_version_upgrade = rg.auto_minor_version_upgrade
#       apply_immediately          = rg.apply_immediately
#       # 참조 해석
#       subnet_group_name           = try(local.ec_subnet_group_name_map[rg._yaml_key], null)
#       parameter_group_name        = try(local.ec_parameter_group_name_map[rg._yaml_key], null)
#       preferred_cache_cluster_azs = length(rg._preferred_azs) > 0 ? rg._preferred_azs : null
#       security_group_ids = [
#         for sg_key in rg._security_group_keys :
#         module.security_group[sg_key].security_group_id
#       ]
#     }
#   }

#   tags = local.default_tags
# }

# ################################################################################
# # EC2 Instance Module (Object Map Pattern - Simplified)
# ################################################################################

# module "ec2_instance" {
#   source = "../terraform-aws-ec2-instance"

#   instances       = local.ec2_instances
#   ebs_volumes     = local.ec2_ebs_volumes
#   ebs_attachments = local.ec2_ebs_attachments
#   eips            = local.ec2_eips

#   tags = local.default_tags
# }

# ################################################################################
# # OpenSearch Module (Object Map Pattern - Simplified)
# ################################################################################

# module "opensearch" {
#   source = "../terraform-aws-opensearch"

#   domains       = local.opensearch_domains
#   saml_options  = local.opensearch_saml_options
#   vpc_endpoints = local.opensearch_vpc_endpoints

#   tags = local.default_tags
# }

# ################################################################################
# # EKS Module - Cluster Only
# # 1단계: EKS 클러스터만 생성 (Node Group, Addon은 IRSA 이후에 생성)
# ################################################################################

# module "eks_cluster" {
#   source = "../terraform-aws-eks"
#   count  = local.resolved_eks_name != null ? 1 : 0

#   # Module Control - 클러스터만 생성
#   create_cluster     = true
#   create_node_groups = false
#   create_addons      = false

#   # Cluster Configuration
#   name             = local.resolved_eks_name
#   cluster_version  = local.resolved_eks_cluster_version
#   cluster_role_arn = local.resolved_eks_cluster_role_arn

#   # Subnet IDs for Cluster
#   subnet_ids = [
#     for sbn_name in local.eks_cluster_subnet_names : module.vpc.subnet_ids[sbn_name]
#   ]

#   # Security Group IDs for Cluster
#   security_group_ids = [
#     for sg_name in local.eks_cluster_security_group_names :
#     module.security_group[
#       [for k, v in local.security_groups : k if v.name == sg_name][0]
#     ].security_group_id
#   ]

#   # Endpoint Configuration
#   endpoint_private_access = local.resolved_eks_endpoint_private_access
#   endpoint_public_access  = local.resolved_eks_endpoint_public_access
#   public_access_cidrs     = local.resolved_eks_public_access_cidrs

#   # Network Configuration
#   service_ipv4_cidr = local.resolved_eks_service_ipv4_cidr
#   ip_family         = local.resolved_eks_ip_family

#   # Logging
#   enabled_cluster_log_types = local.resolved_eks_enabled_cluster_log_types

#   # Authentication
#   authentication_mode                         = local.resolved_eks_authentication_mode
#   bootstrap_cluster_creator_admin_permissions = local.resolved_eks_bootstrap_cluster_creator_admin_permissions

#   # Encryption
#   encryption_config_key_arn = local.resolved_eks_encryption_config_key_arn

#   # Upgrade Policy
#   upgrade_policy_support_type = local.resolved_eks_upgrade_policy_support_type

#   # Access Entries
#   access_entry_principal_arns   = local.resolved_eks_access_entry_principal_arns
#   access_entry_types            = local.resolved_eks_access_entry_types
#   access_entry_kubernetes_groups = local.resolved_eks_access_entry_kubernetes_groups

#   # Access Policy Associations
#   access_policy_associations = local.resolved_eks_access_policy_associations

#   tags = local.default_tags

#   # EKS는 Pre-EKS IAM 역할(Cluster Role)이 먼저 생성되어야 함
#   depends_on = [module.iam_pre_eks]
# }

# ################################################################################
# # IAM Module - Pre-EKS (EKS Cluster/Node Role 등)
# # EKS 클러스터 생성 전에 필요한 IAM 역할들
# ################################################################################

# module "iam_pre_eks" {
#   source = "../terraform-aws-iam"

#   # IAM Roles (is_oidc_template: false) - 객체 맵 형태
#   roles = local.iam_roles_pre_eks

#   # OIDC Providers - Pre-EKS에서는 일반 OIDC만 (EKS OIDC는 Post-EKS에서)
#   oidc_providers = local.iam_oidc_providers

#   tags = local.default_tags
# }

# ################################################################################
# # EKS OIDC Thumbprint (for IRSA)
# ################################################################################

# data "tls_certificate" "eks" {
#   count = length(local.iam_eks_oidc_providers) > 0 && length(module.eks_cluster) > 0 ? 1 : 0

#   url = module.eks_cluster[0].cluster_oidc_issuer_url
# }

# ################################################################################
# # IAM Module - Post-EKS (IRSA Roles + EKS OIDC Provider)
# # EKS OIDC Provider가 필요한 IRSA 역할들
# ################################################################################

# module "iam_post_eks" {
#   source = "../terraform-aws-iam"
#   count  = length(local.iam_roles_post_eks) > 0 || length(local.iam_eks_oidc_providers) > 0 ? 1 : 0

#   # IAM Roles (is_oidc_template: true - IRSA) - 객체 맵 형태
#   roles = local.iam_roles_post_eks

#   # EKS OIDC Providers
#   oidc_providers = length(local.iam_eks_oidc_providers) > 0 && length(module.eks_cluster) > 0 ? {
#     for key, cfg in local.iam_eks_oidc_providers : key => {
#       url             = module.eks_cluster[0].cluster_oidc_issuer_url
#       client_id_list  = cfg.client_id_list
#       thumbprint_list = [data.tls_certificate.eks[0].certificates[0].sha1_fingerprint]
#     }
#   } : {}

#   tags = local.default_tags

#   depends_on = [module.eks_cluster]
# }

# ################################################################################
# # EKS Module - Workloads (Node Groups + Addons)
# # 3단계: IRSA 역할 생성 후 Node Group과 Addon 생성
# ################################################################################

# module "eks_workloads" {
#   source = "../terraform-aws-eks"
#   count  = local.resolved_eks_name != null ? 1 : 0

#   # Module Control - 기존 클러스터 사용, Node Group + Addon만 생성
#   create_cluster     = false
#   create_node_groups = true
#   create_addons      = true
#   cluster_name       = local.resolved_eks_name

#   # Cluster Configuration (클러스터 참조용)
#   name             = local.resolved_eks_name
#   cluster_role_arn = local.resolved_eks_cluster_role_arn

#   # Subnet IDs (클러스터 참조용)
#   subnet_ids = [
#     for sbn_name in local.eks_cluster_subnet_names : module.vpc.subnet_ids[sbn_name]
#   ]

#   # Network Configuration (Launch Template userdata용)
#   service_ipv4_cidr = local.resolved_eks_service_ipv4_cidr

#   # Node Groups
#   node_group_names     = local.eks_node_group_names
#   node_group_role_arns = local.resolved_eks_node_group_role_arns

#   node_group_subnet_ids = [
#     for ng_name in local.eks_ng_keys : [
#       for sbn_name in local.eks_node_group_subnet_names[ng_name] : module.vpc.subnet_ids[sbn_name]
#     ]
#   ]

#   node_group_instance_types      = local.resolved_eks_node_group_instance_types
#   node_group_ami_types           = local.resolved_eks_node_group_ami_types
#   node_group_node_repair_enabled = local.resolved_eks_node_group_node_repair_enabled
#   node_group_capacity_types             = local.resolved_eks_node_group_capacity_types
#   node_group_disk_sizes                 = local.resolved_eks_node_group_disk_sizes
#   node_group_desired_sizes              = local.resolved_eks_node_group_desired_sizes
#   node_group_min_sizes                  = local.resolved_eks_node_group_min_sizes
#   node_group_max_sizes                  = local.resolved_eks_node_group_max_sizes
#   node_group_max_unavailable            = local.resolved_eks_node_group_max_unavailable
#   node_group_max_unavailable_percentage = local.resolved_eks_node_group_max_unavailable_percentage
#   node_group_labels                     = local.resolved_eks_node_group_labels
#   node_group_taints                     = local.resolved_eks_node_group_taints

#   # Launch Templates
#   launch_template_names          = [for lt_name in values(local.eks_launch_template_names) : lt_name]
#   launch_template_ami_ids        = local.eks_launch_template_ami_ids
#   launch_template_instance_types = local.eks_launch_template_instance_types

#   launch_template_security_group_ids = {
#     for lt_name, sg_names in local.eks_launch_template_security_group_names :
#     lt_name => [
#       for sg_name in sg_names :
#       module.security_group[
#         [for k, v in local.security_groups : k if v.name == sg_name][0]
#       ].security_group_id
#     ]
#   }

#   launch_template_block_device_mappings  = local.eks_launch_template_block_device_mappings
#   launch_template_metadata_options       = local.eks_launch_template_metadata_options
#   launch_template_ebs_optimized          = local.eks_launch_template_ebs_optimized
#   launch_template_monitoring_enabled     = local.eks_launch_template_monitoring_enabled
#   launch_template_node_config            = local.eks_launch_template_node_config
#   launch_template_tag_specifications     = local.eks_launch_template_tag_specifications

#   # Node Group Launch Template References
#   node_group_launch_template_refs = local.eks_node_group_launch_template_refs

#   # Addons
#   addon_names                       = local.resolved_eks_addon_names
#   addon_versions                    = local.resolved_eks_addon_versions
#   addon_resolve_conflicts_on_create = local.resolved_eks_addon_resolve_conflicts_on_create
#   addon_resolve_conflicts_on_update = local.resolved_eks_addon_resolve_conflicts_on_update
#   addon_service_account_role_arns   = local.resolved_eks_addon_service_account_role_arns
#   addon_configuration_values        = local.resolved_eks_addon_configuration_values
#   addon_preserve_on_delete          = local.resolved_eks_addon_preserve_on_delete

#   tags = local.default_tags

#   # IRSA 역할이 먼저 생성되어야 함
#   depends_on = [module.iam_post_eks]
# }

# ################################################################################
# # RDS Aurora Module (Object Map Pattern - Simplified)
# ################################################################################

# module "rds_aurora" {
#   source = "../terraform-aws-rds-aurora"

#   subnet_groups            = local.rds_subnet_groups
#   parameter_groups         = local.rds_parameter_groups
#   cluster_parameter_groups = local.rds_cluster_parameter_groups
#   clusters                 = local.rds_clusters

#   tags = local.default_tags
# }

# ################################################################################
# # EFS Module (Object Map Pattern - Simplified)
# ################################################################################

# module "efs" {
#   source = "../terraform-aws-efs"

#   file_systems = local.efs_file_systems

#   tags = local.default_tags
# }

# ################################################################################
# # Launch Template Module
# ################################################################################

# module "launchtemplate" {
#   source = "../terraform-aws-launchtemplate"

#   launch_template_names                 = local.autoscaling_launch_template_names
#   launch_template_descriptions          = local.autoscaling_launch_template_descriptions
#   launch_template_amis                  = local.autoscaling_launch_template_amis
#   launch_template_instance_types        = local.autoscaling_launch_template_instance_types
#   launch_template_key_names             = local.autoscaling_launch_template_key_names
#   launch_template_security_group_ids    = local.autoscaling_launch_template_security_group_ids
#   launch_template_iam_instance_profiles = local.autoscaling_launch_template_iam_instance_profiles
#   launch_template_user_data             = local.autoscaling_launch_template_user_data
#   launch_template_block_device_mappings = local.autoscaling_launch_template_block_device_mappings
#   launch_template_tags                  = local.autoscaling_launch_template_tags

#   tags = local.default_tags
# }

# ################################################################################
# # ALB Module
# ################################################################################

# module "alb" {
#   source   = "../terraform-aws-alb"
#   for_each = local.albs

#   name               = each.value.name
#   load_balancer_type = each.value.load_balancer_type
#   internal           = each.value.internal
#   security_groups    = each.value.security_group_ids
#   subnets            = each.value.subnet_ids

#   target_group_names         = each.value.target_group_keys
#   target_group_name_prefix   = each.value.target_group_name_prefix
#   target_group_name_types    = { for k in each.value.target_group_keys : k => each.value.target_groups[k].type }
#   target_group_ports         = [for k in each.value.target_group_keys : each.value.target_groups[k].port]
#   target_group_protocols     = [for k in each.value.target_group_keys : each.value.target_groups[k].protocol]
#   target_group_target_types  = [for k in each.value.target_group_keys : each.value.target_groups[k].target_type]
#   target_group_vpc_id        = module.vpc.vpc_id
#   target_group_health_checks = { for k in each.value.target_group_keys : k => each.value.target_groups[k].health_check }

#   listener_names            = each.value.listener_keys
#   listener_ports            = [for k in each.value.listener_keys : each.value.listeners[k].port]
#   listener_protocols        = [for k in each.value.listener_keys : each.value.listeners[k].protocol]
#   listener_ssl_policies     = [for k in each.value.listener_keys : each.value.listeners[k].ssl_policy]
#   listener_certificate_arns = [for k in each.value.listener_keys : each.value.listeners[k].certificate_arn]
#   listener_default_actions = {
#     for k in each.value.listener_keys : k => {
#       type              = each.value.listeners[k].default_action.type
#       target_group_name = each.value.listeners[k].default_action.target_group
#       order             = each.value.listeners[k].default_action.order
#       redirect          = each.value.listeners[k].default_action.redirect
#       fixed_response    = each.value.listeners[k].default_action.fixed_response
#       forward           = each.value.listeners[k].default_action.forward
#     }
#   }

#   tags = local.default_tags
# }

# ################################################################################
# # Auto Scaling Module
# ################################################################################

# module "autoscaling" {
#   source = "../terraform-aws-autoscaling"

#   asg_names = local.autoscaling_asg_names
#   asg_launch_template_ids = [
#     for lt_ref in local.autoscaling_asg_launch_template_refs :
#     module.launchtemplate.launch_template_ids[local.autoscaling_launch_template_name_map[lt_ref]]
#   ]

#   asg_min_sizes                  = local.autoscaling_asg_min_sizes
#   asg_max_sizes                  = local.autoscaling_asg_max_sizes
#   asg_desired_capacities         = local.autoscaling_asg_desired_capacities
#   asg_vpc_zone_identifiers       = local.autoscaling_asg_vpc_zone_identifiers
#   asg_target_group_arns          = local.autoscaling_asg_target_group_arns
#   asg_health_check_types         = local.autoscaling_asg_health_check_types
#   asg_health_check_grace_periods = local.autoscaling_asg_health_check_grace_periods

#   tags = local.default_tags

#   depends_on = [module.launchtemplate, module.alb]
# }

# ################################################################################
# # Key Pair Module
# ################################################################################

# module "key_pair" {
#   source = "../terraform-aws-key-pair"

#   key_pair_names               = local.resolved_key_pair_names
#   key_pair_public_keys         = local.resolved_key_pair_public_keys
#   key_pair_create_private_keys = local.resolved_key_pair_create_private_keys
#   key_pair_rsa_bits            = local.resolved_key_pair_rsa_bits
#   key_pair_tags                = local.resolved_key_pair_tags

#   tags = local.default_tags
# }