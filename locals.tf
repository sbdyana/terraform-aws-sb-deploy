################################################################################
# Policy Module
################################################################################

locals {
  policy       = module.policy.policy
  base_name    = module.policy.base_name
  default_tags = module.policy.default_tags
  iam_path     = module.policy.iam_path
}

################################################################################
# VPC Configuration
################################################################################

locals {
  vpc_policy = try(local.policy.infra.vpc, {})
  vpc_name   = "vpc-${local.base_name}"
  vpc_cidr   = try(local.vpc_policy.cidr, "10.0.0.0/16")

  # 타입별 CIDR 맵 (cidrsubnet 자동 계산)
  subnet_cidr_map = {
    att   = [cidrsubnet(local.vpc_cidr, 9, 64), cidrsubnet(local.vpc_cidr, 9, 65)]
    lb    = [cidrsubnet(local.vpc_cidr, 7, 0), cidrsubnet(local.vpc_cidr, 7, 1)]
    com   = [cidrsubnet(local.vpc_cidr, 7, 2), cidrsubnet(local.vpc_cidr, 7, 3)]
    eksng = [cidrsubnet(local.vpc_cidr, 2, 1), cidrsubnet(local.vpc_cidr, 2, 2)]
    db    = [cidrsubnet(local.vpc_cidr, 7, 4), cidrsubnet(local.vpc_cidr, 7, 5)]
    vpce  = [cidrsubnet(local.vpc_cidr, 7, 6), cidrsubnet(local.vpc_cidr, 7, 7)]
  }

  # YAML 파싱: subnets/route_tables가 이미 맵 형태
  subnet_map      = try(local.vpc_policy.subnets, {})
  route_table_map = try(local.vpc_policy.route_tables, {})
  type_keys       = sort(keys(local.subnet_map))

  # Subnet 설정 생성
  subnets = merge([
    for type, zones in local.subnet_map : {
      for idx, s in zones : "${type}-${s.zone}" => {
        name = "sbn-${local.base_name}-${type}-${s.zone}"
        cidr = local.subnet_cidr_map[type][idx]
        az   = "ap-northeast-2${s.zone}"
        type = type
      }
    }
  ]...)

  # Route Table 설정 생성
  route_tables = { for type in local.type_keys : type => "rtb-${local.base_name}-${type}" }

  # Route Table ↔ Subnet 연결
  route_table_associations = { for k, v in local.subnets : v.name => local.route_tables[v.type] }

  # Routes (local 제외, CIDR 타입만)
  routes = flatten([
    for type in local.type_keys : [
      for rt in local.route_table_map[type] : [
        for r in rt.routes : {
          route_table = local.route_tables[type]
          destination = r.route.destination
        } if r.route.target != "local" && r.route.type == "CIDR"
      ]
    ]
  ])
}

################################################################################
# Security Groups Configuration
################################################################################

locals {
  sg_map = try(local.vpc_policy.security_groups, {})

  # Security Group별 설정 생성
  # name_optional 값이 있으면 type 뒤에 추가 (null 또는 빈 문자열이면 무시)
  security_groups = {
    for sg_name, sg in local.sg_map : sg_name => {
      name = (
        try(sg.name_optional != null && sg.name_optional != "", false)
        ? "scg-${try(sg.type, sg_name)}-${local.base_name}-${sg.name_optional}"
        : "scg-${try(sg.type, sg_name)}-${local.base_name}"
      )
      description = try(sg.description, "Managed by Terraform")
      rules       = sg.rules
    }
  }

  # 각 Security Group의 rules를 flat list로 변환 (모듈 입력용)
  sg_rules = {
    for sg_name, sg in local.security_groups : sg_name => {
      names      = [for idx, r in sg.rules : "${sg_name}-${idx}"]
      types      = [for r in sg.rules : r.type == "inbound" ? "ingress" : "egress"]
      cidrs_ipv4 = [
        for r in sg.rules :
        (
          try(r.cidr, "") != "" && !can(regex(":", try(r.cidr, "")))
          ? try(r.cidr, "")
          : ""
        )
      ]
      cidrs_ipv6 = [
        for r in sg.rules :
        (
          try(r.cidr, "") != "" && can(regex(":", try(r.cidr, "")))
          ? try(r.cidr, "")
          : ""
        )
      ]
      protocols    = [for r in sg.rules : try(r.protocol, "-1")]
      from_ports   = [for r in sg.rules : try(r.from_port, -1)]
      to_ports     = [for r in sg.rules : try(r.to_port, -1)]
      descriptions = [for r in sg.rules : try(r.description, "")]
    }
  }
}

################################################################################
# VPC Endpoints Configuration
################################################################################

locals {
  vpce_map = try(local.vpc_policy.vpc_endpoints, {})

  # Endpoint 타입 결정 (route_tables만 있으면 Gateway, subnets 있으면 Interface)
  # coalesce: YAML에서 키만 있고 값이 없으면 null이 되므로 빈 배열로 변환
  vpc_endpoints = {
    for name, config in local.vpce_map : name => {
      name                = name
      service_name        = "com.amazonaws.ap-northeast-2.${name}"
      route_tables        = coalesce(config.route_tables, [])
      subnets             = coalesce(config.subnets, [])
      security_groups     = coalesce(config.security_groups, [])
      type                = contains(["s3", "dynamodb"], name) ? "Gateway" : "Interface"
      private_dns_enabled = try(config.private_dns_enabled, true) # Interface 타입 기본값 true
    }
  }

  vpce_names               = keys(local.vpc_endpoints)
  vpce_service_names       = [for name in local.vpce_names : local.vpc_endpoints[name].service_name]
  vpce_types               = [for name in local.vpce_names : local.vpc_endpoints[name].type]
  vpce_private_dns_enabled = [for name in local.vpce_names : local.vpc_endpoints[name].private_dns_enabled]

  # Route Table IDs 맵 (Gateway 타입용) - 타입 이름 → 실제 route table 이름
  vpce_route_table_ids = {
    for name, vpce in local.vpc_endpoints : name => [
      for rt_type in vpce.route_tables : local.route_tables[rt_type]
    ] if length(vpce.route_tables) > 0
  }

  # Subnet IDs 맵 (Interface 타입용) - 타입 이름 → 실제 subnet 이름
  vpce_subnet_ids = {
    for name, vpce in local.vpc_endpoints : name => flatten([
      for sbn_type in vpce.subnets : [
        for k, v in local.subnets : v.name if v.type == sbn_type
      ]
    ]) if length(vpce.subnets) > 0
  }

  # Security Group IDs 맵 (Interface 타입용)
  vpce_security_group_ids = {
    for name, vpce in local.vpc_endpoints : name => [
      for sg_name in vpce.security_groups : local.security_groups[sg_name].name
    ] if length(vpce.security_groups) > 0
  }
}

################################################################################
# ElastiCache Configuration (Simplified - Object Map)
################################################################################

locals {
  elasticache_map = try(local.vpc_policy.elasticaches, {})
  ec_keys         = keys(local.elasticache_map)

  # Subnet Groups (객체 맵)
  elasticache_subnet_groups = {
    for name, config in local.elasticache_map : (
      try(config.name_optional != null && config.name_optional != "", false)
      ? "ec-sng-${local.base_name}-${config.name_optional}"
      : "ec-sng-${local.base_name}"
      ) => {
      description = try(config.subnet_group.description, "Managed by Terraform")
      # subnet_ids는 main.tf에서 module.vpc.subnet_ids 참조로 변환
      _subnet_types = try(config.subnet_group.subnets, [])
    } if try(config.subnet_group, null) != null
  }

  # Parameter Groups (객체 맵)
  elasticache_parameter_groups = {
    for name, config in local.elasticache_map : (
      try(config.name_optional != null && config.name_optional != "", false)
      ? "ec-pg-${local.base_name}-${config.name_optional}"
      : "ec-pg-${local.base_name}"
      ) => {
      family      = try(config.parameter_group.family, "redis7")
      description = try(config.parameter_group.description, "Managed by Terraform")
      parameters  = coalesce(try(config.parameter_group.parameters, null), [])
    } if try(config.parameter_group, null) != null
  }

  # Replication Groups (객체 맵) - 모듈에 직접 전달할 형태
  # security_group_ids와 subnet_ids는 main.tf에서 처리
  elasticache_replication_groups_base = {
    for idx, name in local.ec_keys : (
      try(local.elasticache_map[name].name_optional != null && local.elasticache_map[name].name_optional != "", false)
      ? "ec-${local.base_name}-${local.elasticache_map[name].name_optional}"
      : "ec-${local.base_name}"
      ) => {
      engine                     = try(local.elasticache_map[name].engine, "redis")
      engine_version             = try(local.elasticache_map[name].engine_version, null)
      description                = try(local.elasticache_map[name].description, "Managed by Terraform")
      node_type                  = try(local.elasticache_map[name].node_type, "cache.t3.micro")
      port                       = try(local.elasticache_map[name].port, 6379)
      num_cache_clusters         = try(local.elasticache_map[name].num_cache_clusters, null)
      num_node_groups            = try(local.elasticache_map[name].num_node_groups, null)
      replicas_per_node_group    = try(local.elasticache_map[name].replicas_per_node_group, null)
      automatic_failover_enabled = try(local.elasticache_map[name].automatic_failover_enabled, true)
      multi_az_enabled           = try(local.elasticache_map[name].multi_az_enabled, true)
      at_rest_encryption_enabled = try(local.elasticache_map[name].at_rest_encryption_enabled, true)
      transit_encryption_enabled = try(local.elasticache_map[name].transit_encryption_enabled, true)
      transit_encryption_mode    = try(local.elasticache_map[name].transit_encryption_mode, null)
      auth_token                 = try(local.elasticache_map[name].auth_token, null)
      kms_key_id                 = try(local.elasticache_map[name].kms_key_id, null)
      snapshot_retention_limit   = try(local.elasticache_map[name].snapshot_retention_limit, 0)
      snapshot_window            = try(local.elasticache_map[name].snapshot_window, null)
      maintenance_window         = try(local.elasticache_map[name].maintenance_window, null)
      auto_minor_version_upgrade = try(local.elasticache_map[name].auto_minor_version_upgrade, true)
      apply_immediately          = try(local.elasticache_map[name].apply_immediately, false)
      # 참조용 필드 (main.tf에서 실제 값으로 변환)
      _yaml_key            = name
      _security_group_keys = try(local.elasticache_map[name].security_groups, [])
      _preferred_azs       = [for az in try(local.elasticache_map[name].preferred_azs, []) : "ap-northeast-2${az}"]
    }
  }

  # Subnet Group 이름 매핑 (yaml key → subnet group name)
  ec_subnet_group_name_map = {
    for name, config in local.elasticache_map : name => (
      try(config.name_optional != null && config.name_optional != "", false)
      ? "ec-sng-${local.base_name}-${config.name_optional}"
      : "ec-sng-${local.base_name}"
    ) if try(config.subnet_group, null) != null
  }

  # Parameter Group 이름 매핑 (yaml key → parameter group name)
  ec_parameter_group_name_map = {
    for name, config in local.elasticache_map : name => (
      try(config.name_optional != null && config.name_optional != "", false)
      ? "ec-pg-${local.base_name}-${config.name_optional}"
      : "ec-pg-${local.base_name}"
    ) if try(config.parameter_group, null) != null
  }

  # Subnet Group의 subnet 타입 → 실제 subnet 이름 매핑 (main.tf에서 ID 변환용)
  elasticache_subnet_group_subnet_names = {
    for sg_name, sg in local.elasticache_subnet_groups : sg_name => flatten([
      for sbn_type in sg._subnet_types : [
        for k, v in local.subnets : v.name if v.type == sbn_type
      ]
    ])
  }
}

################################################################################
# EC2 Instances Configuration (Object Map Pattern - Simplified)
################################################################################

locals {
  ec2_instance_map = try(local.vpc_policy.ec2_instances, {})

  # 중복 판단용: ec2-{base_name}-{name_optional} 기준 그룹핑
  _ec2_base_keys = {
    for key, cfg in local.ec2_instance_map : key => format("ec2-%s-%s",
      local.base_name,
      try(cfg.name_optional, key)
    )
  }

  # 같은 base_key를 가진 인스턴스 개수 카운트
  _ec2_base_key_counts = {
    for base_key in distinct(values(local._ec2_base_keys)) :
    base_key => length([for k, v in local._ec2_base_keys : k if v == base_key])
  }

  # 같은 base_key 내에서 순번 계산
  _ec2_sorted_keys = sort(keys(local.ec2_instance_map))
  _ec2_key_indices = {
    for key in local._ec2_sorted_keys : key => index([
      for k in local._ec2_sorted_keys : k
      if local._ec2_base_keys[k] == local._ec2_base_keys[key]
    ], key) + 1
  }

  # EC2 Instances - 객체 맵으로 직접 전달
  # 키 생성: name 있으면 name 사용
  # 중복 있으면: ec2-{base_name}-{name_optional}-{az}-01, 02, ...
  # 중복 없으면: ec2-{base_name}-{name_optional}-{az}
  ec2_instances = {
    for key, cfg in local.ec2_instance_map : (
      try(cfg.name, "") != "" ? cfg.name :
      (local._ec2_base_key_counts[local._ec2_base_keys[key]] > 1
        ? format("%s-%s-%02d", local._ec2_base_keys[key], try(cfg.availability_zone, ""), local._ec2_key_indices[key])
        : format("%s-%s", local._ec2_base_keys[key], try(cfg.availability_zone, "")))
    ) => {
      ami           = try(cfg.ami, "")
      instance_type = try(cfg.instance_type, "")
      subnet_id = (
        try(cfg.subnet, "") != "" && try(cfg.availability_zone, "") != ""
        ? module.vpc.subnet_ids[local.subnets["${cfg.subnet}-${cfg.availability_zone}"].name]
        : null
      )
      vpc_security_group_ids = [
        for sg_name in try(cfg.security_groups, []) : module.security_group[sg_name].security_group_id
      ]
      key_name                    = try(cfg.key_name, null)
      iam_instance_profile        = try(cfg.iam_instance_profile, null)
      availability_zone           = try(cfg.availability_zone, "") != "" ? "${var.region}${cfg.availability_zone}" : null
      private_ip                  = try(cfg.private_ip, null)
      associate_public_ip_address = try(cfg.associate_public_ip_address, null)
      source_dest_check           = try(cfg.source_dest_check, true)
      disable_api_termination     = try(cfg.disable_api_termination, false)
      disable_api_stop            = try(cfg.disable_api_stop, false)
      ebs_optimized               = try(cfg.ebs_optimized, null)
      monitoring                  = try(cfg.monitoring, false)
      user_data                   = try(cfg.user_data, null)
      user_data_base64            = try(cfg.user_data_base64, null)
      user_data_replace_on_change = try(cfg.user_data_replace_on_change, false)
      tenancy                     = try(cfg.tenancy, null)
      host_id                     = try(cfg.host_id, null)
      placement_group             = try(cfg.placement_group, null)
      placement_partition_number  = try(cfg.placement_partition_number, null)
      hibernation                 = try(cfg.hibernation, null)

      root_block_device = try(cfg.root_block_device, null) != null ? {
        volume_type           = try(cfg.root_block_device.volume_type, null)
        volume_size           = try(cfg.root_block_device.volume_size, null)
        iops                  = try(cfg.root_block_device.iops, null)
        throughput            = try(cfg.root_block_device.throughput, null)
        encrypted             = try(cfg.root_block_device.encrypted, null)
        kms_key_id            = try(cfg.root_block_device.kms_key_id, null)
        delete_on_termination = try(cfg.root_block_device.delete_on_termination, true)
      } : null

      metadata_options = try(cfg.metadata_options, null) != null ? {
        http_endpoint               = try(cfg.metadata_options.http_endpoint, null)
        http_tokens                 = try(cfg.metadata_options.http_tokens, null)
        http_put_response_hop_limit = try(cfg.metadata_options.http_put_response_hop_limit, null)
        instance_metadata_tags      = try(cfg.metadata_options.instance_tags, null)
      } : null

      cpu_credits = try(cfg.credit_specification.cpu_credits, null)

      capacity_reservation = try(cfg.capacity_reservation, null) != null ? {
        preference = try(cfg.capacity_reservation.preference, null)
        target     = try(cfg.capacity_reservation.target, null)
      } : null

      tags = try(cfg.tags, {})
    }
  }

  # EBS Volumes - 객체 맵으로 직접 전달
  ec2_ebs_volumes = {
    for name, cfg in try(local.vpc_policy.ec2_ebs_volumes, {}) : name => {
      availability_zone = (
        try(cfg.availability_zone, "") != ""
        ? (length(cfg.availability_zone) == 1 ? "${var.region}${cfg.availability_zone}" : cfg.availability_zone)
        : ""
      )
      size                 = try(cfg.size, null)
      type                 = try(cfg.type, null)
      iops                 = try(cfg.iops, null)
      throughput           = try(cfg.throughput, null)
      encrypted            = try(cfg.encrypted, null)
      kms_key_id           = try(cfg.kms_key_id, null)
      snapshot_id          = try(cfg.snapshot_id, null)
      multi_attach_enabled = try(cfg.multi_attach_enabled, null)
      final_snapshot       = try(cfg.final_snapshot, false)
      tags                 = try(cfg.tags, {})
    }
  }

  # EBS Attachments - 객체 맵으로 직접 전달
  ec2_ebs_attachments = {
    for idx, a in try(local.vpc_policy.ec2_ebs_attachments, []) : "${a.volume_name}:${a.instance_name}" => {
      volume_name                    = try(a.volume_name, "")
      instance_name                  = try(a.instance_name, "")
      device_name                    = try(a.device_name, "")
      force_detach                   = try(a.force_detach, false)
      stop_instance_before_detaching = try(a.stop_instance_before_detaching, false)
    }
  }

  # Elastic IPs - 객체 맵으로 직접 전달
  ec2_eips = {
    for name, cfg in try(local.vpc_policy.ec2_eips, {}) : name => {
      instance_name        = try(cfg.instance_name, null)
      domain               = try(cfg.domain, "vpc")
      network_border_group = try(cfg.network_border_group, null)
      public_ipv4_pool     = try(cfg.public_ipv4_pool, null)
      tags                 = try(cfg.tags, {})
    }
  }
}

################################################################################
# OpenSearch Configuration (Object Map Pattern - Simplified)
################################################################################

locals {
  opensearch_policy       = try(local.vpc_policy.opensearch, {})
  opensearch_domain_name  = "oss-cls-${local.base_name}"
  opensearch_policy_dir   = "${path.module}/../terraform-mirae-policy/${var.project}/${var.environment}"

  # Access policy resolution (JSON file or inline)
  opensearch_access_policy_value = try(local.opensearch_policy.access_policies, "")
  opensearch_access_policy_path  = "${local.opensearch_policy_dir}/iam/${local.opensearch_access_policy_value}"
  opensearch_access_policy_resolved = (
    local.opensearch_policy_dir != ""
    && endswith(local.opensearch_access_policy_value, ".json")
    && fileexists(local.opensearch_access_policy_path)
    ? file(local.opensearch_access_policy_path)
    : local.opensearch_access_policy_value
  )

  # Subnet and Security Group resolution
  opensearch_subnet_types       = try(local.opensearch_policy.subnets, [])
  opensearch_availability_zones = try(local.opensearch_policy.availability_zones, [])
  opensearch_security_groups    = try(local.opensearch_policy.security_groups, [])

  # OpenSearch Domains - 객체 맵으로 직접 전달
  opensearch_domains = length(keys(local.opensearch_policy)) > 0 ? {
    (local.opensearch_domain_name) = {
      engine_version = try(local.opensearch_policy.engine_version, "OpenSearch_2.11")

      # Cluster configuration
      instance_type            = try(local.opensearch_policy.instance_type, "r6g.large.search")
      instance_count           = try(local.opensearch_policy.instance_count, 1)
      dedicated_master_enabled = try(local.opensearch_policy.dedicated_master_enabled, false)
      dedicated_master_type    = try(local.opensearch_policy.dedicated_master_type, null)
      dedicated_master_count   = try(local.opensearch_policy.dedicated_master_count, null)
      zone_awareness_enabled   = try(local.opensearch_policy.zone_awareness_enabled, false)
      availability_zone_count  = try(local.opensearch_policy.zone_awareness_enabled, false) ? max(2, try(local.opensearch_policy.availability_zone_count, 2)) : 1
      warm_enabled             = try(local.opensearch_policy.warm_enabled, false)
      warm_type                = try(local.opensearch_policy.warm_type, null)
      warm_count               = try(local.opensearch_policy.warm_count, null)
      cold_storage_enabled     = try(local.opensearch_policy.cold_storage_enabled, false)

      # EBS options
      ebs_enabled     = try(local.opensearch_policy.ebs_enabled, true)
      ebs_volume_type = try(local.opensearch_policy.ebs_volume_type, "gp3")
      ebs_volume_size = try(local.opensearch_policy.ebs_volume_size, 100)
      ebs_iops        = try(local.opensearch_policy.ebs_iops, 0) > 0 ? local.opensearch_policy.ebs_iops : null
      ebs_throughput  = try(local.opensearch_policy.ebs_throughput, 0) > 0 ? local.opensearch_policy.ebs_throughput : null

      # VPC options (resolved)
      subnet_ids = flatten([
        for sbn_type in local.opensearch_subnet_types : [
          for k, v in local.subnets : module.vpc.subnet_ids[v.name]
          if v.type == sbn_type && (
            try(local.opensearch_policy.zone_awareness_enabled, false)
            ? (length(local.opensearch_availability_zones) >= 2
              ? contains([for z in local.opensearch_availability_zones : "${var.region}${z}"], v.az)
              : true)
            : (length(local.opensearch_availability_zones) >= 1
              ? v.az == "${var.region}${local.opensearch_availability_zones[0]}"
              : true)
          )
        ]
      ])
      security_group_ids = [
        for sg_name in local.opensearch_security_groups : module.security_group[sg_name].security_group_id
      ]

      # Encryption
      encrypt_at_rest_enabled         = try(local.opensearch_policy.encrypt_at_rest_enabled, true)
      encrypt_at_rest_kms_key_id      = try(local.opensearch_policy.encrypt_at_rest_kms_key_id, null)
      node_to_node_encryption_enabled = try(local.opensearch_policy.node_to_node_encryption_enabled, true)

      # Domain endpoint options
      enforce_https                   = try(local.opensearch_policy.enforce_https, true)
      tls_security_policy             = try(local.opensearch_policy.tls_security_policy, "Policy-Min-TLS-1-2-2019-07")
      custom_endpoint_enabled         = try(local.opensearch_policy.custom_endpoint_enabled, false)
      custom_endpoint                 = try(local.opensearch_policy.custom_endpoint, null)
      custom_endpoint_certificate_arn = try(local.opensearch_policy.custom_endpoint_certificate_arn, null)

      # Advanced security options
      advanced_security_options_enabled = try(local.opensearch_policy.advanced_security_options_enabled, false)
      anonymous_auth_enabled            = try(local.opensearch_policy.anonymous_auth_enabled, false)
      internal_user_database_enabled    = try(local.opensearch_policy.internal_user_database_enabled, false)
      master_user_arn                   = try(local.opensearch_policy.master_user_arn, null)
      master_user_name                  = try(local.opensearch_policy.master_user_name, null)
      master_user_password              = try(local.opensearch_policy.master_user_password, null)

      # Cognito options (embedded)
      cognito_options = try(local.opensearch_policy.cognito.enabled, false) ? {
        enabled          = true
        user_pool_id     = try(local.opensearch_policy.cognito.user_pool_id, null)
        identity_pool_id = try(local.opensearch_policy.cognito.identity_pool_id, null)
        role_arn         = try(local.opensearch_policy.cognito.role_arn, null)
      } : null

      log_publishing_options = try(local.opensearch_policy.log_publishing_options, [])

      # AI/ML options (embedded)
      aiml_options = {
        natural_language_query_generation_enabled = try(local.opensearch_policy.aiml_options.natural_language_query_generation_enabled, false)
        s3_vectors_engine_enabled                 = try(local.opensearch_policy.aiml_options.s3_vectors_engine_enabled, false)
        serverless_vector_acceleration_enabled    = try(local.opensearch_policy.aiml_options.serverless_vector_acceleration_enabled, false)
      }

      auto_tune_enabled               = try(local.opensearch_policy.auto_tune_enabled, null)
      auto_tune_rollback_on_disable   = try(local.opensearch_policy.auto_tune_rollback_on_disable, "NO_ROLLBACK")
      auto_tune_maintenance_schedules = try(local.opensearch_policy.auto_tune_maintenance_schedules, [])

      automated_snapshot_start_hour = try(local.opensearch_policy.automated_snapshot_start_hour, null)

      # Off-peak window (embedded)
      off_peak_window = {
        enabled       = try(local.opensearch_policy.off_peak_window_enabled, false)
        start_hours   = try(local.opensearch_policy.off_peak_window_start_hours, 0)
        start_minutes = try(local.opensearch_policy.off_peak_window_start_minutes, 0)
      }

      auto_software_update_enabled = try(local.opensearch_policy.auto_software_update_enabled, null)
      advanced_options             = try(local.opensearch_policy.advanced_options, null)
      access_policies              = local.opensearch_access_policy_resolved != "" ? local.opensearch_access_policy_resolved : null

      tags = try(local.opensearch_policy.tags, {})
    }
  } : {}

  # SAML Options - 객체 맵으로 직접 전달
  opensearch_saml_options = try(local.opensearch_policy.saml.enabled, false) ? {
    (local.opensearch_domain_name) = {
      idp_entity_id           = try(local.opensearch_policy.saml.idp_entity_id, "")
      idp_metadata_content    = try(local.opensearch_policy.saml.idp_metadata_content, "")
      subject_key             = try(local.opensearch_policy.saml.subject_key, null)
      roles_key               = try(local.opensearch_policy.saml.roles_key, null)
      session_timeout_minutes = try(local.opensearch_policy.saml.session_timeout_minutes, 60)
      master_user_name        = try(local.opensearch_policy.saml.master_user_name, null)
      master_backend_role     = try(local.opensearch_policy.saml.master_backend_role, null)
    }
  } : {}

  # VPC Endpoints - 객체 맵으로 직접 전달
  opensearch_vpc_endpoints = {
    for name, cfg in try(local.opensearch_policy.vpc_endpoints, {}) : name => {
      domain_name = local.opensearch_domain_name
      subnet_ids = flatten([
        for sbn_type in try(cfg.subnets, []) : [
          for k, v in local.subnets : module.vpc.subnet_ids[v.name] if v.type == sbn_type
        ]
      ])
      security_group_ids = [
        for sg_name in try(cfg.security_groups, []) : module.security_group[sg_name].security_group_id
      ]
    }
  }
}

################################################################################
# VPC Module Outputs
################################################################################

locals {
  resolved_vpc_name = local.vpc_name
  resolved_vpc_cidr = local.vpc_cidr

  resolved_subnet_names = [for k, v in local.subnets : v.name]
  resolved_subnet_cidrs = [for k, v in local.subnets : v.cidr]
  resolved_subnet_zones = [for k, v in local.subnets : v.az]

  resolved_route_table_names        = values(local.route_tables)
  resolved_route_table_associations = local.route_table_associations

  resolved_route_names             = [for idx, r in local.routes : "${r.route_table}-${idx}"]
  resolved_route_route_table_names = [for r in local.routes : r.route_table]
  resolved_route_destination_cidrs = [for r in local.routes : r.destination]
}


################################################################################
# EKS Configuration
################################################################################

locals {
  eks_map    = try(local.vpc_policy.eks, {})
  eks_keys   = keys(local.eks_map)
  eks_config = length(local.eks_keys) > 0 ? local.eks_map[local.eks_keys[0]] : null

  # 클러스터 이름 생성 (name_optional 적용)
  # name_optional 있으면: eks-${base_name}-${name_optional}, 없으면: eks-${base_name}
  resolved_eks_name = length(local.eks_keys) > 0 ? (
    try(local.eks_config.name_optional != null && local.eks_config.name_optional != "", false)
    ? "eks-cls-${local.base_name}-${local.eks_config.name_optional}"
    : "eks-cls-${local.base_name}"
  ) : null

  # 클러스터 기본 설정
  resolved_eks_cluster_version = try(local.eks_config.cluster_version, null)

  # cluster_role.ref (IAM role key 참조) 또는 cluster_role.arn (직접 ARN) 지원
  resolved_eks_cluster_role_arn = (
    try(local.eks_config.cluster_role.ref, null) != null && local.eks_config.cluster_role.ref != ""
    ? "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.iam_role_key_to_name[local.eks_config.cluster_role.ref]}"
    : try(local.eks_config.cluster_role.arn, null)
  )

  # Subnet 이름 목록 (타입 -> 실제 이름)
  eks_cluster_subnet_names = length(local.eks_keys) > 0 ? flatten([
    for sbn_type in try(local.eks_config.subnets, []) : [
      for k, v in local.subnets : v.name if v.type == sbn_type
    ]
  ]) : []

  # Security Group 이름 목록
  eks_cluster_security_group_names = length(local.eks_keys) > 0 ? [
    for sg_name in try(local.eks_config.security_groups, []) : local.security_groups[sg_name].name
  ] : []

  # 엔드포인트 설정
  resolved_eks_endpoint_private_access = try(local.eks_config.endpoint_private_access, true)
  resolved_eks_endpoint_public_access  = try(local.eks_config.endpoint_public_access, false)
  resolved_eks_public_access_cidrs     = try(local.eks_config.public_access_cidrs, ["0.0.0.0/0"])

  # 네트워크 설정
  resolved_eks_service_ipv4_cidr = try(local.eks_config.service_ipv4_cidr, null)
  resolved_eks_ip_family         = try(local.eks_config.ip_family, "ipv4")

  # 로깅
  resolved_eks_enabled_cluster_log_types = try(local.eks_config.enabled_cluster_log_types, [])

  # 인증
  resolved_eks_authentication_mode                         = try(local.eks_config.authentication_mode, "API_AND_CONFIG_MAP")
  resolved_eks_bootstrap_cluster_creator_admin_permissions = try(local.eks_config.bootstrap_cluster_creator_admin_permissions, true)

  # 암호화
  resolved_eks_encryption_config_key_arn = try(local.eks_config.encryption_config_key_arn, null)

  # 업그레이드 정책
  resolved_eks_upgrade_policy_support_type = try(local.eks_config.upgrade_policy.support_type, null)
}

################################################################################
# EKS Launch Templates Configuration
################################################################################

locals {
  # Launch Templates 맵 (eks.launch_templates에서 정의)
  eks_launch_template_map = try(local.eks_config.launch_templates, {})
  eks_lt_keys             = keys(local.eks_launch_template_map)

  # Node Group 이름 먼저 계산 (Launch Template 이름 생성에 필요)
  _eks_node_group_names_map = {
    for name, config in try(local.eks_config.node_groups, {}) :
    name => (
      try(config.name_optional != null && config.name_optional != "", false)
      ? "eks-ng-${local.base_name}-${config.name_optional}"
      : "eks-ng-${local.base_name}"
    )
  }

  # Launch Template Key → Node Group Name 매핑
  # (node_groups에서 launch_template 필드로 참조하는 관계를 역으로 매핑)
  _lt_key_to_ng_name = {
    for ng_key, config in try(local.eks_config.node_groups, {}) :
    config.launch_template => local._eks_node_group_names_map[ng_key]
    if try(config.launch_template, null) != null
  }

  # Launch Template 이름 생성 (lt-{node group 이름})
  eks_launch_template_names = {
    for lt_key in local.eks_lt_keys :
    lt_key => "lt-${lookup(local._lt_key_to_ng_name, lt_key, "${local.base_name}-${lt_key}")}"
  }

  # Launch Template AMI IDs
  eks_launch_template_ami_ids = {
    for lt_key in local.eks_lt_keys :
    local.eks_launch_template_names[lt_key] => local.eks_launch_template_map[lt_key].ami_id
    if try(local.eks_launch_template_map[lt_key].ami_id, null) != null
  }

  # Launch Template Instance Types
  eks_launch_template_instance_types = {
    for lt_key in local.eks_lt_keys :
    local.eks_launch_template_names[lt_key] => local.eks_launch_template_map[lt_key].instance_type
    if try(local.eks_launch_template_map[lt_key].instance_type, null) != null
  }

  # Launch Template Security Group Names (vpc.security_groups key 참조)
  eks_launch_template_security_group_names = {
    for lt_key in local.eks_lt_keys :
    local.eks_launch_template_names[lt_key] => [
      for sg_key in coalesce(try(local.eks_launch_template_map[lt_key].security_groups, null), []) :
      local.security_groups[sg_key].name
    ]
    if try(local.eks_launch_template_map[lt_key].security_groups, null) != null
  }

  # Launch Template Block Device Mappings
  eks_launch_template_block_device_mappings = {
    for lt_key in local.eks_lt_keys :
    local.eks_launch_template_names[lt_key] => {
      device_name           = try(local.eks_launch_template_map[lt_key].block_device.device_name, "/dev/xvda")
      volume_size           = try(local.eks_launch_template_map[lt_key].block_device.volume_size, 50)
      volume_type           = try(local.eks_launch_template_map[lt_key].block_device.volume_type, "gp3")
      iops                  = try(local.eks_launch_template_map[lt_key].block_device.iops, null)
      throughput            = try(local.eks_launch_template_map[lt_key].block_device.throughput, null)
      encrypted             = try(local.eks_launch_template_map[lt_key].block_device.encrypted, true)
      kms_key_id            = try(local.eks_launch_template_map[lt_key].block_device.kms_key_id, null)
      delete_on_termination = try(local.eks_launch_template_map[lt_key].block_device.delete_on_termination, true)
    }
    if try(local.eks_launch_template_map[lt_key].block_device, null) != null
  }

  # Launch Template Metadata Options
  eks_launch_template_metadata_options = {
    for lt_key in local.eks_lt_keys :
    local.eks_launch_template_names[lt_key] => {
      http_endpoint               = try(local.eks_launch_template_map[lt_key].metadata_options.http_endpoint, "enabled")
      http_tokens                 = try(local.eks_launch_template_map[lt_key].metadata_options.http_tokens, "required")
      http_put_response_hop_limit = try(local.eks_launch_template_map[lt_key].metadata_options.http_put_response_hop_limit, 2)
      instance_metadata_tags      = try(local.eks_launch_template_map[lt_key].metadata_options.instance_metadata_tags, "disabled")
    }
    if try(local.eks_launch_template_map[lt_key].metadata_options, null) != null
  }

  # Launch Template EBS Optimized
  eks_launch_template_ebs_optimized = {
    for lt_key in local.eks_lt_keys :
    local.eks_launch_template_names[lt_key] => local.eks_launch_template_map[lt_key].ebs_optimized
    if try(local.eks_launch_template_map[lt_key].ebs_optimized, null) != null
  }

  # Launch Template Monitoring Enabled
  eks_launch_template_monitoring_enabled = {
    for lt_key in local.eks_lt_keys :
    local.eks_launch_template_names[lt_key] => local.eks_launch_template_map[lt_key].monitoring_enabled
    if try(local.eks_launch_template_map[lt_key].monitoring_enabled, null) != null
  }

  # Launch Template Node Config (userdata 자동 생성 여부)
  eks_launch_template_node_config = {
    for lt_key in local.eks_lt_keys :
    local.eks_launch_template_names[lt_key] => try(local.eks_launch_template_map[lt_key].node_config, false)
  }

  # Launch Template Tag Specifications (instance, volume에 적용될 태그)
  # Name 태그는 ${base_name}-eks-ng 형식으로 설정
  eks_launch_template_tag_specifications = {
    for lt_key in local.eks_lt_keys :
    local.eks_launch_template_names[lt_key] => {
      Name = "ec2-${local.base_name}-eks-ng"
    }
  }
}

################################################################################
# EKS Node Groups Configuration
################################################################################

locals {
  eks_node_group_map = try(local.eks_config.node_groups, {})
  eks_ng_keys        = keys(local.eks_node_group_map)

  # Node Group 이름 생성 (이미 계산된 _eks_node_group_names_map 활용)
  eks_node_group_names = [
    for name in local.eks_ng_keys : local._eks_node_group_names_map[name]
  ]

  # Node Group Role ARNs
  # node_role.ref (IAM role key 참조) 또는 node_role.arn (직접 ARN) 지원
  resolved_eks_node_group_role_arns = [
    for name in local.eks_ng_keys : (
      try(local.eks_node_group_map[name].node_role.ref, null) != null && local.eks_node_group_map[name].node_role.ref != ""
      ? "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.iam_role_key_to_name[local.eks_node_group_map[name].node_role.ref]}"
      : local.eks_node_group_map[name].node_role.arn
    )
  ]

  # Node Group Subnet 이름 (노드 그룹별)
  eks_node_group_subnet_names = {
    for name, config in local.eks_node_group_map : name => flatten([
      for sbn_type in try(config.subnets, []) : [
        for k, v in local.subnets : v.name if v.type == sbn_type
      ]
    ])
  }

  # Node Group Instance Types
  resolved_eks_node_group_instance_types = [
    for name in local.eks_ng_keys : try(local.eks_node_group_map[name].instance_types, ["t3.medium"])
  ]

  # Node Group AMI Types
  # launch_template이 지정되어 있으면 null, 아니면 Node Group 설정값 사용
  resolved_eks_node_group_ami_types = [
    for name in local.eks_ng_keys : (
      # launch_template이 있으면 null
      try(local.eks_node_group_map[name].launch_template, null) != null
      ? null
      : try(local.eks_node_group_map[name].ami_type, null)
    )
  ]

  # Node Group Node Repair Enabled (노드 자동 복구, null이면 기본값 true)
  resolved_eks_node_group_node_repair_enabled = [
    for name in local.eks_ng_keys : try(local.eks_node_group_map[name].node_repair_enabled, null)
  ]

  # Node Group Capacity Types
  resolved_eks_node_group_capacity_types = [
    for name in local.eks_ng_keys : try(local.eks_node_group_map[name].capacity_type, "ON_DEMAND")
  ]

  # Node Group Disk Sizes
  # launch_template이 지정되어 있으면 null (block_device로 설정), 아니면 Node Group 설정값 사용
  resolved_eks_node_group_disk_sizes = [
    for name in local.eks_ng_keys : (
      # launch_template이 있으면 null (block_device로 설정)
      try(local.eks_node_group_map[name].launch_template, null) != null
      ? null
      : try(local.eks_node_group_map[name].disk_size, null)
    )
  ]

  # Node Group에서 Launch Template 참조 (node_groups.<key>.launch_template)
  # launch_template 필드가 있는 노드 그룹만 처리
  eks_node_group_launch_template_refs = {
    for idx, name in local.eks_ng_keys :
    local.eks_node_group_names[idx] => local.eks_launch_template_names[local.eks_node_group_map[name].launch_template]
    if try(local.eks_node_group_map[name].launch_template, null) != null
  }

  # Node Group Scaling Config
  resolved_eks_node_group_desired_sizes = [
    for name in local.eks_ng_keys : try(local.eks_node_group_map[name].scaling.desired_size, 1)
  ]
  resolved_eks_node_group_min_sizes = [
    for name in local.eks_ng_keys : try(local.eks_node_group_map[name].scaling.min_size, 1)
  ]
  resolved_eks_node_group_max_sizes = [
    for name in local.eks_ng_keys : try(local.eks_node_group_map[name].scaling.max_size, 1)
  ]

  # Node Group Update Config
  resolved_eks_node_group_max_unavailable = [
    for name in local.eks_ng_keys : try(local.eks_node_group_map[name].update_config.max_unavailable, null)
  ]
  resolved_eks_node_group_max_unavailable_percentage = [
    for name in local.eks_ng_keys : try(local.eks_node_group_map[name].update_config.max_unavailable_percentage, null)
  ]

  # Node Group Labels (map of ng_name -> labels)
  resolved_eks_node_group_labels = {
    for idx, name in local.eks_ng_keys : local.eks_node_group_names[idx] =>
    try(local.eks_node_group_map[name].labels, {})
  }

  # Node Group Taints (map of ng_name -> list of taints)
  resolved_eks_node_group_taints = {
    for idx, name in local.eks_ng_keys : local.eks_node_group_names[idx] =>
    try(local.eks_node_group_map[name].taints, [])
  }
}

################################################################################
# EKS Addons Configuration
################################################################################

locals {
  eks_addon_map  = try(local.eks_config.addons, {})
  eks_addon_keys = keys(local.eks_addon_map)

  # Addon Names
  resolved_eks_addon_names = local.eks_addon_keys

  # Addon Versions (빈 문자열 = 기본 버전)
  resolved_eks_addon_versions = [
    for name in local.eks_addon_keys : try(local.eks_addon_map[name].version, "")
  ]

  # Addon Resolve Conflicts
  resolved_eks_addon_resolve_conflicts_on_create = [
    for name in local.eks_addon_keys : try(local.eks_addon_map[name].resolve_conflicts_on_create, "OVERWRITE")
  ]
  resolved_eks_addon_resolve_conflicts_on_update = [
    for name in local.eks_addon_keys : try(local.eks_addon_map[name].resolve_conflicts_on_update, "OVERWRITE")
  ]

  # Addon Service Account Role ARNs
  # service_account_role.ref (IAM role key 참조) 또는 service_account_role.arn (직접 ARN) 지원
  # ref가 있으면 IAM role name을 참조해서 ARN 생성, arn이 있으면 직접 사용
  resolved_eks_addon_service_account_role_arns = [
    for name in local.eks_addon_keys : (
      # ref가 있으면 IAM role ARN 생성
      try(local.eks_addon_map[name].service_account_role.ref, null) != null && local.eks_addon_map[name].service_account_role.ref != ""
      ? "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.iam_role_key_to_name[local.eks_addon_map[name].service_account_role.ref]}"
      # arn이 있으면 직접 사용
      : try(local.eks_addon_map[name].service_account_role.arn, null) != null && local.eks_addon_map[name].service_account_role.arn != ""
      ? local.eks_addon_map[name].service_account_role.arn
      # 둘 다 없으면 빈 문자열
      : ""
    )
  ]

  # Addon Configuration Values (map of addon_name -> json string)
  resolved_eks_addon_configuration_values = {
    for name in local.eks_addon_keys : name =>
    try(local.eks_addon_map[name].configuration_values, null)
    if try(local.eks_addon_map[name].configuration_values, null) != null
  }

  # Addon Preserve on Delete
  resolved_eks_addon_preserve_on_delete = [
    for name in local.eks_addon_keys : try(local.eks_addon_map[name].preserve_on_delete, false)
  ]
}

################################################################################
# EKS Access Entries Configuration
################################################################################

locals {
  eks_access_entry_map  = try(local.eks_config.access_entries, {})
  eks_access_entry_keys = keys(local.eks_access_entry_map)

  # Access Entry Principal ARNs
  # principal_arn.ref (IAM role key 참조) 또는 principal_arn.arn (직접 ARN) 지원
  resolved_eks_access_entry_principal_arns = [
    for key in local.eks_access_entry_keys : (
      try(local.eks_access_entry_map[key].principal_arn.ref, null) != null && local.eks_access_entry_map[key].principal_arn.ref != ""
      ? "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.iam_role_key_to_name[local.eks_access_entry_map[key].principal_arn.ref]}"
      : try(local.eks_access_entry_map[key].principal_arn.arn, "")
    )
  ]

  # Access Entry Types
  resolved_eks_access_entry_types = [
    for key in local.eks_access_entry_keys : try(local.eks_access_entry_map[key].type, "STANDARD")
  ]

  # Access Entry Kubernetes Groups (map of principal_arn -> groups)
  resolved_eks_access_entry_kubernetes_groups = {
    for idx, key in local.eks_access_entry_keys : local.resolved_eks_access_entry_principal_arns[idx] =>
    try(local.eks_access_entry_map[key].kubernetes_groups, [])
  }

  # Access Policy Associations
  # flatten하여 각 access_policy 항목을 개별 association으로 변환
  resolved_eks_access_policy_associations = flatten([
    for key in local.eks_access_entry_keys : [
      for policy in try(local.eks_access_entry_map[key].access_policies, []) : {
        principal_arn = (
          try(local.eks_access_entry_map[key].principal_arn.ref, null) != null && local.eks_access_entry_map[key].principal_arn.ref != ""
          ? "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.iam_role_key_to_name[local.eks_access_entry_map[key].principal_arn.ref]}"
          : try(local.eks_access_entry_map[key].principal_arn.arn, "")
        )
        policy_arn = "arn:aws:eks::aws:cluster-access-policy/${policy.policy}"
        access_scope = {
          type       = try(policy.access_scope.type, "cluster")
          namespaces = try(policy.access_scope.namespaces, null)
        }
      }
    ]
  ])
}

################################################################################
# IAM Configuration (Object Map - Simplified)
# Pre-EKS: is_oidc_template: false인 역할들 (EKS 생성 전에 필요)
# Post-EKS: is_oidc_template: true인 역할들 (EKS OIDC 필요)
################################################################################

locals {
  iam_config = try(local.policy.infra.iam, {})

  # IAM Role 이름 생성 함수 (name 또는 name_optional 기반)
  _iam_role_name = {
    for key, cfg in try(local.iam_config.roles, {}) : key => (
      try(cfg.name, null) != null && try(cfg.name, "") != ""
      ? cfg.name
      : (try(cfg.name_optional, "") != "" ? "iam-rol-${local.base_name}-${cfg.name_optional}" : "iam-rol-${local.base_name}")
    )
  }

  # IAM Role key → name 역매핑 (EKS에서 role key로 참조할 때 사용)
  iam_role_key_to_name = local._iam_role_name

  # EKS OIDC provider 정보 (Post-EKS에서 사용)
  eks_oidc_provider_host = length(module.eks_cluster) > 0 ? replace(module.eks_cluster[0].cluster_oidc_issuer_url, "https://", "") : ""
  eks_oidc_provider_arn  = length(module.eks_cluster) > 0 ? "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.eks_oidc_provider_host}" : ""

  #=============================================================================
  # Pre-EKS IAM Roles (is_oidc_template: false) - 객체 맵 형태
  #=============================================================================
  iam_roles_pre_eks = {
    for key, cfg in try(local.iam_config.roles, {}) : local._iam_role_name[key] => {
      assume_role_policy    = file("${local.iam_path}/${cfg.trust_policy.file}")
      description           = try(cfg.description, "Managed by Terraform")
      max_session_duration  = try(cfg.max_session_duration, 3600)
      path                  = try(cfg.path, "/")
      permissions_boundary  = try(cfg.permissions_boundary, null)
      force_detach_policies = try(cfg.force_detach_policies, false)
      managed_policy_arns   = try(cfg.managed_policy_arns, [])
      inline_policies = {
        for p in coalesce(try(cfg.inline_policies, null), []) :
        "iam-pol-${local.base_name}-${p.name_optional}" => file("${local.iam_path}/${p.file}")
      }
      create_instance_profile = try(cfg.create_instance_profile, false)
    } if try(cfg.trust_policy.is_oidc_template, false) == false
  }

  #=============================================================================
  # Post-EKS IAM Roles (is_oidc_template: true) - 객체 맵 형태
  #=============================================================================
  iam_roles_post_eks = {
    for key, cfg in try(local.iam_config.roles, {}) : local._iam_role_name[key] => {
      assume_role_policy = templatefile("${local.iam_path}/${cfg.trust_policy.file}", {
        oidc_provider_arn         = local.eks_oidc_provider_arn
        oidc_provider_host        = local.eks_oidc_provider_host
        service_account_namespace = cfg.trust_policy.service_account_namespace
        service_account_name      = cfg.trust_policy.service_account_name
      })
      description           = try(cfg.description, "Managed by Terraform")
      max_session_duration  = try(cfg.max_session_duration, 3600)
      path                  = try(cfg.path, "/")
      permissions_boundary  = try(cfg.permissions_boundary, null)
      force_detach_policies = try(cfg.force_detach_policies, false)
      managed_policy_arns   = try(cfg.managed_policy_arns, [])
      inline_policies = {
        for p in coalesce(try(cfg.inline_policies, null), []) :
        "iam-pol-${local.base_name}-${p.name_optional}" => file("${local.iam_path}/${p.file}")
      }
      create_instance_profile = try(cfg.create_instance_profile, false)
    } if try(cfg.trust_policy.is_oidc_template, false) == true
  }

  #=============================================================================
  # OIDC Providers - 객체 맵 형태
  #=============================================================================

  # 일반 OIDC Providers (eks_cluster: false)
  iam_oidc_providers = {
    for key, cfg in try(local.iam_config.oidc_providers, {}) : key => {
      url             = cfg.url
      client_id_list  = cfg.client_id_list
      thumbprint_list = try(cfg.thumbprint_list, [])
    } if try(cfg.eks_cluster, false) != true && try(cfg.url, null) != null && try(cfg.url, "") != ""
  }

  # EKS OIDC Providers (eks_cluster: true) - Post-EKS에서 처리
  iam_eks_oidc_providers = {
    for key, cfg in try(local.iam_config.oidc_providers, {}) : key => {
      eks_cluster_key = cfg.url
      client_id_list  = try(cfg.client_id_list, ["sts.amazonaws.com"])
    } if try(cfg.eks_cluster, false) == true && try(cfg.url, null) != null && try(cfg.url, "") != ""
  }
}

################################################################################
# RDS Aurora Configuration (Object Map Pattern - Simplified)
################################################################################

locals {
  rds_auroras  = try(local.policy.infra.vpc.rds_auroras, [])
  rds_has_list = length(local.rds_auroras) > 0

  # YAML에서 설정 로드
  rds_policy_raw = local.rds_has_list ? {
    subnet_groups = flatten([
      for r in local.rds_auroras : try(r.subnet_groups, [])
    ])
    parameter_groups = merge([
      for r in local.rds_auroras : try(r.parameter_groups, {})
    ]...)
    clusters          = merge([for r in local.rds_auroras : try(r.clusters, {})]...)
    cluster_instances = merge([for r in local.rds_auroras : try(r.cluster_instances, {})]...)
    name_optional     = try(local.rds_auroras[0].name_optional, null)
  } : {
    subnet_groups     = try(local.vpc_policy.rds_aurora.subnet_groups, [])
    parameter_groups  = try(local.vpc_policy.rds_aurora.parameter_groups, {})
    clusters          = try(local.vpc_policy.rds_aurora.clusters, {})
    cluster_instances = try(local.vpc_policy.rds_aurora.cluster_instances, {})
    name_optional     = try(local.vpc_policy.rds_aurora.name_optional, null)
  }

  rds_name_base         = "rds-${local.base_name}"
  rds_name_optional_def = try(local.rds_policy_raw.name_optional, null)

  #=============================================================================
  # Subnet Groups - 객체 맵
  #=============================================================================
  rds_subnet_groups = {
    for idx, sg in local.rds_policy_raw.subnet_groups : (
      try(sg.name, "") != "" ? sg.name :
      (try(sg.name_optional, null) != null
        ? "rds-sng-${local.base_name}-${sg.name_optional}"
        : "rds-sng-${local.base_name}")
    ) => {
      description = try(sg.description, "Managed by Terraform")
      subnet_ids = [
        for sbn_name in(
          length(coalesce(try(sg.subnet_names, null), [])) > 0
          ? sg.subnet_names
          : flatten([for sbn_type in try(sg.rds_subnets, []) : [for _, sbn in local.subnets : sbn.name if sbn.type == sbn_type]])
        ) : module.vpc.subnet_ids[sbn_name]
      ]
      tags = try(sg.tags, {})
    }
  }

  rds_default_subnet_group_name = length(keys(local.rds_subnet_groups)) > 0 ? keys(local.rds_subnet_groups)[0] : null

  #=============================================================================
  # Parameter Groups - 인스턴스용 (type != "cluster")
  #=============================================================================
  rds_parameter_groups = {
    for k, v in local.rds_policy_raw.parameter_groups : (
      try(v.name, "") != "" ? v.name :
      (try(v.name_optional, null) != null
        ? "rds-pg-${local.base_name}-${v.name_optional}"
        : (local.rds_name_optional_def != null
          ? "rds-pg-${local.base_name}-${local.rds_name_optional_def}"
          : "rds-pg-${local.base_name}"))
    ) => {
      family      = v.family
      description = try(v.description, "Managed by Terraform")
      parameters  = try(v.parameters, [])
      tags        = try(v.tags, {})
    } if try(v.type, "instance") == "instance"
  }

  #=============================================================================
  # Cluster Parameter Groups - 클러스터용 (type == "cluster")
  #=============================================================================
  rds_cluster_parameter_groups = {
    for k, v in local.rds_policy_raw.parameter_groups : (
      try(v.name, "") != "" ? v.name :
      (try(v.name_optional, null) != null
        ? "rds-cpg-${local.base_name}-${v.name_optional}"
        : (local.rds_name_optional_def != null
          ? "rds-cpg-${local.base_name}-${local.rds_name_optional_def}"
          : "rds-cpg-${local.base_name}"))
    ) => {
      family      = v.family
      description = try(v.description, "Managed by Terraform")
      parameters  = try(v.parameters, [])
      tags        = try(v.tags, {})
    } if try(v.type, "instance") == "cluster"
  }

  rds_default_cpg_name = length(keys(local.rds_cluster_parameter_groups)) > 0 ? keys(local.rds_cluster_parameter_groups)[0] : null
  rds_default_pg_name  = length(keys(local.rds_parameter_groups)) > 0 ? keys(local.rds_parameter_groups)[0] : null

  #=============================================================================
  # Clusters - 인스턴스 내장 객체 맵
  #=============================================================================
  rds_clusters = {
    for k, v in local.rds_policy_raw.clusters : (
      try(v.name, "") != "" ? v.name :
      (try(v.name_optional, null) != null
        ? "${local.rds_name_base}-${v.name_optional}"
        : (local.rds_name_optional_def != null
          ? "${local.rds_name_base}-${local.rds_name_optional_def}"
          : local.rds_name_base))
    ) => {
      engine         = try(v.engine, null)
      engine_mode    = try(v.engine_mode, "provisioned")
      engine_version = try(v.engine_version, null)

      database_name   = try(v.database_name, null)
      master_username = try(v.master_username, null)
      master_password = try(v.master_password, null)
      port            = try(v.port, null)

      manage_master_user_password   = try(v.manage_master_user_password, null)
      master_user_secret_kms_key_id = try(v.master_user_secret_kms_key_id, null)

      db_cluster_parameter_group_name  = try(v.cluster_parameter_group_name, null) != null ? v.cluster_parameter_group_name : local.rds_default_cpg_name
      db_instance_parameter_group_name = try(v.instance_parameter_group_name, null) != null ? v.instance_parameter_group_name : local.rds_default_pg_name

      db_subnet_group_name = try(v.subnet_group_name, null) != null ? v.subnet_group_name : local.rds_default_subnet_group_name
      vpc_security_group_ids = [
        for sg_name in coalesce(try(v.security_groups, null), []) : module.security_group[sg_name].security_group_id
      ]
      availability_zones = try(v.availability_zones, null) != null ? [
        for az in v.availability_zones : length(az) == 1 ? "${var.region}${az}" : az
      ] : null

      storage_encrypted = try(v.storage_encrypted, true)
      kms_key_id        = try(v.kms_key_id, null)

      backup_retention_period      = try(v.backup_retention_period, 7)
      preferred_backup_window      = try(v.preferred_backup_window, null)
      preferred_maintenance_window = try(v.preferred_maintenance_window, null)
      copy_tags_to_snapshot        = try(v.copy_tags_to_snapshot, true)

      deletion_protection       = try(v.deletion_protection, true)
      skip_final_snapshot       = try(v.skip_final_snapshot, false)
      final_snapshot_identifier = try(v.final_snapshot_identifier, null)

      enabled_cloudwatch_logs_exports = try(v.enabled_cloudwatch_logs_exports, null)

      iam_database_authentication_enabled = try(v.iam_database_authentication_enabled, false)

      apply_immediately           = try(v.apply_immediately, false)
      allow_major_version_upgrade = try(v.allow_major_version_upgrade, false)

      serverlessv2_scaling = try(v.serverlessv2_scaling, null)

      # 인스턴스 내장 (cluster_instances에서 매핑)
      instances = {
        for ci_key, ci in local.rds_policy_raw.cluster_instances : (
          try(ci.name_optional, null) != null
          ? "${ci.name_optional}-${format("%02d", try(tonumber(regexall("[0-9]+$", ci_key)[0]), index(keys(local.rds_policy_raw.cluster_instances), ci_key) + 1))}"
          : format("%02d", try(tonumber(regexall("[0-9]+$", ci_key)[0]), index(keys(local.rds_policy_raw.cluster_instances), ci_key) + 1))
        ) => {
          instance_class = ci.instance_class
          availability_zone = try(ci.availability_zone, null) != null ? (
            length(ci.availability_zone) == 1 ? "${var.region}${ci.availability_zone}" : ci.availability_zone
          ) : null
          publicly_accessible                   = try(ci.publicly_accessible, false)
          promotion_tier                        = try(ci.promotion_tier, null)
          auto_minor_version_upgrade            = try(ci.auto_minor_version_upgrade, false)
          apply_immediately                     = try(ci.apply_immediately, false)
          performance_insights_enabled          = try(ci.performance_insights_enabled, false)
          performance_insights_retention_period = try(ci.performance_insights_retention_period, null)
          performance_insights_kms_key_id       = try(ci.performance_insights_kms_key_id, null)
          monitoring_interval                   = try(ci.monitoring_interval, 0)
          monitoring_role_arn                   = try(ci.monitoring_role_arn, null)
          ca_cert_identifier                    = try(ci.ca_cert_identifier, null)
          copy_tags_to_snapshot                 = try(ci.copy_tags_to_snapshot, true)
          tags                                  = try(ci.tags, {})
        } if try(ci.cluster_name, k) == k || (try(ci.cluster_name, null) == null && k == keys(local.rds_policy_raw.clusters)[0])
      }

      tags = try(v.tags, {})
    }
  }
}

################################################################################
# EFS Configuration (Object Map Pattern - Simplified)
################################################################################

locals {
  efs_policy          = try(local.policy.infra.vpc.efs, {})
  efs_file_system_raw = try(local.efs_policy.file_systems, {})

  # EFS File Systems - 객체 맵으로 직접 전달
  efs_file_systems = {
    for k, v in local.efs_file_system_raw : (
      try(v.name, "") != "" ? v.name :
      (try(v.name_optional != null && v.name_optional != "", false)
        ? "efs-${local.base_name}-${v.name_optional}"
        : "efs-${local.base_name}")
    ) => {
      encrypted                       = try(v.encrypted, true)
      kms_key_id                      = try(v.kms_key_id, null)
      performance_mode                = try(v.performance_mode, "generalPurpose")
      throughput_mode                 = try(v.throughput_mode, "bursting")
      provisioned_throughput_in_mibps = try(v.provisioned_throughput_in_mibps, null)
      availability_zone_name          = try(v.availability_zone_name, null)
      lifecycle_policy                = try(v.lifecycle_policy, null)

      # Mount Targets (embedded)
      mount_targets = length(try(v.subnet_types, [])) > 0 || length(try(v.subnet_names, [])) > 0 ? {
        subnet_ids = [
          for sbn_name in(
            length(coalesce(try(v.subnet_names, null), [])) > 0
            ? v.subnet_names
            : flatten([for sbn_type in try(v.subnet_types, []) : [for _, sbn in local.subnets : sbn.name if sbn.type == sbn_type]])
          ) : module.vpc.subnet_ids[sbn_name]
        ]
        security_groups = [
          for sg_name in try(v.security_groups, []) : module.security_group[sg_name].security_group_id
          if contains(keys(module.security_group), sg_name)
        ]
        ip_addresses = try(v.mount_target_ip_addresses, {})
      } : null

      # Access Points (embedded list)
      access_points = [
        for ap in try(v.access_points, []) : {
          name = (
            try(ap.name, "") != "" ? ap.name :
            (try(ap.name_optional != null && ap.name_optional != "", false)
              ? "efs-ap-${local.base_name}-${ap.name_optional}"
              : "efs-ap-${local.base_name}")
          )
          root_directory = try(ap.root_directory, null)
          posix_user     = try(ap.posix_user, null)
          tags           = try(ap.tags, {})
        }
      ]

      backup_policy_status = try(v.backup_policy_status, null)
      tags                 = try(v.tags, {})
    }
  }
}


################################################################################
# Launch Template Configuration
################################################################################

locals {
  launch_template_config = try(
    local.vpc_policy.launch_templates,
    try(local.vpc_policy.autoscaling.launch_templates, try(local.vpc_policy.autoscalings.launch_templates, {}))
  )

  # Launch Templates
  autoscaling_launch_template_map  = local.launch_template_config
  autoscaling_launch_template_keys = sort(keys(local.autoscaling_launch_template_map))

  autoscaling_launch_template_names = [
    for k in local.autoscaling_launch_template_keys :
    (
      try(local.autoscaling_launch_template_map[k].name_optional, "") != ""
      ? "lt-${try(local.autoscaling_launch_template_map[k].type, k)}-${local.base_name}-${local.autoscaling_launch_template_map[k].name_optional}"
      : "lt-${try(local.autoscaling_launch_template_map[k].type, k)}-${local.base_name}"
    )
  ]

  autoscaling_launch_template_descriptions = [
    for k in local.autoscaling_launch_template_keys :
    try(local.autoscaling_launch_template_map[k].description, "")
  ]

  autoscaling_launch_template_amis = [
    for k in local.autoscaling_launch_template_keys :
    try(local.autoscaling_launch_template_map[k].ami, "")
  ]

  autoscaling_launch_template_instance_types = [
    for k in local.autoscaling_launch_template_keys :
    try(local.autoscaling_launch_template_map[k].instance_type, "")
  ]

  autoscaling_launch_template_key_names = [
    for k in local.autoscaling_launch_template_keys :
    try(local.autoscaling_launch_template_map[k].key_name, "")
  ]

  autoscaling_launch_template_iam_instance_profiles = [
    for k in local.autoscaling_launch_template_keys :
    try(local.autoscaling_launch_template_map[k].iam_instance_profile, "")
  ]

  autoscaling_launch_template_security_group_ids = {
    for idx, k in local.autoscaling_launch_template_keys :
    local.autoscaling_launch_template_names[idx] => [
      for sg_key in coalesce(try(local.autoscaling_launch_template_map[k].security_groups, null), []) :
      module.security_group[sg_key].security_group_id
    ]
  }

  autoscaling_launch_template_user_data = {
    for idx, k in local.autoscaling_launch_template_keys :
    local.autoscaling_launch_template_names[idx] => try(local.autoscaling_launch_template_map[k].user_data, null)
    if try(local.autoscaling_launch_template_map[k].user_data, null) != null
  }

  autoscaling_launch_template_block_device_mappings = {
    for idx, k in local.autoscaling_launch_template_keys :
    local.autoscaling_launch_template_names[idx] => coalesce(try(local.autoscaling_launch_template_map[k].block_device_mappings, null), [])
  }

  autoscaling_launch_template_tags = {
    for idx, k in local.autoscaling_launch_template_keys :
    local.autoscaling_launch_template_names[idx] => coalesce(try(local.autoscaling_launch_template_map[k].tags, null), {})
  }

  autoscaling_launch_template_name_map = {
    for idx, k in local.autoscaling_launch_template_keys :
    k => local.autoscaling_launch_template_names[idx]
  }
}

################################################################################
# ALB Configuration
################################################################################

locals {
  albs_input  = try(local.vpc_policy.albs, {})
  alb_enabled = length(keys(local.albs_input)) > 0

  albs = {
    for alb_key, alb_cfg in local.albs_input : alb_key => {
      load_balancer_type = lookup(alb_cfg, "load_balancer_type", null)
      name = (
        try(alb_cfg.name_optional, "") != ""
        ? "alb-${local.base_name}-${alb_cfg.name_optional}"
        : "alb-${local.base_name}-${alb_key}"
      )
      internal                 = try(alb_cfg.internal, false)
      target_group_name_prefix = "alb-tg-${local.base_name}-${alb_key}"

      subnet_ids = [
        for az in coalesce(try(alb_cfg.availability_zones, null), []) :
        module.vpc.subnet_ids[local.subnets["${try(alb_cfg.subnet_type, "web")}-${az}"].name]
      ]

      security_group_ids = [
        for sg_key in coalesce(try(alb_cfg.security_groups, null), []) :
        module.security_group[sg_key].security_group_id
      ]

      target_group_map  = try(alb_cfg.target_groups, {})
      target_group_keys = sort(keys(try(alb_cfg.target_groups, {})))
      target_groups = {
        for tg_key in sort(keys(try(alb_cfg.target_groups, {}))) : tg_key => {
          type         = try(alb_cfg.target_groups[tg_key].type, tg_key)
          port         = try(alb_cfg.target_groups[tg_key].port, 443)
          protocol     = try(alb_cfg.target_groups[tg_key].protocol, "HTTPS")
          target_type  = try(alb_cfg.target_groups[tg_key].target_type, "instance")
          health_check = try(alb_cfg.target_groups[tg_key].health_check, {})
        }
      }

      listener_map  = try(alb_cfg.listeners, {})
      listener_keys = sort(keys(try(alb_cfg.listeners, {})))
      listeners = {
        for listener_key in sort(keys(try(alb_cfg.listeners, {}))) : listener_key => {
          port            = try(alb_cfg.listeners[listener_key].port, 443)
          protocol        = try(alb_cfg.listeners[listener_key].protocol, lookup(alb_cfg, "load_balancer_type", null) == "application" ? "HTTPS" : "TCP")
          ssl_policy      = try(alb_cfg.listeners[listener_key].ssl_policy, "")
          certificate_arn = try(alb_cfg.listeners[listener_key].certificate_arn, "")
          default_action = {
            type           = try(alb_cfg.listeners[listener_key].default_action.type, "forward")
            target_group   = try(alb_cfg.listeners[listener_key].default_action.target_group, null)
            order          = try(alb_cfg.listeners[listener_key].default_action.order, null)
            redirect       = try(alb_cfg.listeners[listener_key].default_action.redirect, null)
            fixed_response = try(alb_cfg.listeners[listener_key].default_action.fixed_response, null)
            forward = try(alb_cfg.listeners[listener_key].default_action.forward, null) != null ? {
              target_groups = [
                for tg in alb_cfg.listeners[listener_key].default_action.forward.target_groups : {
                  target_group_name = tg.target_group
                  weight            = try(tg.weight, null)
                }
              ]
              stickiness = try(alb_cfg.listeners[listener_key].default_action.forward.stickiness, null)
            } : null
          }
        }
      }

      asg_target_groups = try(alb_cfg.asg_target_groups, {})
    }
  }

  # autoscaling 연결용: 각 ALB의 asg_target_groups를 flatten
  alb_asg_target_group_bindings = flatten([
    for alb_key, alb in local.albs : [
      for asg_key, tg_keys in alb.asg_target_groups : [
        for tg_key in tg_keys : {
          asg_name = local.autoscaling_asg_name_map[asg_key]
          tg_arn   = module.alb[alb_key].target_group_arns[tg_key]
        }
      ]
    ]
  ])
}

################################################################################
# Auto Scaling Configuration
################################################################################

locals {
  autoscaling_config = try(local.vpc_policy.autoscaling, try(local.vpc_policy.autoscalings, {}))

  # ASGs
  autoscaling_asg_map = try(local.autoscaling_config.asgs, {})
  autoscaling_asgs = {
    for k, cfg in local.autoscaling_asg_map : k => {
      name = (
        try(cfg.name_optional, "") != ""
        ? "asg-${local.base_name}-${cfg.name_optional}"
        : "asg-${local.base_name}"
      )
      launch_template_ref       = try(cfg.launch_template, "")
      min_size                  = try(cfg.min_size, 1)
      max_size                  = try(cfg.max_size, 2)
      desired_capacity          = try(cfg.desired_capacity, 1)
      health_check_type         = try(cfg.health_check_type, "")
      health_check_grace_period = try(cfg.health_check_grace_period, 0)
      subnet_type               = try(cfg.subnet_type, "")
      availability_zones        = coalesce(try(cfg.availability_zones, null), [])
    }
  }
  autoscaling_asg_keys = sort(keys(local.autoscaling_asgs))

  autoscaling_asg_names = [
    for k in local.autoscaling_asg_keys :
    local.autoscaling_asgs[k].name
  ]

  autoscaling_asg_name_map = {
    for idx, k in local.autoscaling_asg_keys :
    k => local.autoscaling_asg_names[idx]
  }

  autoscaling_asg_launch_template_refs = [
    for k in local.autoscaling_asg_keys :
    local.autoscaling_asgs[k].launch_template_ref
  ]

  autoscaling_asg_min_sizes = [
    for k in local.autoscaling_asg_keys :
    local.autoscaling_asgs[k].min_size
  ]

  autoscaling_asg_max_sizes = [
    for k in local.autoscaling_asg_keys :
    local.autoscaling_asgs[k].max_size
  ]

  autoscaling_asg_desired_capacities = [
    for k in local.autoscaling_asg_keys :
    local.autoscaling_asgs[k].desired_capacity
  ]

  autoscaling_asg_health_check_types = [
    for k in local.autoscaling_asg_keys :
    local.autoscaling_asgs[k].health_check_type
  ]

  autoscaling_asg_health_check_grace_periods = [
    for k in local.autoscaling_asg_keys :
    local.autoscaling_asgs[k].health_check_grace_period
  ]

  autoscaling_asg_vpc_zone_identifiers = {
    for idx, k in local.autoscaling_asg_keys :
    local.autoscaling_asg_names[idx] => [
      for az in local.autoscaling_asgs[k].availability_zones :
      module.vpc.subnet_ids[local.subnets["${local.autoscaling_asgs[k].subnet_type}-${az}"].name]
    ]
  }

  autoscaling_asg_target_group_arns = local.alb_enabled ? {
    for asg_name in distinct([for b in local.alb_asg_target_group_bindings : b.asg_name]) :
    asg_name => [for b in local.alb_asg_target_group_bindings : b.tg_arn if b.asg_name == asg_name]
  } : {}
}


################################################################################
# Key Pair Configuration
################################################################################

locals {
  key_pair_map  = try(local.vpc_policy.key_pairs, {})
  key_pair_keys = sort(keys(local.key_pair_map))

  resolved_key_pair_names = [
    for k in local.key_pair_keys :
    (
      try(local.key_pair_map[k].name_optional, "") != ""
      ? "kp-${try(local.key_pair_map[k].type, k)}-${local.base_name}-${local.key_pair_map[k].name_optional}"
      : "kp-${try(local.key_pair_map[k].type, k)}-${local.base_name}"
    )
  ]

  resolved_key_pair_public_keys = [
    for k in local.key_pair_keys :
    try(local.key_pair_map[k].public_key, "")
  ]

  resolved_key_pair_create_private_keys = [
    for k in local.key_pair_keys :
    try(local.key_pair_map[k].create_private_key, false)
  ]

  resolved_key_pair_rsa_bits = [
    for k in local.key_pair_keys :
    try(local.key_pair_map[k].rsa_bits, 4096)
  ]

  resolved_key_pair_tags = {
    for idx, k in local.key_pair_keys :
    local.resolved_key_pair_names[idx] => coalesce(try(local.key_pair_map[k].tags, null), {})
  }

  resolved_key_pair_name_map = {
    for idx, k in local.key_pair_keys :
    k => local.resolved_key_pair_names[idx]
  }
}
